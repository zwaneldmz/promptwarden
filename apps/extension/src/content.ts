/**
 * PromptWarden content script.
 *
 * Selector-less by design: AI sites change their DOM weekly, so nothing here
 * depends on site-specific CSS selectors. Instead it intercepts the generic
 * mechanics every chat UI shares, in the capture phase so it runs before the
 * page's own handlers:
 *   1. Enter keydown inside an editable element
 *   2. click on a button that submits an adjacent editable element
 *   3. paste of text into an editable element
 *   4. change on <input type="file"> and drop of files
 *
 * Intercepted text is evaluated against the policy and allowed, warned,
 * redacted, or blocked. Everything runs locally: no network call, no LLM.
 * The only thing that leaves this script is the output of `toLogRecord`,
 * the single privacy gate for all logging.
 */
import { evaluate, parsePolicy, hostMatches, Policy, EvaluationResult, toLogRecord } from "@promptwarden/policy-engine";
import { FALLBACK_POLICY } from "./default-policy.js";
import { FileScan, isScannableFile, scanFiles } from "./file-scan.js";
import {
  SavedSelection,
  activeEditable,
  insertText,
  isEditable,
  readText,
  saveSelection,
  writeText,
} from "./text-io.js";

let policy: Policy = FALLBACK_POLICY;
/**
 * The one resubmission "Send anyway" approved: which editable, and the
 * exact text it was approved with. A bare timer (the previous design) arms
 * a 2s window during which ANY submission passes unscanned — different
 * text, a different editable entirely, the site's own queued-draft resend,
 * a network retry, or page script rewriting the textarea and dispatching an
 * untrusted `input` — because a boolean has no way to ask "is this the
 * literal thing that got approved?". Binding to element identity plus a
 * snapshot of the text closes that: `matchesApprovedBypass` below only
 * returns true for a submit attempt on this exact element still holding
 * this exact text, so a different prompt — even one typed a moment later
 * into the same box — is evaluated normally. Cleared to null by whichever
 * comes first: the timer, or the "any subsequent input" listener below.
 */
let approvedBypass: { editable: HTMLElement; text: string } | null = null;
/**
 * Auto-expires `approvedBypass` after 2s — an outer backstop, not the
 * primary mechanism: if the resumed submit never reaches a real submit
 * handler at all (click-only sites, a detached editable), the approval
 * still can't linger indefinitely.
 */
let bypassTimer: ReturnType<typeof setTimeout> | null = null;
/** True only while synthesizing an event to release a held upload. */
let replaying = false;
/**
 * The most recently focused editable, tracked via a capture-phase `focusin`
 * listener. Clicking a send button moves focus to the button before the
 * click listener runs, so `document.activeElement` is already the button —
 * this is the fallback of last resort for the click and submit paths.
 * Re-checked for `isConnected` since a framework re-render can detach it.
 */
let lastFocusedEditable: HTMLElement | null = null;

/**
 * (Re-)resolve the effective policy and parse it in place. Shared by the
 * initial document_start fetch below and the storage-change listener that
 * follows it, so a corrected or tightened push reaches already-open tabs
 * without a reload — and a rollback doesn't need a browser restart either.
 *
 * Goes through background's `resolvePolicy()` (managed > local > built-in,
 * including its handling of a managed policy that's present but broken)
 * rather than reading a storage change's `newValue` directly: that keeps
 * this one precedence-and-fail-safe implementation in one place instead of
 * a second copy here that could drift from it — in particular, a managed
 * policy failing to parse must fail to the built-in default, never fall
 * through to the user-writable local policy, and duplicating that rule
 * imperfectly here would reopen the exact privilege inversion it fixes.
 *
 * A parse failure (or a dead service worker) leaves `policy` exactly as it
 * was — the module-level variable is only ever reassigned on success — so
 * enforcement can fail to strengthen on a bad update, but never silently
 * weakens from whatever is already in force.
 */
function refreshPolicy(): void {
  send({ type: "get-policy" }, (resp) => {
    if (chrome.runtime.lastError) return;
    if (resp?.policy) {
      try {
        policy = parsePolicy(resp.policy);
      } catch {
        report("policy-parse-error");
      }
    }
  });
}

refreshPolicy();

/**
 * ROADMAP §1.5 item 19: content.ts used to fetch the policy once at
 * document_start and never again, so a corrected or rolled-back push needed
 * a full browser restart to reach tabs already open. Content scripts get
 * `storage.onChanged` for free under the existing `storage` permission — no
 * manifest change needed — so listen for the `policy` key changing in
 * either area an admin or the user can write it (`managed`, `local`) and
 * re-resolve on any hit.
 */
chrome.storage.onChanged.addListener((changes, areaName) => {
  if ((areaName === "managed" || areaName === "local") && "policy" in changes) {
    refreshPolicy();
  }
});

function enforcing(): boolean {
  return hostMatches(policy, location.hostname);
}

/**
 * Approve exactly one resubmission: `editable` holding exactly `text`,
 * auto-expiring after 2s. Called at the moment "Send anyway" is picked, so
 * `text` is a snapshot of what the user actually approved — not re-derived
 * later, when the box's contents could already have changed.
 */
function armBypass(editable: HTMLElement, text: string) {
  approvedBypass = { editable, text };
  if (bypassTimer !== null) clearTimeout(bypassTimer);
  bypassTimer = setTimeout(() => {
    approvedBypass = null;
    bypassTimer = null;
  }, 2000);
}

function disarmBypass() {
  approvedBypass = null;
  if (bypassTimer !== null) {
    clearTimeout(bypassTimer);
    bypassTimer = null;
  }
}

/** True only for a submit attempt on the exact element + text "Send anyway" approved. */
function matchesApprovedBypass(editable: HTMLElement): boolean {
  return (
    approvedBypass !== null &&
    approvedBypass.editable === editable &&
    readText(editable) === approvedBypass.text
  );
}

/** Fallback of last resort for the click and submit paths. */
function connectedLastFocused(): HTMLElement | null {
  return lastFocusedEditable && lastFocusedEditable.isConnected ? lastFocusedEditable : null;
}

/** The first genuinely editable descendant of a submitted form. */
function editableInForm(form: HTMLFormElement): HTMLElement | null {
  const candidates = form.querySelectorAll<HTMLElement>("textarea, input, [contenteditable]");
  for (const el of candidates) {
    if (isEditable(el)) return el;
  }
  return null;
}

/* ------------------------------ submit path ------------------------------ */

/**
 * How a submit attempt was triggered, so "Send anyway" can resume it the
 * same way instead of always faking an Enter keypress. A synthetic Enter
 * silently no-ops on sites where Enter doesn't send (click-only UIs, or
 * ChatGPT's "Enter = newline" setting); only the original click, swallowed
 * by `stopImmediatePropagation` below, would have sent it.
 */
type SubmitTrigger =
  | { kind: "keyboard" }
  | { kind: "click"; button: HTMLElement }
  | { kind: "submit"; form: HTMLFormElement };

/**
 * Resume the send exactly the way it was originally triggered. Falls back to
 * the Enter re-dispatch if the stored button/form was detached by a
 * framework re-render since interception.
 *
 * Called synchronously from the "Send anyway" `onPick`, so `readText`
 * captures precisely what the user approved at the moment they approved it
 * — the snapshot `matchesApprovedBypass` will compare every resumed submit
 * attempt against.
 */
function resumeSubmit(trigger: SubmitTrigger, editable: HTMLElement) {
  armBypass(editable, readText(editable));
  if (trigger.kind === "click" && trigger.button.isConnected) {
    // The click listener below no longer short-circuits on a bare bypass
    // flag — it re-enters onSubmitAttempt like any other click, which is
    // what lets matchesApprovedBypass() verify identity+text before
    // standing aside for this resumed click.
    trigger.button.click();
    return;
  }
  if (trigger.kind === "submit" && trigger.form.isConnected) {
    editable.focus();
    trigger.form.requestSubmit();
    return;
  }
  editable.focus();
  // Re-dispatch Enter so the page's own submit handler runs.
  editable.dispatchEvent(
    new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }),
  );
}

function onSubmitAttempt(e: Event, editable: HTMLElement, trigger: SubmitTrigger) {
  // Not cleared here: a "send anyway" resubmission can legitimately reach
  // this function twice (the synthetic Enter, then the resulting "submit"
  // event), and both must skip evaluation identically — matchesApprovedBypass
  // is a pure check, not a consume-once flag, so it says yes both times. Only
  // the timer and the "any subsequent input" listener clear it, so a later,
  // different prompt (or the same text retyped into a different editable) is
  // never waved through.
  if (matchesApprovedBypass(editable)) return;
  const text = readText(editable);
  if (!text.trim()) return;

  const result = evaluate(text, policy);
  if (result.findings.length === 0) return;

  // Observe-only result (silent baseline mode): the policy wants a record,
  // not an interruption — log and let the send proceed untouched.
  if (!result.blocked && !result.needsWarning && result.redactedText === text) {
    log(result);
    return;
  }

  e.preventDefault();
  e.stopImmediatePropagation();
  log(result);

  const actions: GuardrailAction[] = [];
  if (!result.blocked) {
    if (result.redactedText !== text) {
      actions.push({
        label: "Redact and continue",
        primary: true,
        onPick: () => {
          writeText(editable, result.redactedText);
          editable.focus();
        },
      });
    }
    if (result.needsWarning) {
      actions.push({
        label: "Send anyway",
        onPick: () => resumeSubmit(trigger, editable),
      });
    }
  }
  actions.push({ label: result.blocked ? "Close" : "Cancel", onPick: () => {} });

  showGuardrail({
    title: result.blocked ? "This message can't be sent" : "Sensitive data detected",
    detail: result.blocked
      ? `Your organization's policy blocks sending: ${categoriesOf(result)}.`
      : `Found: ${categoriesOf(result)}. Choose how to continue.`,
    actions,
  });
}

/**
 * Track the last-focused editable so the click and submit paths have a
 * fallback for when focus has already moved elsewhere by the time they run.
 */
document.addEventListener(
  "focusin",
  (e) => {
    const editable = activeEditable(e.target);
    if (editable) lastFocusedEditable = editable;
  },
  true,
);

/**
 * Real user input disarms a still-armed bypass immediately rather than
 * waiting out the timer, so a new prompt typed right after "send anyway" is
 * always scanned. Still useful even with identity+text binding: it's what
 * catches the edge case where the *same* editable is retyped back to the
 * *exact same* approved text before the resumed submit lands — text
 * equality alone can't tell that apart from the original approval, but an
 * intervening real keystroke can. Gated on isTrusted: synthetic input events
 * (file-release replay, redact/paste insertion) must not disarm a
 * legitimately armed bypass.
 */
document.addEventListener(
  "input",
  (e) => {
    if (e.isTrusted && approvedBypass !== null) disarmBypass();
  },
  true,
);

document.addEventListener(
  "keydown",
  (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
    if (!enforcing()) return;
    const editable = activeEditable(e.target);
    if (editable) onSubmitAttempt(e, editable, { kind: "keyboard" });
  },
  true, // capture phase: run before the page's own handlers
);

/**
 * Substring match, not word-boundary: German "Absenden"/"Abschicken" embed
 * "senden"/"schick" mid-word, so \b anchors would miss them. Known false
 * positive: labels containing "Sender".
 */
const SEND_WORD = /send|senden|schick|submit/i;

function isLikelySendButton(btn: Element): boolean {
  if (btn instanceof HTMLButtonElement && btn.type === "submit") return true;
  const ariaLabel = btn.getAttribute("aria-label") ?? "";
  const title = btn.getAttribute("title") ?? "";
  const dataTestId = btn.getAttribute("data-testid") ?? "";
  const text = btn.textContent?.trim() ?? "";
  return SEND_WORD.test(`${ariaLabel} ${title} ${dataTestId} ${text}`);
}

document.addEventListener(
  "click",
  (e) => {
    if (!enforcing()) return;
    const target = e.target as Element | null;
    // Exclude clicks inside the guardrail dialog itself: "Send anyway"
    // matches SEND_WORD, so without this the button would swallow its own
    // click and re-open the dialog instead of resuming the send. Identity
    // check, not an id/selector lookup — see clickIsFromGuardrail() below.
    if (clickIsFromGuardrail(e)) return;
    // No blanket "bypass armed, skip everything" check here on purpose: that
    // was the free-fire window (ROADMAP §1.2 item 6) — during it, ANY click
    // on ANY send-shaped button passed unexamined, not just the resumed one.
    // The resumed click from resumeSubmit() still reaches onSubmitAttempt
    // below like every other click; matchesApprovedBypass() there is what
    // recognizes it (same editable, same text) and stands aside for it
    // specifically, without ever preventDefault()-ing it.
    const btn = target?.closest?.("button, [role='button' i]");
    if (!btn || !isLikelySendButton(btn)) return;
    // Clicking the button usually moves focus to it first, so
    // activeEditable(null)'s document.activeElement fallback misses; fall
    // back further to the last focused editable.
    const editable = activeEditable(null) ?? connectedLastFocused();
    if (editable) onSubmitAttempt(e, editable, { kind: "click", button: btn as HTMLElement });
  },
  true,
);

/**
 * Catches a genuine <form> submit: Enter inside a plain form, a page
 * calling `requestSubmit()`, or any other path that bypasses the
 * click/keydown listeners above.
 */
document.addEventListener(
  "submit",
  (e) => {
    if (!enforcing()) return;
    const form = e.target instanceof HTMLFormElement ? e.target : null;
    const editable = (form && editableInForm(form)) ?? connectedLastFocused();
    if (editable) {
      onSubmitAttempt(e, editable, form ? { kind: "submit", form } : { kind: "keyboard" });
    }
  },
  true,
);

/* ------------------------------- paste path ------------------------------ */

document.addEventListener(
  "paste",
  (e) => {
    if (!enforcing()) return;
    const editable = activeEditable(e.target);
    if (!editable) return;
    const pasted = e.clipboardData?.getData("text/plain") ?? "";
    if (!pasted.trim()) return;

    const result = evaluate(pasted, policy);
    if (result.findings.length === 0) return;

    // Observe-only result: record it, let the paste land untouched.
    if (!result.blocked && !result.needsWarning && result.redactedText === pasted) {
      log(result);
      return;
    }

    // Take over the insertion so a redacted version can be substituted before
    // the text ever reaches the page's editor state.
    e.preventDefault();
    e.stopImmediatePropagation();
    // NOTE: paste + later submit can double-log one exposure. Add a
    // correlation id if event counts must be exact.
    log(result);

    const saved: SavedSelection = saveSelection(editable);
    const actions: GuardrailAction[] = [];
    if (!result.blocked) {
      if (result.redactedText !== pasted) {
        actions.push({
          label: "Paste redacted",
          primary: true,
          onPick: () => insertText(saved, result.redactedText),
        });
      }
      if (result.needsWarning) {
        actions.push({ label: "Paste anyway", onPick: () => insertText(saved, pasted) });
      }
    }
    actions.push({
      label: result.blocked ? "Close" : "Cancel",
      onPick: () => editable.focus(),
    });

    showGuardrail({
      title: result.blocked ? "This text can't be pasted" : "Sensitive data in pasted text",
      detail: result.blocked
        ? `Your organization's policy blocks pasting: ${categoriesOf(result)}.`
        : `Found in the pasted text: ${categoriesOf(result)}. Choose how to continue.`,
      actions,
    });
  },
  true,
);

/* ---------------------------- file upload path --------------------------- */

/**
 * Scannable attachments — text-like files and .xlsx/.docx (see
 * `isScannableFile`) — are held (propagation stopped) while read and
 * evaluated, then released or dropped. Anything else passes through
 * untouched: no filename or metadata is recorded.
 */
/**
 * Inputs whose files are currently held while a scan runs. Browsers fire
 * `input` before `change` for a file pick; the first of the pair starts the
 * hold, the sibling is swallowed here without a second scan.
 */
const heldInputs = new WeakSet<HTMLInputElement>();

function onFileInputEvent(e: Event) {
  if (replaying || !enforcing()) return;
  const input = e.target as HTMLInputElement | null;
  if (!input || input.tagName !== "INPUT" || input.type !== "file") return;

  if (heldInputs.has(input)) {
    e.stopImmediatePropagation();
    return;
  }

  const files = input.files ? Array.from(input.files) : [];
  const scannable = files.filter(isScannableFile);
  if (scannable.length === 0) return;

  e.stopImmediatePropagation();
  heldInputs.add(input);

  void scanFiles(scannable, policy)
      .then((scan) => {
        if (!scan) {
          releaseFileInput(input);
          return;
        }
        log(scan.result);
        // Observe-only scan, or nothing found: recorded above. Still has to
        // fork on `unreadable` — see handleUnscanned() — since an
        // all-unreadable scan reaches this branch too (zero findings, so
        // neither `blocked` nor `needsWarning` is ever true for it).
        if (!scan.blocked && !scan.needsWarning) {
          handleUnscanned(scan, () => releaseFileInput(input), () => clearFileInput(input));
          return;
        }
        if (scan.blocked) {
          clearFileInput(input);
          showGuardrail({
            title: "This file can't be uploaded",
            detail: `Your organization's policy blocks uploading files containing: ${scan.categories.join(", ")}.`,
            actions: [{ label: "Close", onPick: () => {} }],
          });
          return;
        }
        showGuardrail({
          title: "Sensitive data in attached file",
          detail:
            `Found in the file: ${scan.categories.join(", ")}. File contents can't be ` +
            "redacted automatically — remove it or upload it as it is." +
            unreadableNote(scan.unreadable),
          actions: [
            { label: "Upload anyway", primary: true, onPick: () => releaseFileInput(input) },
            { label: "Remove file", onPick: () => clearFileInput(input) },
          ],
          // A newer dialog displacing this one must not leak the held upload:
          // default to the safe branch.
          onDisplaced: () => clearFileInput(input),
        });
      })
      // policy.onError decides: "open" (default) releases the upload so a
      // guardrail bug can't block everything; "closed" blocks unscanned files.
      .catch(() => {
        report("file-scan-error");
        if (failClosed()) {
          clearFileInput(input);
          showScanErrorBlocked();
        } else {
          releaseFileInput(input);
        }
      });
}

document.addEventListener("input", onFileInputEvent, true);
document.addEventListener("change", onFileInputEvent, true);

document.addEventListener(
  "drop",
  (e) => {
    if (replaying || !enforcing()) return;
    // A drop onto a native file input populates input.files as the browser's
    // default action, which a synthetic replay can never reproduce — and it
    // fires input/change anyway, so the file-input path above scans it.
    if (e.target instanceof HTMLInputElement && e.target.type === "file") return;
    const files = e.dataTransfer?.files ? Array.from(e.dataTransfer.files) : [];
    if (files.length === 0) return; // text drops are handled by the paste path
    const scannable = files.filter(isScannableFile);
    if (scannable.length === 0) return;

    const target = e.target instanceof HTMLElement ? e.target : document.body;
    e.preventDefault();
    e.stopImmediatePropagation();

    void scanFiles(scannable, policy)
      .then((scan) => {
        if (!scan) {
          replayDrop(target, files);
          return;
        }
        log(scan.result);
        // Observe-only scan, or nothing found: recorded above. Still has to
        // fork on `unreadable` — see handleUnscanned() — since an
        // all-unreadable scan reaches this branch too (zero findings, so
        // neither `blocked` nor `needsWarning` is ever true for it).
        if (!scan.blocked && !scan.needsWarning) {
          handleUnscanned(scan, () => replayDrop(target, files));
          return;
        }
        if (scan.blocked) {
          showGuardrail({
            title: "This file can't be uploaded",
            detail: `Your organization's policy blocks uploading files containing: ${scan.categories.join(", ")}.`,
            actions: [{ label: "Close", onPick: () => {} }],
          });
          return;
        }
        showGuardrail({
          title: "Sensitive data in dropped file",
          detail:
            `Found in the file: ${scan.categories.join(", ")}. File contents can't be ` +
            "redacted automatically — discard it or upload it as it is." +
            unreadableNote(scan.unreadable),
          actions: [
            { label: "Upload anyway", primary: true, onPick: () => replayDrop(target, files) },
            { label: "Discard", onPick: () => {} },
          ],
        });
      })
      .catch(() => {
        report("file-scan-error");
        if (failClosed()) {
          showScanErrorBlocked();
        } else {
          replayDrop(target, files);
        }
      });
  },
  true,
);

/** Let the page see the input/change events that were held back. */
function releaseFileInput(input: HTMLInputElement) {
  replaying = true;
  try {
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  } catch {
    /* nothing to recover: the user can re-pick the file */
  } finally {
    replaying = false;
    heldInputs.delete(input);
  }
}

function clearFileInput(input: HTMLInputElement) {
  try {
    input.value = "";
  } catch {
    /* read-only in exotic cases */
  } finally {
    heldInputs.delete(input);
  }
}

function unreadableNote(count: number): string {
  return count > 0 ? ` ${count} file(s) could not be scanned.` : "";
}

function failClosed(): boolean {
  return policy.onError === "closed";
}

/**
 * Shared by the file-input and drop paths for a scan that came back neither
 * `blocked` nor `needsWarning`. That used to mean one thing — genuinely
 * clean, release silently — but `scanFiles` now also reaches zero findings
 * when every file was unreadable (oversized, or a read/extract failure):
 * `blocked`/`needsWarning` are derived from `findings`, so an all-unreadable
 * scan is indistinguishable from a clean one by those two flags alone.
 * Without this fork, that scan released (or replayed) the upload with no
 * dialog, no event, and no way for `onError:"closed"` to ever engage —
 * indistinguishable from "nothing found" from the outside.
 *
 * `release()` is the path's normal continuation (releaseFileInput /
 * replayDrop). `onBlock`, run only when failing closed, lets the file-input
 * caller clear its held input (drop has no analogous held state, so it
 * defaults to a no-op).
 */
function handleUnscanned(scan: FileScan, release: () => void, onBlock: () => void = () => {}): void {
  if (scan.unreadable === 0) {
    release();
    return;
  }
  if (failClosed()) {
    onBlock();
    showGuardrail({
      title: "This file can't be uploaded",
      detail: `${unreadableNote(scan.unreadable).trim()} Your organization's policy blocks unscanned uploads.`,
      actions: [{ label: "Close", onPick: () => {} }],
    });
    return;
  }
  release();
  showGuardrail({
    title: "Some files could not be scanned",
    detail: `${unreadableNote(scan.unreadable).trim()} The upload was not blocked, but its contents were not checked against policy.`,
    actions: [{ label: "OK", onPick: () => {} }],
  });
}

function showScanErrorBlocked() {
  showGuardrail({
    title: "This file can't be uploaded",
    detail: "The file couldn't be scanned and your organization's policy blocks unscanned uploads.",
    actions: [{ label: "Close", onPick: () => {} }],
  });
}

/** Re-deliver a held drop with a freshly built DataTransfer. */
function replayDrop(target: HTMLElement, files: File[]) {
  replaying = true;
  try {
    const dt = new DataTransfer();
    for (const f of files) dt.items.add(f);
    target.dispatchEvent(
      new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt }),
    );
  } catch {
    report("drop-replay-unsupported");
  } finally {
    replaying = false;
  }
}

/* ------------------------------ guardrail UI ----------------------------- */

interface GuardrailAction {
  label: string;
  primary?: boolean;
  onPick: () => void;
}

/**
 * Invoked when the active dialog is displaced by a newer one before any
 * button was picked. Dialogs that hold state (a paused upload) use this to
 * take their safe branch instead of leaking the hold.
 */
let onActiveDisplaced: (() => void) | null = null;

function categoriesOf(result: EvaluationResult): string {
  return [...new Set(result.findings.map((f) => f.detector))].join(", ");
}

/**
 * The dialog's host element and its closed shadow root, created once on
 * first display and reused for the page's lifetime. `guardrailHost` is the
 * ONLY way this module ever locates its own dialog — never
 * `document.getElementById` or a `#id`/class selector — because a fixed,
 * guessable id is exactly what let a page find and control the old dialog:
 *   - `host.id` is a per-load `crypto.randomUUID()`, not a constant, so a
 *     page cannot target it by id in CSS (`#promptwarden-guardrail{display:
 *     none!important}`) or in a `MutationObserver`/`querySelector` lookup —
 *     even one hardcoded from old source or docs misses on every load;
 *   - the shadow root's mode is "closed", so `guardrailHost.shadowRoot` is
 *     null to page script and page-authored CSS selectors cannot match
 *     anything inside it at all (open or closed — selectors never cross a
 *     shadow boundary). Inline styles on each element still apply exactly
 *     as before; a shadow root does not block a node's own `style` attribute.
 * The host is left attached (empty) after a dialog closes rather than
 * removed and recreated, so `guardrailHost` — and the identity check below
 * that depends on it — stay valid for the whole page lifetime.
 */
let guardrailHost: HTMLDivElement | null = null;
let guardrailShadow: ShadowRoot | null = null;

function ensureGuardrailHost(): ShadowRoot {
  if (guardrailHost && guardrailShadow) return guardrailShadow;
  guardrailHost = document.createElement("div");
  guardrailHost.id = crypto.randomUUID();
  guardrailShadow = guardrailHost.attachShadow({ mode: "closed" });
  document.documentElement.appendChild(guardrailHost);
  return guardrailShadow;
}

/**
 * Identity check for the click listener's self-exemption: does this click's
 * path pass through our own dialog host? `composedPath()` is deliberately
 * used instead of `event.target`: at a closed shadow boundary `target` is
 * retargeted to the host for outside listeners, but `composedPath()` is
 * unaffected by "closed" mode (it only gates the `.shadowRoot` property and
 * `target` retargeting, not path introspection) and still lists the host.
 * Since there is no id/selector involved, a page cannot forge a match by
 * setting its own id or injecting a lookalike element.
 */
function clickIsFromGuardrail(e: Event): boolean {
  if (!guardrailHost) return false;
  if (typeof e.composedPath === "function") {
    return e.composedPath().includes(guardrailHost);
  }
  // Defensive fallback for an engine without composedPath(): only catches a
  // click on the host itself, not its shadow-internal descendants.
  return e.target === guardrailHost;
}

function showGuardrail(opts: {
  title: string;
  detail: string;
  actions: GuardrailAction[];
  onDisplaced?: () => void;
}) {
  const shadow = ensureGuardrailHost();
  const existing = shadow.firstElementChild;
  if (existing) {
    existing.remove();
    const displaced = onActiveDisplaced;
    onActiveDisplaced = null;
    displaced?.();
  }
  onActiveDisplaced = opts.onDisplaced ?? null;

  const box = document.createElement("div");
  box.setAttribute("role", "alertdialog");
  box.setAttribute("aria-label", "PromptWarden");
  box.style.cssText =
    "position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:2147483647;" +
    "max-width:520px;background:#101418;color:#e8edf2;border:1px solid #2c3540;" +
    "border-radius:10px;padding:14px 16px;font:13px/1.5 system-ui,sans-serif;" +
    "box-shadow:0 8px 30px rgba(0,0,0,.45)";

  // textContent throughout: detector labels come from a distributed policy
  // document, so they are never interpolated into markup.
  const title = document.createElement("strong");
  title.style.cssText = "display:block;margin-bottom:4px";
  title.textContent = opts.title;

  const detail = document.createElement("span");
  detail.style.color = "#aeb8c2";
  detail.textContent = opts.detail;

  const actions = document.createElement("div");
  actions.style.cssText = "margin-top:10px;display:flex;gap:8px";

  for (const action of opts.actions) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = action.label;
    b.style.cssText =
      "cursor:pointer;border-radius:6px;padding:6px 12px;font:inherit;border:1px solid " +
      (action.primary
        ? "#3f8cff;background:#1d4f9c;color:#fff"
        : "#2c3540;background:transparent;color:#e8edf2");
    b.addEventListener("click", (e) => {
      // Defense in depth, independent of the shadow boundary above: even if
      // a page ever obtained a reference to this button (a future bug, a
      // misconfiguration, a different browser's shadow-DOM quirk) and called
      // .click() on it, that must not self-approve the exact bypass this
      // dialog exists to gate. Reject anything not user-driven outright —
      // don't run onPick, and don't remove the dialog either, so the
      // approval stays pending. A real user click (isTrusted) behaves
      // exactly as before.
      if (!e.isTrusted) return;
      onActiveDisplaced = null;
      box.remove();
      action.onPick();
    });
    actions.appendChild(b);
  }

  box.append(title, detail, actions);
  shadow.appendChild(box);
}

/* ----------------------------- logging & telemetry ----------------------- */

/** Fire-and-forget messaging: a dead service worker must never break the page. */
function send(message: unknown, callback?: (resp: any) => void) {
  try {
    const result = callback
      ? chrome.runtime.sendMessage(message, callback)
      : chrome.runtime.sendMessage(message);
    // Without a callback MV3 returns a promise; swallow rejections.
    void (result as unknown as Promise<unknown> | undefined)?.catch?.(() => {});
  } catch {
    /* extension context invalidated */
  }
}

/**
 * The only outbound event surface. `toLogRecord` is the single privacy gate:
 * it returns null when logging is off and strips matched content unless the
 * policy explicitly opts into logging mode "content". The record is sent
 * verbatim — nothing is added to it here.
 */
function log(result: EvaluationResult) {
  const record = toLogRecord(result, policy, location.hostname);
  if (!record) return;
  send({ type: "pw-event", record });
}

/**
 * Breakage telemetry. The payload is closed-set by construction: a reason code
 * from this union plus the hostname — never an error string, never content.
 * Suppressed entirely when the policy disables logging, so "logging: off"
 * means no record of any kind leaves the page.
 */
type DiagnosticKind = "policy-parse-error" | "file-scan-error" | "drop-replay-unsupported";

function report(kind: DiagnosticKind) {
  if (policy.logging === "off") return;
  send({ type: "diagnostic", kind, host: location.hostname });
}
