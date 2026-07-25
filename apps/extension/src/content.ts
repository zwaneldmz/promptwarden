/**
 * PromptWarden content script.
 *
 * Deliberately selector-less: AI sites change their DOM weekly, so nothing
 * here depends on site-specific CSS selectors. Instead we intercept the
 * generic mechanics every chat UI shares, all in the capture phase so we run
 * before the page's own handlers:
 *   1. Enter keydown inside an editable element
 *   2. click on a button that submits an adjacent editable element
 *   3. paste of text into an editable element
 *   4. change on <input type="file"> and drop of files
 *
 * On interception we evaluate the text against the policy and either let it
 * pass, warn, redact, or block. The inline path is entirely local: no network
 * call, no LLM, ever. The only thing that leaves this script is the output of
 * `toLogRecord`, which is the single privacy gate for all logging.
 */
import { evaluate, parsePolicy, hostMatches, Policy, EvaluationResult, toLogRecord } from "@promptwarden/policy-engine";
import { FALLBACK_POLICY } from "./default-policy.js";
import { isTextLikeFile, scanFiles } from "./file-scan.js";
import {
  SavedSelection,
  activeEditable,
  insertText,
  readText,
  saveSelection,
  writeText,
} from "./text-io.js";

let policy: Policy = FALLBACK_POLICY;
let bypassNextSubmit = false; // set after the user chooses "send anyway" / redact
/** True only while we synthesize an event to release an upload we held. */
let replaying = false;

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

function enforcing(): boolean {
  return hostMatches(policy, location.hostname);
}

/* ------------------------------ submit path ------------------------------ */

function onSubmitAttempt(e: Event, editable: HTMLElement) {
  if (bypassNextSubmit) {
    bypassNextSubmit = false;
    return;
  }
  const text = readText(editable);
  if (!text.trim()) return;

  const result = evaluate(text, policy);
  if (result.findings.length === 0) return;

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
        onPick: () => {
          bypassNextSubmit = true;
          editable.focus();
          // Re-dispatch Enter so the page's own submit handler runs.
          editable.dispatchEvent(
            new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }),
          );
        },
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

document.addEventListener(
  "keydown",
  (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
    if (!enforcing()) return;
    const editable = activeEditable(e.target);
    if (editable) onSubmitAttempt(e, editable);
  },
  true, // capture phase: run before the page's own handlers
);

document.addEventListener(
  "click",
  (e) => {
    if (!enforcing()) return;
    const btn = (e.target as Element)?.closest?.('button[type="submit"], button[aria-label*="end" i], button[data-testid*="send" i]');
    if (!btn) return;
    const editable = activeEditable(null);
    if (editable) onSubmitAttempt(e, editable);
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

    // Take over the insertion so a redacted version can be substituted before
    // the text ever reaches the page's editor state.
    e.preventDefault();
    e.stopImmediatePropagation();
    // ponytail: paste + later submit can double-log one exposure; add a
    // correlation id if event counts must be exact
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
 * Text-like attachments are held (propagation stopped) while we read and
 * evaluate them, then either released or dropped. Anything not text-like is
 * never touched at all — the event flows on untouched and no filename or
 * metadata is recorded.
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
  const scannable = files.filter(isTextLikeFile);
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
      // Failing open on our own error: a bug in the guardrail must not leave
      // the user unable to upload anything.
      .catch(() => {
        report("file-scan-error");
        releaseFileInput(input);
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
    const scannable = files.filter(isTextLikeFile);
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
        replayDrop(target, files);
      });
  },
  true,
);

/** Let the page see the input/change events we held back. */
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

const UI_ID = "promptwarden-guardrail";

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

function showGuardrail(opts: {
  title: string;
  detail: string;
  actions: GuardrailAction[];
  onDisplaced?: () => void;
}) {
  const existing = document.getElementById(UI_ID);
  if (existing) {
    existing.remove();
    const displaced = onActiveDisplaced;
    onActiveDisplaced = null;
    displaced?.();
  }
  onActiveDisplaced = opts.onDisplaced ?? null;

  const box = document.createElement("div");
  box.id = UI_ID;
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
    b.addEventListener("click", () => {
      onActiveDisplaced = null;
      box.remove();
      action.onPick();
    });
    actions.appendChild(b);
  }

  box.append(title, detail, actions);
  document.documentElement.appendChild(box);
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
