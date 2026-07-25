/**
 * PromptWarden content script.
 *
 * Deliberately selector-less: AI sites change their DOM weekly, so nothing
 * here depends on site-specific CSS selectors. Instead we intercept the two
 * generic submission mechanics every chat UI uses:
 *   1. Enter keydown inside an editable element (capture phase)
 *   2. click on a button that submits an adjacent editable element
 *
 * On interception we read the active editable's text, evaluate it against the
 * policy, and either let it pass, warn, redact-and-resend, or block.
 */
import { evaluate, parsePolicy, hostMatches, Policy, EvaluationResult, toLogRecord } from "@promptwarden/policy-engine";
import { FALLBACK_POLICY } from "./default-policy.js";

let policy: Policy = FALLBACK_POLICY;
let bypassNextSubmit = false; // set after the user chooses "send anyway" / redact

chrome.runtime.sendMessage({ type: "get-policy" }, (resp) => {
  if (chrome.runtime.lastError) return;
  if (resp?.policy) {
    try {
      policy = parsePolicy(resp.policy);
    } catch (e) {
      report("policy-parse-error", String(e));
    }
  }
});

/* ------------------------------ text access ------------------------------ */

function isEditable(el: Element | null): el is HTMLElement {
  if (!el) return false;
  const tag = el.tagName;
  return (
    tag === "TEXTAREA" ||
    (tag === "INPUT" && (el as HTMLInputElement).type === "text") ||
    (el as HTMLElement).isContentEditable
  );
}

function readText(el: HTMLElement): string {
  if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
    return (el as HTMLTextAreaElement | HTMLInputElement).value;
  }
  return el.innerText ?? "";
}

function writeText(el: HTMLElement, text: string) {
  if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
    const input = el as HTMLTextAreaElement | HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(input),
      "value",
    )?.set;
    setter ? setter.call(input, text) : (input.value = text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  } else {
    el.innerText = text;
    el.dispatchEvent(new InputEvent("input", { bubbles: true }));
  }
}

function activeEditable(target: EventTarget | null): HTMLElement | null {
  const el = (target as Element)?.closest?.("textarea, input, [contenteditable=true], [contenteditable=plaintext-only]");
  if (isEditable(el as Element)) return el as HTMLElement;
  const focused = document.activeElement;
  return isEditable(focused) ? (focused as HTMLElement) : null;
}

/* ------------------------------ interception ----------------------------- */

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
  showGuardrail(editable, result);
}

document.addEventListener(
  "keydown",
  (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
    if (!hostMatches(policy, location.hostname)) return;
    const editable = activeEditable(e.target);
    if (editable) onSubmitAttempt(e, editable);
  },
  true, // capture phase: run before the page's own handlers
);

document.addEventListener(
  "click",
  (e) => {
    if (!hostMatches(policy, location.hostname)) return;
    const btn = (e.target as Element)?.closest?.('button[type="submit"], button[aria-label*="end" i], button[data-testid*="send" i]');
    if (!btn) return;
    const editable = activeEditable(null);
    if (editable) onSubmitAttempt(e, editable);
  },
  true,
);

/* ------------------------------ guardrail UI ----------------------------- */

const UI_ID = "promptwarden-guardrail";

function showGuardrail(editable: HTMLElement, result: EvaluationResult) {
  document.getElementById(UI_ID)?.remove();

  const categories = [...new Set(result.findings.map((f) => f.detector))].join(", ");
  const box = document.createElement("div");
  box.id = UI_ID;
  box.setAttribute("role", "alertdialog");
  box.setAttribute("aria-label", "PromptWarden");
  box.style.cssText =
    "position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:2147483647;" +
    "max-width:520px;background:#101418;color:#e8edf2;border:1px solid #2c3540;" +
    "border-radius:10px;padding:14px 16px;font:13px/1.5 system-ui,sans-serif;" +
    "box-shadow:0 8px 30px rgba(0,0,0,.45)";

  const title = result.blocked
    ? "This message can't be sent"
    : "Sensitive data detected";
  const detail = result.blocked
    ? `Your organization's policy blocks sending: ${categories}.`
    : `Found: ${categories}. Choose how to continue.`;

  box.innerHTML =
    `<strong style="display:block;margin-bottom:4px">${title}</strong>` +
    `<span style="color:#aeb8c2">${detail}</span>` +
    `<div id="pw-actions" style="margin-top:10px;display:flex;gap:8px"></div>`;

  const actions = box.querySelector("#pw-actions")!;
  const mkBtn = (label: string, primary: boolean, fn: () => void) => {
    const b = document.createElement("button");
    b.textContent = label;
    b.style.cssText =
      "cursor:pointer;border-radius:6px;padding:6px 12px;font:inherit;border:1px solid " +
      (primary ? "#3f8cff;background:#1d4f9c;color:#fff" : "#2c3540;background:transparent;color:#e8edf2");
    b.addEventListener("click", fn);
    actions.appendChild(b);
  };

  if (!result.blocked) {
    if (result.redactedText !== readText(editable)) {
      mkBtn("Redact and continue", true, () => {
        writeText(editable, result.redactedText);
        box.remove();
        editable.focus();
      });
    }
    if (result.needsWarning) {
      mkBtn("Send anyway", false, () => {
        bypassNextSubmit = true;
        box.remove();
        editable.focus();
        // Re-dispatch Enter so the page's own submit handler runs.
        editable.dispatchEvent(
          new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }),
        );
      });
    }
  }
  mkBtn(result.blocked ? "Close" : "Cancel", false, () => box.remove());

  document.documentElement.appendChild(box);
}

/* ----------------------------- logging & telemetry ----------------------- */

function log(result: EvaluationResult) {
  const record = toLogRecord(result, policy, location.hostname);
  if (record) chrome.runtime.sendMessage({ type: "event", record });
}

/** Breakage telemetry: category-level only, never content. */
function report(kind: string, detail: string) {
  chrome.runtime.sendMessage({ type: "diagnostic", kind, detail, host: location.hostname });
}
