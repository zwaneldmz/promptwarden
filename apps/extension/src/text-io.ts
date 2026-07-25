/**
 * Editable-element text I/O for the content script.
 *
 * Selector-less by construction: elements are identified by generic DOM
 * semantics (tag name, `isContentEditable`) only — never by site-specific
 * selectors — so nothing here rots when an AI vendor reshuffles its DOM.
 */

export function isEditable(el: Element | null): el is HTMLElement {
  if (!el) return false;
  const tag = el.tagName;
  return (
    tag === "TEXTAREA" ||
    (tag === "INPUT" && (el as HTMLInputElement).type === "text") ||
    (el as HTMLElement).isContentEditable
  );
}

function isField(el: HTMLElement): el is HTMLInputElement | HTMLTextAreaElement {
  return el.tagName === "TEXTAREA" || el.tagName === "INPUT";
}

/**
 * Write through the prototype's native `value` setter so frameworks that keep
 * their own value tracker (React) observe the change.
 */
function setFieldValue(
  input: HTMLInputElement | HTMLTextAreaElement,
  value: string,
  caret?: number,
) {
  const setter = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(input),
    "value",
  )?.set;
  setter ? setter.call(input, value) : (input.value = value);
  if (caret !== undefined) {
    try {
      input.setSelectionRange(caret, caret);
    } catch {
      /* input types without a selection range */
    }
  }
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

export function readText(el: HTMLElement): string {
  if (isField(el)) return el.value;
  return el.innerText ?? "";
}

/** Replace the entire contents of an editable. */
export function writeText(el: HTMLElement, text: string) {
  if (isField(el)) {
    setFieldValue(el, text, text.length);
  } else {
    el.innerText = text;
    el.dispatchEvent(new InputEvent("input", { bubbles: true }));
  }
}

export function activeEditable(target: EventTarget | null): HTMLElement | null {
  const el = (target as Element)?.closest?.("textarea, input, [contenteditable]");
  if (isEditable(el as Element)) return el as HTMLElement;
  const focused = document.activeElement;
  return isEditable(focused) ? (focused as HTMLElement) : null;
}

/* --------------------------- caret-preserving insert --------------------- */

/**
 * A snapshot of where an insertion should land. Captured while the originating
 * event is still being handled, because showing the guardrail moves focus.
 */
export type SavedSelection =
  | { kind: "field"; el: HTMLInputElement | HTMLTextAreaElement; start: number; end: number }
  | { kind: "range"; el: HTMLElement; range: Range | null };

export function saveSelection(el: HTMLElement): SavedSelection {
  if (isField(el)) {
    const end = el.value.length;
    return {
      kind: "field",
      el,
      start: el.selectionStart ?? end,
      end: el.selectionEnd ?? end,
    };
  }
  const sel = window.getSelection();
  const range =
    sel && sel.rangeCount > 0 && el.contains(sel.getRangeAt(0).commonAncestorContainer)
      ? sel.getRangeAt(0).cloneRange()
      : null;
  return { kind: "range", el, range };
}

/**
 * Insert `text` at the saved position, replacing whatever it spanned.
 * Used to substitute redacted text for a paste we intercepted.
 */
export function insertText(saved: SavedSelection, text: string) {
  if (saved.kind === "field") {
    const f = saved.el;
    f.focus();
    const value = f.value;
    const start = Math.min(saved.start, value.length);
    const end = Math.min(Math.max(saved.end, start), value.length);
    setFieldValue(f, value.slice(0, start) + text + value.slice(end), start + text.length);
    return;
  }

  saved.el.focus();
  if (saved.range) {
    const sel = window.getSelection();
    sel?.removeAllRanges();
    sel?.addRange(saved.range);
  }
  // execCommand keeps the page's undo stack and fires a native input event,
  // which editors built on contenteditable rely on.
  let inserted = false;
  try {
    inserted = document.execCommand("insertText", false, text);
  } catch {
    inserted = false;
  }
  if (inserted) return;

  const range = saved.range;
  if (!range) {
    saved.el.append(document.createTextNode(text));
  } else {
    range.deleteContents();
    const node = document.createTextNode(text);
    range.insertNode(node);
    range.setStartAfter(node);
    range.collapse(true);
    const sel = window.getSelection();
    sel?.removeAllRanges();
    sel?.addRange(range);
  }
  saved.el.dispatchEvent(
    new InputEvent("input", { bubbles: true, inputType: "insertText", data: text }),
  );
}
