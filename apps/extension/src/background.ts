/**
 * Background service worker.
 *
 * Policy precedence: managed storage (admin-pushed) > local (user-configured).
 * Events are buffered locally; in managed deployments the console's ingest
 * endpoint (policyUrl origin) receives them in batches. In standalone mode
 * they stay on-device.
 */

type Message =
  | { type: "get-policy" }
  | { type: "event"; record: Record<string, unknown> }
  | { type: "diagnostic"; kind: string; detail: string; host: string };

const EVENT_BUFFER_KEY = "pw-events";
const MAX_BUFFERED = 500;

async function resolvePolicy(): Promise<unknown | null> {
  try {
    const managed = await chrome.storage.managed.get(["policy"]);
    if (typeof managed.policy === "string" && managed.policy.length > 0) {
      return JSON.parse(managed.policy);
    }
  } catch {
    /* managed storage unavailable outside enterprise deployments */
  }
  const local = await chrome.storage.local.get(["policy"]);
  return local.policy ?? null;
}

chrome.runtime.onMessage.addListener((msg: Message, _sender, sendResponse) => {
  if (msg.type === "get-policy") {
    resolvePolicy().then((policy) => sendResponse({ policy }));
    return true; // async response
  }
  if (msg.type === "event" || msg.type === "diagnostic") {
    chrome.storage.local.get([EVENT_BUFFER_KEY]).then((data) => {
      const buf: unknown[] = Array.isArray(data[EVENT_BUFFER_KEY]) ? data[EVENT_BUFFER_KEY] : [];
      buf.push({ ...msg, ts: (msg as { record?: { ts?: string } }).record?.ts ?? new Date().toISOString() });
      chrome.storage.local.set({ [EVENT_BUFFER_KEY]: buf.slice(-MAX_BUFFERED) });
    });
  }
  return false;
});
