/**
 * Background service worker.
 *
 * Policy precedence: managed storage (admin-pushed) > local (user-configured).
 * Events are buffered locally in chrome.storage.local and never leave the
 * device — there is no ingest endpoint and this file makes no network calls.
 *
 * Event records arrive already privacy-filtered by the policy engine's
 * `toLogRecord` (see packages/policy-engine/src/engine.ts) — this file must
 * never add fields to them, only buffer and cap what it's given.
 */

type Message =
  | { type: "get-policy" }
  | { type: "event"; record: Record<string, unknown> }
  | { type: "pw-event"; record: Record<string, unknown> }
  | { type: "diagnostic"; kind: string; host: string };

const EVENT_BUFFER_KEY = "pw-events";
const DIAGNOSTIC_BUFFER_KEY = "pw-diagnostics";
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

/** Append `entry` to the array stored at `key`, keeping only the most recent `max`. */
async function appendCapped(key: string, entry: unknown, max: number): Promise<void> {
  const data = await chrome.storage.local.get([key]);
  const buf: unknown[] = Array.isArray(data[key]) ? data[key] : [];
  buf.push(entry);
  await chrome.storage.local.set({ [key]: buf.slice(-max) });
}

/**
 * appendCapped is a non-atomic read-modify-write; two events arriving within
 * one storage round-trip would clobber each other. All buffer writes are
 * serialized through this tail promise.
 */
let writeQueue: Promise<void> = Promise.resolve();
function enqueueAppend(key: string, entry: unknown, max: number): void {
  writeQueue = writeQueue
    .then(() => appendCapped(key, entry, max))
    .catch((err) => console.warn("promptwarden: buffer write failed", err));
}

chrome.runtime.onMessage.addListener((msg: Message, _sender, sendResponse) => {
  if (msg.type === "get-policy") {
    resolvePolicy().then((policy) => sendResponse({ policy }));
    return true; // async response
  }
  // "pw-event" is the current wire format; "event" is kept as an alias for
  // compatibility with the existing content-script sender. Both carry a
  // record that already passed through toLogRecord — store it as-is.
  if (msg.type === "pw-event" || msg.type === "event") {
    enqueueAppend(EVENT_BUFFER_KEY, msg.record, MAX_BUFFERED);
    return false;
  }
  if (msg.type === "diagnostic") {
    enqueueAppend(
      DIAGNOSTIC_BUFFER_KEY,
      { kind: msg.kind, host: msg.host, ts: new Date().toISOString() },
      MAX_BUFFERED,
    );
    return false;
  }
  return false;
});
