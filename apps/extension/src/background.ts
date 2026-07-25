/**
 * Background service worker.
 *
 * Policy precedence: managed storage (admin-pushed) > local (user-configured).
 * Events are buffered locally in chrome.storage.local and never leave the
 * device — there is no ingest endpoint and this file makes no network calls.
 *
 * Event records arrive already privacy-filtered by the policy engine's
 * `toLogRecord` (see packages/policy-engine/src/engine.ts) — this file must
 * never add fields to them, only buffer, age out, and cap what it's given.
 */

type Message =
  | { type: "get-policy" }
  | { type: "event"; record: Record<string, unknown> }
  | { type: "pw-event"; record: Record<string, unknown> }
  | { type: "diagnostic"; kind: string; host: string };

const EVENT_BUFFER_KEY = "pw-events";
const DIAGNOSTIC_BUFFER_KEY = "pw-diagnostics";
const MAX_BUFFERED = 500;
const DEFAULT_RETENTION_DAYS = 90;
const DAY_MS = 24 * 60 * 60 * 1000;

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

/**
 * `retentionDays` is an admin-controlled field on the distributed policy
 * document. The policy schema (packages/policy-engine/src/policy.ts) is
 * outside this file's ownership, so it's read defensively off the resolved
 * `unknown` policy rather than assumed typed — anything missing, non-numeric,
 * or non-positive falls back to the DPIA-documented default of 90 days.
 */
function retentionDaysOf(policy: unknown): number {
  const raw = (policy as { retentionDays?: unknown } | null)?.retentionDays;
  return typeof raw === "number" && Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_RETENTION_DAYS;
}

/**
 * True if `entry.ts` parses to a time at or before `cutoffMs`. Entries
 * without a parseable `ts` are never treated as expired — retention can only
 * discard what it can date, never guess.
 */
function isExpired(entry: unknown, cutoffMs: number): boolean {
  const ts = entry && typeof entry === "object" ? (entry as Record<string, unknown>).ts : undefined;
  if (typeof ts !== "string") return false;
  const t = Date.parse(ts);
  return !Number.isNaN(t) && t < cutoffMs;
}

/** Drop entries older than the resolved policy's retentionDays from `buf`. */
async function pruneExpired(buf: unknown[]): Promise<unknown[]> {
  if (buf.length === 0) return buf;
  const policy = await resolvePolicy();
  const cutoff = Date.now() - retentionDaysOf(policy) * DAY_MS;
  return buf.filter((entry) => !isExpired(entry, cutoff));
}

/**
 * Append `entry` to the array stored at `key`, keeping only the most recent
 * `max`. For the event buffer this also prunes anything past the policy's
 * retentionDays first — age-based retention on top of the count cap, applied
 * on every append so a long-lived service worker still ages events out even
 * if it's never restarted.
 */
async function appendCapped(key: string, entry: unknown, max: number): Promise<void> {
  const data = await chrome.storage.local.get([key]);
  let buf: unknown[] = Array.isArray(data[key]) ? data[key] : [];
  if (key === EVENT_BUFFER_KEY) {
    buf = await pruneExpired(buf);
  }
  buf.push(entry);
  await chrome.storage.local.set({ [key]: buf.slice(-max) });
}

/**
 * appendCapped is a non-atomic read-modify-write; two events arriving within
 * one storage round-trip would clobber each other. All buffer writes — plus
 * the startup prune below — are serialized through this tail promise so none
 * of them can race each other.
 */
let writeQueue: Promise<void> = Promise.resolve();
function enqueueAppend(key: string, entry: unknown, max: number): void {
  writeQueue = writeQueue
    .then(() => appendCapped(key, entry, max))
    .catch((err) => console.warn("promptwarden: buffer write failed", err));
}

/**
 * Age out expired events once per service-worker startup, independent of
 * whether a new event ever arrives to trigger the prune-before-append above
 * (a quiet device should still lose old events on the day it wakes up).
 */
function enqueueStartupPrune(): void {
  writeQueue = writeQueue
    .then(async () => {
      const data = await chrome.storage.local.get([EVENT_BUFFER_KEY]);
      const buf: unknown[] = Array.isArray(data[EVENT_BUFFER_KEY]) ? data[EVENT_BUFFER_KEY] : [];
      const pruned = await pruneExpired(buf);
      if (pruned.length !== buf.length) {
        await chrome.storage.local.set({ [EVENT_BUFFER_KEY]: pruned });
      }
    })
    .catch((err) => console.warn("promptwarden: startup retention prune failed", err));
}
enqueueStartupPrune();

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
