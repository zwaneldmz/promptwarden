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
 *
 * Also owns dynamic host coverage (docs/HOST_COVERAGE.md): reconciling the
 * admin's managed-storage `extraHosts` declaration and Chrome's actually
 * granted optional permissions into a single dynamically registered content
 * script. This never requests a permission itself (that requires a user
 * gesture and lives in popup.js) — it only registers scripts for origins
 * Chrome already confirms are granted.
 */

import { FALLBACK_POLICY } from "./default-policy.js";

type Message =
  | { type: "get-policy" }
  | { type: "event"; record: Record<string, unknown> }
  | { type: "pw-event"; record: Record<string, unknown> }
  | { type: "diagnostic"; kind: string; host: string }
  | { type: "sync-extra-hosts" };

const EVENT_BUFFER_KEY = "pw-events";
const DIAGNOSTIC_BUFFER_KEY = "pw-diagnostics";
const MAX_BUFFERED = 500;
const DEFAULT_RETENTION_DAYS = 90;
const DAY_MS = 24 * 60 * 60 * 1000;

/** Registration id for the extraHosts dynamic content script. Stable across
 * reconciliation calls so re-registering under the same id is idempotent. */
const EXTRA_HOSTS_SCRIPT_ID = "pw-extra";
/** Same bundle the manifest's static entry injects — extraHosts get the
 * identical, host-agnostic content script, never a different one. */
const CONTENT_SCRIPT_FILE = "content.bundle.js";

/**
 * Closed set of reason codes background.ts can append to the shared
 * pw-diagnostics buffer. Kept as a literal union (rather than a free string)
 * so a future new failure mode has to be named here deliberately, matching
 * the pattern content.ts uses for its own `DiagnosticKind`.
 */
type BackgroundDiagnosticKind = "extra-hosts-error" | "managed-policy-invalid";

/** Where the currently resolved policy document came from. */
type PolicySource = "managed" | "local" | "built-in";

interface ResolvedPolicy {
  policy: unknown;
  source: PolicySource;
  /**
   * True only when a managed policy was present but failed to parse — the
   * one state that must be visible to an admin within seconds, since it
   * means enforcement silently dropped to the built-in default.
   */
  errored: boolean;
}

/**
 * Resolve the effective policy document.
 *
 * Precedence: managed storage (admin-pushed) > local (user-configured) >
 * built-in default. A managed policy that is *present but unparseable* is
 * the one case that must never fall through to `chrome.storage.local` — a
 * broken admin push handing control to the user-writable area is a
 * privilege inversion. That case fails to the built-in default instead,
 * comes back marked `errored: true`, and — unless `recordFailure` is false
 * — records a `managed-policy-invalid` diagnostic unconditionally: nothing
 * has loaded successfully at that point, so there is no policy's logging
 * mode to gate it on (see recordDiagnostic, which never checks one either).
 *
 * `recordFailure` defaults to true and must be passed `false` from
 * `pruneExpired`: that path itself appends to the diagnostic buffer, and
 * recording another diagnostic on every prune of a persistently-malformed
 * managed policy would requeue itself forever.
 */
async function resolvePolicy(recordFailure = true): Promise<ResolvedPolicy> {
  try {
    const managed = await chrome.storage.managed.get(["policy"]);
    if (typeof managed.policy === "string" && managed.policy.length > 0) {
      try {
        return { policy: JSON.parse(managed.policy), source: "managed", errored: false };
      } catch {
        if (recordFailure) {
          const kind: BackgroundDiagnosticKind = "managed-policy-invalid";
          recordDiagnostic(kind);
        }
        return { policy: FALLBACK_POLICY, source: "built-in", errored: true };
      }
    }
  } catch {
    /* managed storage unavailable outside enterprise deployments */
  }
  const local = await chrome.storage.local.get(["policy"]);
  if (local.policy) {
    return { policy: local.policy, source: "local", errored: false };
  }
  return { policy: FALLBACK_POLICY, source: "built-in", errored: false };
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
  // recordFailure: false — pruning must never itself enqueue a new
  // diagnostic write; see resolvePolicy's doc comment.
  const resolved = await resolvePolicy(false);
  const cutoff = Date.now() - retentionDaysOf(resolved.policy) * DAY_MS;
  return buf.filter((entry) => !isExpired(entry, cutoff));
}

/**
 * Append `entry` to the array stored at `key`, keeping only the most recent
 * `max`. For the event and diagnostic buffers this also prunes anything past
 * the policy's retentionDays first — age-based retention on top of the count
 * cap, applied on every append so a long-lived service worker still ages
 * entries out even if it's never restarted. The diagnostic buffer is a
 * second persistence path and must not be exempt from the same
 * policy-driven retention the event buffer gets.
 */
async function appendCapped(key: string, entry: unknown, max: number): Promise<void> {
  const data = await chrome.storage.local.get([key]);
  let buf: unknown[] = Array.isArray(data[key]) ? data[key] : [];
  if (key === EVENT_BUFFER_KEY || key === DIAGNOSTIC_BUFFER_KEY) {
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
 * Age out expired events and diagnostics once per service-worker startup,
 * independent of whether a new entry ever arrives to trigger the
 * prune-before-append above (a quiet device should still lose old entries on
 * the day it wakes up).
 */
function enqueueStartupPrune(): void {
  writeQueue = writeQueue
    .then(async () => {
      for (const key of [EVENT_BUFFER_KEY, DIAGNOSTIC_BUFFER_KEY]) {
        const data = await chrome.storage.local.get([key]);
        const buf: unknown[] = Array.isArray(data[key]) ? data[key] : [];
        const pruned = await pruneExpired(buf);
        if (pruned.length !== buf.length) {
          await chrome.storage.local.set({ [key]: pruned });
        }
      }
    })
    .catch((err) => console.warn("promptwarden: startup retention prune failed", err));
}
enqueueStartupPrune();

/**
 * Append a diagnostic entry through the same serialized write queue as every
 * other buffer write. `host` defaults to "background" for failures that
 * originate here rather than in a content script's page context — the
 * buffer's stored shape is unchanged (`{ kind, host, ts }`), this just gives
 * background-origin entries an identifiable, non-empty host value.
 */
function recordDiagnostic(kind: string, host: string = "background"): void {
  enqueueAppend(DIAGNOSTIC_BUFFER_KEY, { kind, host, ts: new Date().toISOString() }, MAX_BUFFERED);
}

/**
 * Reflects resolved-policy health in the toolbar badge — the "visible in
 * five seconds on a helpdesk call" signal for a state that requires opening
 * the popup to otherwise notice. Cleared on any healthy resolution. Wrapped
 * defensively: chrome.action is unavailable in some non-standard contexts,
 * and a background-only signal must never throw.
 */
async function setBadgeForErrored(errored: boolean): Promise<void> {
  try {
    await chrome.action.setBadgeText({ text: errored ? "!" : "" });
    if (errored) {
      await chrome.action.setBadgeBackgroundColor({ color: "#c0392b" });
    }
  } catch {
    /* badge API unavailable; never throw from a background-only signal */
  }
}

/** Resolve the policy and update the toolbar badge from its errored state. */
function refreshPolicyBadge(): void {
  resolvePolicy(true)
    .then((resolved) => setBadgeForErrored(resolved.errored))
    .catch(() => {});
}

// ---------------------------------------------------------------------------
// Dynamic host coverage (docs/HOST_COVERAGE.md)
// ---------------------------------------------------------------------------

/**
 * True if `pattern` is a well-formed *https-only* match pattern
 * ("https://<host><path>"). Deliberately rejects `<all_urls>`, `http:`, and
 * every other scheme — `extraHosts` is admin-controlled input read out of
 * managed storage, so it's validated with the same distrust as any other
 * externally supplied string before it's ever handed to
 * chrome.permissions.contains/chrome.scripting.
 *
 * Grammar (subset of https://developer.chrome.com/docs/extensions/mv3/match_patterns/):
 * host is "*.<label>..." or a literal hostname — never empty, never a bare
 * "*" (a single extraHosts entry must not mean "every https origin"; the
 * whole point of the list is a narrow, named, auditable coverage extension),
 * and never containing "*" anywhere but that single leading wildcard label.
 */
function isValidHttpsMatchPattern(pattern: unknown): pattern is string {
  if (typeof pattern !== "string") return false;
  const m = /^https:\/\/([^/]+)(\/.*)$/.exec(pattern);
  if (!m) return false;
  const host = m[1];
  if (host.length === 0) return false;
  if (host === "*") return false; // bare wildcard: every https origin — rejected
  if (host.startsWith("*.")) {
    const rest = host.slice(2);
    return rest.length > 0 && !rest.includes("*");
  }
  return !host.includes("*");
}

/**
 * Read the admin's declared `extraHosts` out of managed storage, validated
 * to well-formed https match patterns. Missing/malformed/non-array/absent
 * managed storage all resolve to "no extra hosts" — matching the existing
 * fail-closed-to-default posture `resolvePolicy()` already uses for the
 * sibling `policy` field.
 */
async function readManagedExtraHosts(): Promise<string[]> {
  try {
    const managed = await chrome.storage.managed.get(["extraHosts"]);
    const raw = (managed as { extraHosts?: unknown }).extraHosts;
    if (!Array.isArray(raw)) return [];
    return [...new Set(raw.filter(isValidHttpsMatchPattern))];
  } catch {
    return [];
  }
}

/**
 * Whether the extension currently holds the "scripting" API permission
 * itself (declared in `optional_permissions`, granted only via a user
 * gesture in the popup or a fleet-wide `ExtensionSettings` push — never
 * requested from here). `chrome.permissions.contains` never throws for
 * asking about a permission the caller doesn't hold, but it's wrapped anyway
 * per this file's "never throw" contract.
 */
async function hasScriptingPermission(): Promise<boolean> {
  try {
    return await chrome.permissions.contains({ permissions: ["scripting"] });
  } catch {
    return false;
  }
}

/**
 * Filter `patterns` down to the subset Chrome confirms is already granted as
 * a host permission. Checked one pattern at a time (a batched
 * `contains({ origins: patterns })` call only answers "are all of these
 * granted?", not which ones) — this is what makes declaring 40 hosts and
 * granting 3 of them independently safe: the other 37 simply never make it
 * into the registered script's `matches`.
 */
async function filterGrantedOrigins(patterns: string[]): Promise<string[]> {
  const granted: string[] = [];
  for (const pattern of patterns) {
    try {
      if (await chrome.permissions.contains({ origins: [pattern] })) {
        granted.push(pattern);
      }
    } catch {
      // Treat a rejected contains() check as "not granted" — never throw.
    }
  }
  return granted;
}

function sameOriginSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.every((v, i) => v === sortedB[i]);
}

/**
 * Reconcile the single `pw-extra` dynamic content script registration
 * against `matches` (the currently granted, declared extraHosts). Reads the
 * existing registration first so this is idempotent to call repeatedly:
 * unchanged match sets are a no-op, a changed set goes through
 * `updateContentScripts` (not blind unregister-then-register), an empty set
 * unregisters, and a first-time non-empty set creates.
 */
async function reconcileRegisteredScript(matches: string[]): Promise<void> {
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [EXTRA_HOSTS_SCRIPT_ID] });
  const current = existing[0];

  if (matches.length === 0) {
    if (current) {
      await chrome.scripting.unregisterContentScripts({ ids: [EXTRA_HOSTS_SCRIPT_ID] });
    }
    return;
  }

  const sorted = [...matches].sort();
  if (current?.matches && sameOriginSet(current.matches, sorted)) {
    return; // already in sync
  }

  // Mirrors the static manifest entry's run_at/all_frames exactly, so
  // behavior on an extraHosts origin matches behavior on a default host.
  const definition: chrome.scripting.RegisteredContentScript = {
    id: EXTRA_HOSTS_SCRIPT_ID,
    matches: sorted,
    js: [CONTENT_SCRIPT_FILE],
    runAt: "document_start",
    allFrames: true,
    persistAcrossSessions: true,
  };

  if (current) {
    await chrome.scripting.updateContentScripts([definition]);
  } else {
    await chrome.scripting.registerContentScripts([definition]);
  }
}

/**
 * Reconciles dynamically-registered content scripts against the admin's
 * `extraHosts` policy field and the host permissions Chrome has actually
 * granted. Safe to call repeatedly — see call sites below (service-worker
 * startup, managed-storage change, permission grant/revoke, popup re-sync
 * request).
 *
 * Never throws: every step is either individually guarded or covered by the
 * outer try/catch, and any failure lands in pw-diagnostics as the single
 * closed-set "extra-hosts-error" reason code rather than surfacing to the
 * caller or crashing the service worker.
 */
async function syncExtraHostCoverage(): Promise<void> {
  try {
    const scriptingGranted = await hasScriptingPermission();
    if (!scriptingGranted) {
      // Without the "scripting" API permission itself, nothing could have
      // been registered through this API in the first place (registration
      // requires it too), and Chrome won't honor a stale registration
      // without it either — nothing to reconcile.
      return;
    }
    const declared = await readManagedExtraHosts();
    const grantedOrigins = await filterGrantedOrigins(declared);
    await reconcileRegisteredScript(grantedOrigins);
  } catch (err) {
    const kind: BackgroundDiagnosticKind = "extra-hosts-error";
    recordDiagnostic(kind);
    console.warn("promptwarden: extra-hosts sync failed", err);
  }
}

// Trigger points (docs/HOST_COVERAGE.md "Registration flow"):
// service-worker startup (direct call, mirroring enqueueStartupPrune()
// above — a service worker can wake for reasons other than onInstalled/
// onStartup firing), managed-storage changes to extraHosts, and permission
// grant/revoke (covers both the popup's user-gesture grant and a fleet-wide
// ExtensionSettings push, which lands here without ever touching the popup).
syncExtraHostCoverage();

// Same rationale, for policy health: refresh the toolbar badge on
// service-worker startup too, so a broken managed policy is visible even
// before any tab asks for one.
refreshPolicyBadge();

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "managed" && "extraHosts" in changes) {
    syncExtraHostCoverage();
  }
  if (areaName === "managed" && "policy" in changes) {
    refreshPolicyBadge();
  }
});

chrome.permissions.onAdded.addListener(() => syncExtraHostCoverage());
chrome.permissions.onRemoved.addListener(() => syncExtraHostCoverage());

chrome.runtime.onMessage.addListener((msg: Message, _sender, sendResponse) => {
  if (msg.type === "get-policy") {
    resolvePolicy(true).then((resolved) => {
      sendResponse({ policy: resolved.policy, source: resolved.source, errored: resolved.errored });
      void setBadgeForErrored(resolved.errored);
    });
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
    recordDiagnostic(msg.kind, msg.host);
    return false;
  }
  if (msg.type === "sync-extra-hosts") {
    // Sent by popup.js right after chrome.permissions.request resolves
    // truthy — re-syncs immediately instead of waiting for the
    // chrome.permissions.onAdded listener above. Both paths converge on the
    // same idempotent syncExtraHostCoverage().
    syncExtraHostCoverage().then(() => sendResponse({ ok: true }));
    return true; // async response
  }
  return false;
});
