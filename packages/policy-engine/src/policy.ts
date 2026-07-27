/**
 * Wardkeep policy schema.
 *
 * A policy is a versioned JSON document distributed to devices (via Chrome
 * managed storage in managed deployments, or a local file in standalone use).
 * It maps detector categories to actions and scopes enforcement to hosts.
 */

/** What the engine should do when a detector fires. */
export type Action =
  | "allow" // record nothing, let it through
  | "observe" // record the finding, never interrupt — silent baseline mode
  | "warn" // let the user decide; show what was found
  | "redact" // replace the finding with a placeholder before send
  | "block"; // prevent submission entirely

/** Built-in detector identifiers. */
export type DetectorId =
  | "credit_card"
  | "iban"
  | "email"
  | "phone"
  | "api_key"
  | "at_svnr" // Austrian social insurance number
  | "private_key" // PEM-armored private key block (RSA/EC/DSA/OpenSSH/PKCS#8/PGP)
  | "jwt" // three base64url segments with a decodable {"alg":…} header
  | "connection_string" // DB/queue URI or ODBC key=value form, credentials present
  | "bulk_pii"; // synthetic post-pass, see engine.ts evaluate()

export interface DetectorRule {
  detector: DetectorId | string; // string allows custom regex rules
  action: Action;
  /** Optional custom pattern (used when `detector` is not a built-in id). */
  pattern?: string;
  /** Placeholder label used for redaction, e.g. "[REDACTED:IBAN]". */
  label?: string;
}

/**
 * A known-good value that must never produce a finding, even though a
 * detector would otherwise match it — e.g. the reserved Luhn-valid test
 * card numbers (4111 1111 1111 1111, …) that engineers paste constantly, or
 * an internal example host. See the `exceptions` doc comment on `Policy`
 * for the full matching contract.
 */
export interface PolicyException {
  /** Restrict this exception to one detector id; omit to apply to all. */
  detector?: string;
  /** Compiled as a RegExp and tested against a finding's matched text. */
  pattern: string;
  /** Restrict this exception to these evaluated hosts; omit to apply everywhere. */
  hosts?: string[];
  /** Free-text justification. Not persisted, not shown to the user. */
  note?: string;
}

/** Logging levels, most-private first. EU-safe default is "event". */
export type LoggingMode =
  | "off" // nothing is recorded
  | "event" // category + host + timestamp only (default)
  | "content"; // full matched text — explicit opt-in, requires org policy basis

export interface Policy {
  /** Schema version for forward compatibility. */
  version: 1;
  /** Human-readable profile name, e.g. "Healthcare front office". */
  name: string;
  /** Hosts this policy applies to. Supports leading-wildcard, e.g. "*.openai.com". */
  hosts: string[];
  rules: DetectorRule[];
  logging: LoggingMode;
  /** Fallback action for detectors not listed in `rules`. */
  defaultAction: Action;
  /**
   * What a guardrail failure (e.g. an unreadable/unscannable file) does:
   * "open" releases the content unscanned (availability first, the default),
   * "closed" blocks it (strictness first, for managed deployments).
   */
  onError?: "open" | "closed";
  /**
   * Days locally buffered events are kept before age-based pruning
   * (Art. 5(1)(e) storage limitation). Default 90.
   */
  retentionDays?: number;
  /**
   * Threshold for the synthetic "bulk_pii" finding — "someone pasted our
   * whole customer list." Positive integer, default 5. Also derives
   * `CROSS_CATEGORY_MIN = max(2, ceil(bulkPiiThreshold / 2))` (3 at the
   * default). `bulk_pii` fires when EITHER:
   *
   *   (a) a SINGLE detector category (email, iban, credit_card, phone, or
   *       at_svnr) reaches `bulkPiiThreshold` DISTINCT matched strings on
   *       its own — many values of the same kind, never summed across
   *       categories — OR
   *   (b) at least TWO categories each reach `CROSS_CATEGORY_MIN` distinct
   *       values — breadth across categories AND depth within each one, the
   *       shape of a pasted customer table (3 rows -> 3 emails + 3 phones +
   *       3 IBANs) as opposed to one person's signature block (1 email + 4
   *       of their own phone numbers: depth without breadth).
   *
   * See engine.ts evaluate() for the full rationale and worked examples.
   * `bulk_pii` only fires when the policy carries an explicit `bulk_pii`
   * rule; it is never activated implicitly by `defaultAction`.
   */
  bulkPiiThreshold?: number;
  /**
   * Known-good values that should never produce a finding, applied after
   * detection but before a finding can block/warn/redact or count toward
   * `bulk_pii` — an excepted value is not exposure. Each entry is a
   * strictness REDUCTION: it can only ever drop a finding a detector would
   * otherwise raise, never add one. A finding is dropped when:
   *
   *   - the exception's compiled `pattern` matches the finding's matched
   *     text (via `RegExp.test`, so a partial match is enough — a pattern
   *     of `.*` matches everything a detector produces and so effectively
   *     DISABLES that detector; give such an exception a `note` explaining
   *     why that's intentional), AND
   *   - if `detector` is set, the finding's detector id equals it, AND
   *   - if `hosts` is set, the host passed to `evaluate()` matches at least
   *     one entry via `hostMatchesPattern` — the SAME matching `policy.hosts`
   *     uses (exact string equality, or a leading-wildcard subdomain match,
   *     e.g. "*.internal.example.com"), not a stricter exact-only check.
   *     "Host" here is the caller's surface label, not necessarily a
   *     browser hostname: `location.hostname` in the extension, but a
   *     string like "cli:scan" or "claude-code:PreToolUse" from a
   *     non-browser adapter — whatever that call site also passes to
   *     `toLogRecord`/`recordEvent`, so an exception scoped to a surface and
   *     an event logged from it always agree on what the surface is called.
   *
   * An exception whose `pattern` fails to compile as a `RegExp` is rejected
   * by `parsePolicy` (mirrors the same guard already applied to custom
   * `DetectorRule.pattern` values).
   *
   * SECURITY: a repo-local `.wardkeep.json` (see
   * apps/cli/src/policy.ts's strictness-monotonic clamp) strips
   * `exceptions` entirely before use — an untrusted checkout must not be
   * able to introduce or extend the set of values that silently bypass
   * detection any more than it can lower a rule's action.
   */
  exceptions?: PolicyException[];
}

export interface Finding {
  detector: string;
  action: Action;
  /** Start/end offsets in the original text. */
  start: number;
  end: number;
  /** The matched text. Never persisted unless logging === "content". */
  match: string;
  label: string;
}

export interface EvaluationResult {
  findings: Finding[];
  /** Text with all `redact`-action findings replaced by their labels. */
  redactedText: string;
  /** True if any finding carries the `block` action. */
  blocked: boolean;
  /** True if any finding carries `warn` (and none block). */
  needsWarning: boolean;
}

const ACTIONS: Action[] = ["allow", "observe", "warn", "redact", "block"];
const LOGGING: LoggingMode[] = ["off", "event", "content"];

/**
 * Ceiling for `retentionDays` (ROADMAP §1.1 #12). Without this, a managed or
 * repo-local policy setting e.g. 36500 turns a 90-day local event buffer
 * into an effectively permanent archive of what this device flagged.
 */
export const MAX_RETENTION_DAYS = 365;

/** Validate an untrusted policy document. Throws with a readable message. */
export function parsePolicy(input: unknown): Policy {
  if (typeof input !== "object" || input === null) {
    throw new Error("Policy must be an object");
  }
  const p = input as Record<string, unknown>;
  if (p.version !== 1) throw new Error("Unsupported policy version");
  if (typeof p.name !== "string" || p.name.length === 0) {
    throw new Error("Policy needs a name");
  }
  if (!Array.isArray(p.hosts) || p.hosts.some((h) => typeof h !== "string")) {
    throw new Error("Policy hosts must be an array of strings");
  }
  if ((p.hosts as string[]).some((h) => h.trim() === "*")) {
    throw new Error(
      'Policy hosts must not contain a bare "*" — hostMatches() has no all-hosts branch, so ' +
        '"*" matches zero hosts and silently disables enforcement everywhere. List explicit ' +
        'hosts (e.g. "claude.ai") or a subdomain wildcard (e.g. "*.example.com") instead.',
    );
  }
  if (!ACTIONS.includes(p.defaultAction as Action)) {
    throw new Error("defaultAction must be one of " + ACTIONS.join(", "));
  }
  if (!LOGGING.includes(p.logging as LoggingMode)) {
    throw new Error("logging must be one of " + LOGGING.join(", "));
  }
  if (p.onError !== undefined && p.onError !== "open" && p.onError !== "closed") {
    throw new Error('onError must be "open" or "closed"');
  }
  if (
    p.retentionDays !== undefined &&
    (typeof p.retentionDays !== "number" ||
      !Number.isFinite(p.retentionDays) ||
      p.retentionDays <= 0 ||
      p.retentionDays > MAX_RETENTION_DAYS)
  ) {
    throw new Error(`retentionDays must be a positive number no greater than ${MAX_RETENTION_DAYS}`);
  }
  if (
    p.bulkPiiThreshold !== undefined &&
    (typeof p.bulkPiiThreshold !== "number" ||
      !Number.isInteger(p.bulkPiiThreshold) ||
      p.bulkPiiThreshold <= 0)
  ) {
    throw new Error("bulkPiiThreshold must be a positive integer");
  }
  if (!Array.isArray(p.rules)) throw new Error("Policy rules must be an array");
  for (const r of p.rules as Array<Record<string, unknown>>) {
    if (typeof r.detector !== "string") throw new Error("Rule needs a detector id");
    if (!ACTIONS.includes(r.action as Action)) {
      throw new Error(`Rule "${r.detector}" has invalid action`);
    }
    if (r.pattern !== undefined && typeof r.pattern !== "string") {
      throw new Error(`Rule "${r.detector}" pattern must be a string`);
    }
  }
  if (p.exceptions !== undefined) {
    if (!Array.isArray(p.exceptions)) throw new Error("Policy exceptions must be an array");
    for (const ex of p.exceptions as Array<Record<string, unknown>>) {
      if (typeof ex.pattern !== "string") {
        throw new Error("Policy exception needs a pattern string");
      }
      try {
        new RegExp(ex.pattern);
      } catch (err) {
        throw new Error(
          `Policy exception pattern ${JSON.stringify(ex.pattern)} is not a valid regular expression: ${(err as Error).message}`,
        );
      }
      if (ex.detector !== undefined && typeof ex.detector !== "string") {
        throw new Error("Policy exception detector must be a string");
      }
      if (ex.note !== undefined && typeof ex.note !== "string") {
        throw new Error("Policy exception note must be a string");
      }
      if (ex.hosts !== undefined && (!Array.isArray(ex.hosts) || ex.hosts.some((h) => typeof h !== "string"))) {
        throw new Error("Policy exception hosts must be an array of strings");
      }
    }
  }
  return input as Policy;
}

/**
 * Does `host` match a single pattern entry — exact string equality, or a
 * leading-wildcard subdomain match ("*.example.com" matches both
 * "foo.example.com" and the bare apex "example.com")? Case-insensitive.
 *
 * This is the one implementation of "what does a host pattern mean" in the
 * engine: `hostMatches` uses it for every entry of `policy.hosts`, and
 * `evaluate()`'s exception matching (see the `exceptions` doc comment on
 * `Policy`) uses it for every entry of a `PolicyException.hosts` list — so
 * an admin writing "*.internal.example.com" in an exception gets the same
 * wildcard behaviour they already rely on in `policy.hosts`, not a silent
 * exact-match-only fallback.
 */
export function hostMatchesPattern(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase();
  if (p.startsWith("*.")) {
    const suffix = p.slice(1); // ".example.com"
    return h.endsWith(suffix) || h === p.slice(2);
  }
  return h === p;
}

/** Does `host` match any policy host entry (exact or "*." wildcard)? */
export function hostMatches(policy: Policy, host: string): boolean {
  return policy.hosts.some((entry) => hostMatchesPattern(host, entry));
}
