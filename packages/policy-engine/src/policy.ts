/**
 * PromptWarden policy schema.
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
  | "bulk_pii"; // synthetic post-pass, see engine.ts evaluate()

export interface DetectorRule {
  detector: DetectorId | string; // string allows custom regex rules
  action: Action;
  /** Optional custom pattern (used when `detector` is not a built-in id). */
  pattern?: string;
  /** Placeholder label used for redaction, e.g. "[REDACTED:IBAN]". */
  label?: string;
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
   * Minimum count of DISTINCT matched strings across the email/iban/
   * credit_card/phone/at_svnr detectors (in one evaluated text) before the
   * synthetic "bulk_pii" finding fires — "someone pasted our whole customer
   * list." Positive integer. Default 5.
   */
  bulkPiiThreshold?: number;
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
    (typeof p.retentionDays !== "number" || !Number.isFinite(p.retentionDays) || p.retentionDays <= 0)
  ) {
    throw new Error("retentionDays must be a positive number");
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
  return input as Policy;
}

/** Does `host` match any policy host entry (exact or "*." wildcard)? */
export function hostMatches(policy: Policy, host: string): boolean {
  const h = host.toLowerCase();
  return policy.hosts.some((entry) => {
    const e = entry.toLowerCase();
    if (e.startsWith("*.")) {
      const suffix = e.slice(1); // ".example.com"
      return h.endsWith(suffix) || h === e.slice(2);
    }
    return h === e;
  });
}
