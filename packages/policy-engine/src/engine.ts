import { BUILTIN_DETECTORS, DEFAULT_LABELS, RawMatch } from "./detectors.js";
import { Action, EvaluationResult, Finding, Policy } from "./policy.js";

/**
 * Detectors whose matches feed the bulk_pii post-pass (see evaluate()).
 * Deliberately excludes api_key and custom regex rules: bulk_pii models
 * "someone pasted our whole customer list," not a batch of leaked secrets or
 * an org-specific identifier.
 */
const BULK_PII_DETECTORS = new Set(["email", "iban", "credit_card", "phone", "at_svnr"]);

const DEFAULT_BULK_PII_THRESHOLD = 5;

interface CompiledException {
  detector?: string;
  pattern: RegExp;
  hosts?: string[];
}

/**
 * Compile `policy.exceptions` once per `evaluate()` call. Guarded the same
 * way the custom-rule loop below guards `DetectorRule.pattern`: an invalid
 * pattern must not break evaluation. `parsePolicy` already rejects an
 * invalid pattern at policy-load time, so this catch only matters for a
 * `Policy` value that reached `evaluate()` without going through it.
 */
function compileExceptions(exceptions: Policy["exceptions"]): CompiledException[] {
  if (!exceptions || exceptions.length === 0) return [];
  const out: CompiledException[] = [];
  for (const ex of exceptions) {
    let pattern: RegExp;
    try {
      pattern = new RegExp(ex.pattern);
    } catch {
      continue;
    }
    out.push({ detector: ex.detector, pattern, hosts: ex.hosts });
  }
  return out;
}

/**
 * Upper bound on how much of a matched value an exception pattern is tested
 * against. See `isExcepted`.
 */
const MAX_EXCEPTION_TEST_BYTES = 1024;

/**
 * Does any compiled exception cover this candidate match? `hosts`-scoped
 * exceptions require the caller to have passed `evaluate()`'s `host`
 * parameter — an exception cannot claim to be host-restricted and then
 * apply unconditionally just because the caller didn't say which host it
 * evaluated.
 */
function isExcepted(m: RawMatch, exceptions: CompiledException[], host: string | undefined): boolean {
  // Test against a bounded prefix, never the whole match. An exception
  // pattern is admin-supplied but the string it runs against is not: a
  // `private_key` match is a whole PEM block and a custom rule's match can be
  // arbitrarily long, so a pattern with catastrophic backtracking would scale
  // its cost with attacker-controlled input and stall the inline path — which
  // is synchronous and holds a <10ms budget. Any exception meaningful enough
  // to allowlist a value is decidable from its opening bytes.
  for (const ex of exceptions) {
    if (ex.detector !== undefined && ex.detector !== m.detector) continue;
    if (ex.hosts !== undefined && (host === undefined || !ex.hosts.includes(host))) continue;
    const probe =
      m.match.length > MAX_EXCEPTION_TEST_BYTES ? m.match.slice(0, MAX_EXCEPTION_TEST_BYTES) : m.match;
    if (ex.pattern.test(probe)) return true;
  }
  return false;
}

/**
 * Evaluate `text` against `policy`.
 *
 * Precedence when spans overlap (e.g. a card number inside a longer string):
 * the stricter action wins, then the longer span.
 *
 * `host` is the currently-evaluated host (e.g. `location.hostname` in the
 * extension, a CLI surface label). It is optional and used only to resolve
 * `policy.exceptions` entries that carry a `hosts` restriction — omitting it
 * means host-scoped exceptions never apply, never that they apply
 * everywhere.
 */
export function evaluate(text: string, policy: Policy, host?: string): EvaluationResult {
  const candidates: RawMatch[] = [];
  const ruleFor = new Map(policy.rules.map((r) => [r.detector, r]));

  // Built-in detectors: run those the policy mentions, plus everything else
  // if the default action isn't "allow" (so a strict default still catches
  // categories the profile author forgot to list). Detectors that feed the
  // bulk_pii post-pass below always run regardless of their own action: an
  // individually-allowed email still has to count toward the bulk threshold
  // (email may be fine one-at-a-time, but 50 distinct emails is an exfil).
  for (const [id, fn] of Object.entries(BUILTIN_DETECTORS)) {
    const rule = ruleFor.get(id);
    const action = rule ? rule.action : policy.defaultAction;
    if (action === "allow" && !BULK_PII_DETECTORS.has(id)) continue;
    candidates.push(...fn(text));
  }

  // Custom regex rules (org-specific: customer ids, project code names, …).
  for (const rule of policy.rules) {
    if (rule.detector in BUILTIN_DETECTORS || rule.detector === "bulk_pii" || !rule.pattern) continue;
    let re: RegExp;
    try {
      re = new RegExp(rule.pattern, "g");
    } catch {
      continue; // invalid pattern in a distributed policy must not break the page
    }
    for (const m of text.matchAll(re)) {
      if (m[0].length === 0) break; // guard against zero-width infinite loops
      candidates.push({ detector: rule.detector, start: m.index!, end: m.index! + m[0].length, match: m[0] });
    }
  }

  // Exceptions: known-good values that must never produce a finding, applied
  // to the raw candidate list — BEFORE candidates become findings (so an
  // excepted value never reaches `blocked`/`needsWarning`/`redactedText`)
  // and before the bulk_pii post-pass below counts distinct values (so an
  // excepted value is not exposure). See the `exceptions` doc comment on
  // `Policy` for the full matching contract.
  const exceptions = compileExceptions(policy.exceptions);
  const matches = exceptions.length === 0 ? candidates : candidates.filter((m) => !isExcepted(m, exceptions, host));

  const severity: Record<Action, number> = { allow: 0, observe: 1, warn: 2, redact: 3, block: 4 };

  const findings: Finding[] = matches
    .map((m) => {
      const rule = ruleFor.get(m.detector);
      const action: Action = rule ? rule.action : policy.defaultAction;
      const label = rule?.label ?? DEFAULT_LABELS[m.detector] ?? `[REDACTED:${m.detector.toUpperCase()}]`;
      return { ...m, action, label };
    })
    .filter((f) => f.action !== "allow")
    .sort((a, b) => a.start - b.start || severity[b.action] - severity[a.action] || (b.end - b.start) - (a.end - a.start));

  // Drop spans fully contained in an earlier, equal-or-stricter span.
  const kept: Finding[] = [];
  for (const f of findings) {
    const covered = kept.some(
      (k) => k.start <= f.start && k.end >= f.end && severity[k.action] >= severity[f.action],
    );
    if (!covered) kept.push(f);
  }

  // bulk_pii post-pass: fires when a SINGLE detector category (email, iban,
  // credit_card, phone, or at_svnr) reaches N+ DISTINCT values in one
  // payload — "5 different customers' emails," "5 different IBANs."
  // Counting is deliberately PER CATEGORY rather than a flat union across
  // all five (the previous behaviour): an ordinary business email signature
  // carries one person's own email plus several of THEIR OWN phone numbers
  // under different labels (office/mobile/fax/direct line) — e.g. 4 distinct
  // phone numbers + 1 email is 5 distinct values in total, but neither
  // category individually reaches the threshold, and it is one person's
  // contact details, not bulk exposure. Requiring the threshold to be met
  // WITHIN a single category catches the genuine mass-export case (many
  // distinct values of the SAME kind) without that cross-category false
  // positive (ROADMAP §1.4 #16(a); fp-corpus.test.ts carries both the
  // signature fixture that reproduced it and a 5-customer fixture that must
  // still fire).
  //
  // Counting uses `matches` (the raw, pre-allow-filter, post-exception
  // list), so an individually-allowed category (e.g. email: allow) still
  // counts toward ITS OWN category's threshold — allowed one-at-a-time but
  // not as a mass export — while a value dropped by a policy exception
  // never counts at all (see `exceptions` above).
  //
  // Per ROADMAP §1.4 #16(b), bulk_pii is a synthetic meta-detector: unlike
  // every other detector it has NO rule-free fallback to `defaultAction`.
  // With no explicit `bulk_pii` rule in the policy it never fires, however
  // far past the threshold a category goes — otherwise it would silently
  // activate on any policy whose defaultAction isn't "allow", without the
  // policy author ever having opted into it.
  const bulkRule = ruleFor.get("bulk_pii");
  if (bulkRule) {
    const distinctByCategory = new Map<string, Set<string>>();
    for (const m of matches) {
      if (!BULK_PII_DETECTORS.has(m.detector)) continue;
      let bucket = distinctByCategory.get(m.detector);
      if (!bucket) {
        bucket = new Set();
        distinctByCategory.set(m.detector, bucket);
      }
      bucket.add(m.match);
    }
    const bulkThreshold = policy.bulkPiiThreshold ?? DEFAULT_BULK_PII_THRESHOLD;
    const triggered = [...distinctByCategory.values()].some((bucket) => bucket.size >= bulkThreshold);
    if (triggered) {
      const bulkAction: Action = bulkRule.action;
      if (bulkAction === "redact") {
        // Redacting the whole-text span would wipe the entire prompt down to
        // one label. Redact the contributing PII matches instead: one finding
        // per distinct span not already redacted/blocked by its own rule, so
        // the surrounding legitimate text survives.
        const bulkLabel = bulkRule.label ?? DEFAULT_LABELS.bulk_pii;
        const promoted = new Set<string>();
        for (const m of matches) {
          if (!BULK_PII_DETECTORS.has(m.detector)) continue;
          const key = `${m.start}:${m.end}`;
          if (promoted.has(key)) continue;
          promoted.add(key);
          const alreadyHandled = kept.some(
            (k) => k.start <= m.start && k.end >= m.end && severity[k.action] >= severity.redact,
          );
          if (alreadyHandled) continue;
          kept.push({ detector: "bulk_pii", start: m.start, end: m.end, match: m.match, action: "redact", label: bulkLabel });
        }
      } else if (bulkAction !== "allow") {
        const bulkLabel = bulkRule.label ?? DEFAULT_LABELS.bulk_pii;
        const totalDistinct = new Set(
          matches.filter((m) => BULK_PII_DETECTORS.has(m.detector)).map((m) => m.match),
        ).size;
        // Deliberately NOT `match: text` — this finding's span covers the whole
        // evaluated text (see comment above), and `toLogRecord` copies `match`
        // verbatim under logging:"content". A synthetic, count-style token
        // keeps the finding shape intact (start/end still describe "the whole
        // text was implicated") without ever putting the whole prompt — or a
        // whole extracted spreadsheet, via scanFiles — into a persisted record.
        kept.push({
          detector: "bulk_pii",
          start: 0,
          end: text.length,
          match: `${totalDistinct} distinct matches`,
          action: bulkAction,
          label: bulkLabel,
        });
      }
    }
  }

  // Build redacted text right-to-left so offsets stay valid.
  let redactedText = text;
  for (const f of [...kept].sort((a, b) => b.start - a.start)) {
    if (f.action === "redact" || f.action === "block") {
      redactedText = redactedText.slice(0, f.start) + f.label + redactedText.slice(f.end);
    }
  }

  const blocked = kept.some((f) => f.action === "block");
  const needsWarning = !blocked && kept.some((f) => f.action === "warn");

  return { findings: kept, redactedText, blocked, needsWarning };
}

/**
 * Hard cap on the length of any `match` string that reaches a persisted
 * record, regardless of which detector produced it or how long the
 * underlying span was. This is a backstop, not the primary defense — the
 * primary defense is that individual detectors match bounded-length tokens
 * (an IBAN, a card number, …) and the bulk_pii post-pass no longer carries
 * the whole text (see `evaluate`) — but nothing here should ever have to
 * trust that upstream invariant to hold forever.
 */
const MAX_LOGGED_MATCH_CHARS = 64;

/** Truncate `match` to the persisted cap, leaving an explicit marker when cut. */
function truncateMatch(match: string): string {
  if (match.length <= MAX_LOGGED_MATCH_CHARS) return match;
  return match.slice(0, MAX_LOGGED_MATCH_CHARS) + "…";
}

/**
 * `categories` and `actions` are each independently deduped, so a record
 * with e.g. a card at `block` and an IBAN at `redact` loses which detector
 * had which action — a consumer (the popup's per-rule tuning view) can only
 * guess a single "primary" action for every category listed. `pairs` keeps
 * detector and action bound together — still carrying no matched text — so
 * an "observe mode" reader can tell exactly which detector took which
 * action. Deduped (a detector firing twice with the same action is one
 * pair) and sorted by detector then action so the record is deterministic
 * regardless of finding order.
 */
function dedupedSortedPairs(findings: Finding[]): Array<{ detector: string; action: Action }> {
  const seen = new Map<string, { detector: string; action: Action }>();
  for (const f of findings) {
    seen.set(`${f.detector} ${f.action}`, { detector: f.detector, action: f.action });
  }
  return [...seen.values()].sort(
    (a, b) => a.detector.localeCompare(b.detector) || a.action.localeCompare(b.action),
  );
}

/**
 * Produce the log record for an evaluation, honouring the policy's logging
 * mode. This is the only function that should ever build persisted output —
 * keeping the privacy decision in one place makes it auditable.
 */
export function toLogRecord(
  result: EvaluationResult,
  policy: Policy,
  host: string,
): Record<string, unknown> | null {
  if (policy.logging === "off" || result.findings.length === 0) return null;
  const base = {
    ts: new Date().toISOString(),
    host,
    policy: policy.name,
    categories: [...new Set(result.findings.map((f) => f.detector))],
    actions: [...new Set(result.findings.map((f) => f.action))],
    pairs: dedupedSortedPairs(result.findings),
  };
  if (policy.logging === "event") return base;
  return {
    ...base,
    matches: result.findings.map((f) => ({ detector: f.detector, match: truncateMatch(f.match) })),
  };
}

/**
 * Second privacy gate: a summary safe to hand to something that isn't the
 * extension's own local storage — a CLI exit message, a hook's block reason
 * fed back into a model's context, anything that might echo the string
 * onward. Unlike `toLogRecord`, this is NOT governed by `policy.logging`:
 * even under logging:"content" it must never contain a matched value, only
 * which detector categories fired and what action each one took. A block
 * message that quoted the IBAN it just blocked would leak exactly what the
 * block was meant to prevent.
 */
export function toUserMessage(result: EvaluationResult): string {
  if (result.findings.length === 0) return "No policy findings.";
  const byAction = new Map<Action, Set<string>>();
  for (const f of result.findings) {
    if (!byAction.has(f.action)) byAction.set(f.action, new Set());
    byAction.get(f.action)!.add(f.detector);
  }
  const order: Action[] = ["block", "redact", "warn", "observe", "allow"];
  const parts: string[] = [];
  for (const action of order) {
    const categories = byAction.get(action);
    if (categories && categories.size > 0) {
      parts.push(`${action}: ${[...categories].sort().join(", ")}`);
    }
  }
  return parts.join("; ");
}
