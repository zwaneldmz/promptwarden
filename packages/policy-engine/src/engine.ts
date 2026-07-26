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

/**
 * Evaluate `text` against `policy`.
 *
 * Precedence when spans overlap (e.g. a card number inside a longer string):
 * the stricter action wins, then the longer span.
 */
export function evaluate(text: string, policy: Policy): EvaluationResult {
  const matches: RawMatch[] = [];
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
    matches.push(...fn(text));
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
      matches.push({ detector: rule.detector, start: m.index!, end: m.index! + m[0].length, match: m[0] });
    }
  }

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

  // bulk_pii post-pass: N+ distinct PII strings in one payload reads as
  // "someone pasted our whole customer list," even when every individual
  // category is allow-listed on its own. Counting uses `matches` (the raw,
  // pre-allow-filter list), so an individually-allowed email still counts
  // toward the threshold; the synthesized bulk_pii finding's own action is
  // resolved separately (its own rule entry, else defaultAction). Added to
  // `kept` after the containment pass so a whole-text bulk_pii span never
  // swallows the individual findings that justified it.
  const distinctBulkMatches = new Set(
    matches.filter((m) => BULK_PII_DETECTORS.has(m.detector)).map((m) => m.match),
  );
  const bulkThreshold = policy.bulkPiiThreshold ?? DEFAULT_BULK_PII_THRESHOLD;
  if (distinctBulkMatches.size >= bulkThreshold) {
    const bulkRule = ruleFor.get("bulk_pii");
    const bulkAction: Action = bulkRule ? bulkRule.action : policy.defaultAction;
    if (bulkAction === "redact") {
      // Redacting the whole-text span would wipe the entire prompt down to
      // one label. Redact the contributing PII matches instead: one finding
      // per distinct span not already redacted/blocked by its own rule, so
      // the surrounding legitimate text survives.
      const bulkLabel = bulkRule?.label ?? DEFAULT_LABELS.bulk_pii;
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
      const bulkLabel = bulkRule?.label ?? DEFAULT_LABELS.bulk_pii;
      kept.push({ detector: "bulk_pii", start: 0, end: text.length, match: text, action: bulkAction, label: bulkLabel });
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
  };
  if (policy.logging === "event") return base;
  return { ...base, matches: result.findings.map((f) => ({ detector: f.detector, match: f.match })) };
}
