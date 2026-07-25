import { BUILTIN_DETECTORS, DEFAULT_LABELS, RawMatch } from "./detectors.js";
import { Action, EvaluationResult, Finding, Policy } from "./policy.js";

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
  // categories the profile author forgot to list).
  for (const [id, fn] of Object.entries(BUILTIN_DETECTORS)) {
    const rule = ruleFor.get(id);
    const action = rule ? rule.action : policy.defaultAction;
    if (action === "allow") continue;
    matches.push(...fn(text));
  }

  // Custom regex rules (org-specific: customer ids, project code names, …).
  for (const rule of policy.rules) {
    if (rule.detector in BUILTIN_DETECTORS || !rule.pattern) continue;
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

  const severity: Record<Action, number> = { allow: 0, warn: 1, redact: 2, block: 3 };

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
