import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../src/engine.js";
import { parsePolicy, Policy } from "../src/policy.js";
import { openAiStyleKey } from "./fixtures.js";

/**
 * Deterministic ~10 KB prompt: repeating prose paragraph interleaved with a
 * handful of PII-like strings (some detector-valid, some near-miss to make
 * the detectors do real work rather than short-circuiting on the first
 * candidate). No randomness, no network — pure string building so the test
 * is reproducible across machines and CI runs.
 */
function buildPrompt(): string {
  const paragraph =
    "Please review the attached quarterly summary and let me know if the " +
    "figures reconcile with what finance reported last cycle. The client " +
    "wants a walkthrough of the onboarding flow before the next release, " +
    "and we should confirm the support rota covers the holiday period. ";

  const piiSamples = [
    "card: 4532 0151 1283 0366", // Luhn-valid
    "card: 4532-0151-1283-0367", // Luhn-invalid (near miss)
    "iban: AT61 1904 3002 3457 3201", // mod-97 valid
    "iban: at61 1904 3002 3457 3202", // mod-97 invalid, lowercase
    "contact anna.maier@example.at for details",
    "call +43 660 1234567 about the ticket",
    `key ${openAiStyleKey("abcdefghijklmnopqrstuvwx123456")} is a demo secret`,
    "svnr 1237 010180 on file",
    "see ticket CUST-004211 today",
    "project code PROJ-77-ALPHA is confidential",
    "internal ref INT-9981-XZ needs review",
  ];

  const parts: string[] = [];
  let size = 0;
  let i = 0;
  const targetBytes = 10 * 1024;
  while (size < targetBytes) {
    const chunk = i % 4 === 0 ? piiSamples[(i / 4) % piiSamples.length] + ". " : paragraph;
    parts.push(chunk);
    size += chunk.length;
    i++;
  }
  return parts.join("");
}

const PROMPT = buildPrompt();

const policy: Policy = parsePolicy({
  version: 1,
  name: "bench-policy",
  hosts: ["chatgpt.com"],
  defaultAction: "warn",
  logging: "event",
  rules: [
    { detector: "credit_card", action: "block" },
    { detector: "iban", action: "redact" },
    { detector: "email", action: "redact" },
    { detector: "phone", action: "warn" },
    { detector: "api_key", action: "block" },
    { detector: "at_svnr", action: "redact" },
    { detector: "customer_id", action: "redact", pattern: "\\bCUST-\\d{6}\\b", label: "[REDACTED:CUSTOMER]" },
    { detector: "project_code", action: "warn", pattern: "\\bPROJ-\\d{2}-[A-Z]+\\b", label: "[REDACTED:PROJECT]" },
    { detector: "internal_ref", action: "redact", pattern: "\\bINT-\\d{4}-[A-Z]{2}\\b", label: "[REDACTED:INTERNAL]" },
  ],
});

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

test("engine evaluates a realistic 10 KB prompt in under 10ms median (50 runs, all detectors + 3 custom rules)", () => {
  assert.ok(PROMPT.length >= 10 * 1024, `prompt should be at least 10 KB, got ${PROMPT.length} bytes`);

  // Pin what the benchmark measures: a detector regressing to a no-op must
  // fail this test, not make it faster.
  const check = evaluate(PROMPT, policy);
  const found = new Set(check.findings.map((f) => f.detector));
  for (const d of ["credit_card", "iban", "phone", "email", "api_key", "at_svnr", "customer_id", "project_code", "internal_ref"]) {
    assert.ok(found.has(d), `detector ${d} found nothing in the fixture`);
  }
  assert.ok(check.findings.length >= 11, `expected >= 11 findings, got ${check.findings.length}`);

  // Warm up (JIT, hidden classes, etc.) — not measured.
  for (let i = 0; i < 5; i++) {
    evaluate(PROMPT, policy);
  }

  const samples: number[] = [];
  for (let i = 0; i < 50; i++) {
    const start = performance.now();
    evaluate(PROMPT, policy);
    samples.push(performance.now() - start);
  }

  const m = median(samples);
  // eslint-disable-next-line no-console
  console.log(`bench: median=${m.toFixed(3)}ms min=${Math.min(...samples).toFixed(3)}ms max=${Math.max(...samples).toFixed(3)}ms over ${samples.length} runs on a ${PROMPT.length}-byte prompt`);
  assert.ok(m < 10, `median evaluation time ${m.toFixed(3)}ms exceeds 10ms budget`);
});
