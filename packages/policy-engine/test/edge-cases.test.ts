import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../src/engine.js";
import { parsePolicy, Policy } from "../src/policy.js";

const strict: Policy = parsePolicy({
  version: 1,
  name: "test-edge",
  hosts: ["chatgpt.com"],
  defaultAction: "warn",
  logging: "event",
  rules: [
    { detector: "credit_card", action: "block" },
    { detector: "iban", action: "redact" },
    { detector: "at_svnr", action: "redact" },
  ],
});

test("credit card with dash separators (Luhn-valid) is blocked", () => {
  const r = evaluate("card: 4532-0151-1283-0366", strict);
  assert.equal(r.blocked, true);
  assert.equal(r.findings[0].detector, "credit_card");
});

test("credit card with mixed dash/space separators (Luhn-valid) is blocked", () => {
  const r = evaluate("card: 4532-0151 1283-0366", strict);
  assert.equal(r.blocked, true);
  assert.equal(r.findings[0].detector, "credit_card");
});

test("Austrian SVNR without the optional space separator is still redacted", () => {
  // Same digits/check as the spaced case in engine.test.ts, just compact.
  const r = evaluate("svnr 1237010180 on file", strict);
  assert.equal(r.findings.some((f) => f.detector === "at_svnr"), true);
  assert.ok(r.redactedText.includes("[REDACTED:SVNR]"));
});
