import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, toLogRecord } from "../src/engine.js";
import { parsePolicy, Policy } from "../src/policy.js";

/**
 * False-positive corpus + bulk_pii coverage.
 *
 * FP corpus: every fixture below is a realistic, everyday string a
 * support/ops/finance employee might paste, and must produce ZERO findings
 * under a policy with every built-in detector active (nothing set to
 * "allow", so nothing here passes by being ignored).
 *
 * bulk_pii: tests the post-pass detector for "someone pasted our whole
 * customer list" (see engine.ts evaluate()).
 */

/** Every built-in detector + bulk_pii turned on (non-allow), nothing silently skipped. */
const allDetectorsActive: Policy = parsePolicy({
  version: 1,
  name: "fp-corpus-all-active",
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
    { detector: "bulk_pii", action: "block" },
  ],
});

const FALSE_POSITIVE_CORPUS: Array<[label: string, text: string]> = [
  ["invoice number, bare", "RE-2026-004512"],
  ["invoice number, in a sentence", "Please process invoice RE-2026-004512 by Friday."],
  ["order number, 12 digits (non-Luhn)", "Order #400012345678 shipped today."],
  ["order number, 16 digits (non-Luhn)", "Reference 9876543210987654 on the packing slip."],
  ["order number, 10 digits (non-Luhn)", "PO 1234567890 approved."],
  ["German tracking number, 20 digits", "Tracking: 00340434161094137030"],
  ["German tracking number, letter-prefixed", "Sendungsnummer JJD0003900123456789"],
  ["EAN-13 barcode", "Barcode 5901234123457 on the label"],
  ["EAN-13 barcode, well-known example", "EAN 4006381333931 on the box"],
  ["IBAN-shaped but mod-97 invalid (DE)", "Old ref DE89370400440532013001 (do not use)"],
  ["IBAN-shaped but mod-97 invalid (AT)", "AT001904300234573201 was retired"],
  ["phone-shaped internal extension, ext.", "reach me on ext. 4471"],
  ["phone-shaped internal extension, Durchwahl", "Durchwahl 331-4471"],
  ["phone-shaped internal extension, x-prefix", "x4471 is the desk line"],
  ["UUID v4, in a log line", "id a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d in the trace"],
  ["UUID, standalone", "550e8400-e29b-41d4-a716-446655440000"],
  ["git SHA, full, in a sentence", "fixed in a94a8fe5ccb19ba61c4c0873d391e987982fbbd"],
  ["git SHA, short", "see commit a94a8fe for context"],
];

for (const [label, text] of FALSE_POSITIVE_CORPUS) {
  test(`false-positive corpus: ${label} produces zero findings`, () => {
    const r = evaluate(text, allDetectorsActive);
    assert.deepEqual(
      r.findings.map((f) => f.detector),
      [],
      `expected no findings for ${JSON.stringify(text)}, got: ${JSON.stringify(r.findings)}`,
    );
  });
}

test("false-positive corpus: the whole corpus concatenated still produces zero findings (no accidental bulk_pii either)", () => {
  const combined = FALSE_POSITIVE_CORPUS.map(([, text]) => text).join(" ");
  const r = evaluate(combined, allDetectorsActive);
  assert.deepEqual(r.findings, []);
});

/* ------------------------------- credit_card BIN gating ------------------------------- */

test("credit_card BIN gating: Luhn-valid but non-issuer-prefixed numbers are not flagged", () => {
  const policy = parsePolicy({
    version: 1,
    name: "bin-gating",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [{ detector: "credit_card", action: "block" }],
  });
  // Each of these is Luhn-valid (verified) but starts with a prefix outside
  // the real issuer ranges (Visa 4, Mastercard 51-55/22-27, Amex 34/37,
  // Discover 6011) — a bare "starts with 3-6" gate would have wrongly
  // flagged all three as a card.
  for (const n of ["5600000000000003", "6000000000000007", "3600000000000008"]) {
    const r = evaluate(`card: ${n}`, policy);
    assert.equal(
      r.findings.some((f) => f.detector === "credit_card"),
      false,
      `${n} is Luhn-valid but not a real issuer prefix and must not be flagged`,
    );
  }
});

test("credit_card BIN gating: a real issuer-prefixed, Luhn-valid card is still flagged", () => {
  const policy = parsePolicy({
    version: 1,
    name: "bin-gating-positive",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [{ detector: "credit_card", action: "block" }],
  });
  const r = evaluate("card: 4532 0151 1283 0366", policy); // Visa test number
  assert.equal(r.blocked, true);
  assert.equal(r.findings[0].detector, "credit_card");
});

/* ---------------------------------- bulk_pii ------------------------------------------ */

function bulkPolicy(overrides: Partial<Record<string, unknown>> = {}): Policy {
  return parsePolicy({
    version: 1,
    name: "bulk-pii-test",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [{ detector: "bulk_pii", action: "block" }],
    ...overrides,
  });
}

const FIVE_EMAILS = "a@example.com b@example.com c@example.com d@example.com e@example.com";
const FOUR_EMAILS = "a@example.com b@example.com c@example.com d@example.com";

test("bulk_pii: 5 distinct emails meets the default threshold and fires", () => {
  const r = evaluate(FIVE_EMAILS, bulkPolicy());
  assert.equal(r.findings.some((f) => f.detector === "bulk_pii"), true);
  assert.equal(r.blocked, true);
  const bulk = r.findings.find((f) => f.detector === "bulk_pii")!;
  assert.equal(bulk.start, 0);
  assert.equal(bulk.end, FIVE_EMAILS.length);
});

test("bulk_pii: 4 distinct emails does not meet the default threshold of 5", () => {
  const r = evaluate(FOUR_EMAILS, bulkPolicy());
  assert.equal(r.findings.some((f) => f.detector === "bulk_pii"), false);
});

test("bulk_pii: 10 copies of the same email count as 1 distinct match, so it does not fire", () => {
  const repeated = Array(10).fill("a@example.com").join(" ");
  const r = evaluate(repeated, bulkPolicy());
  assert.equal(r.findings.some((f) => f.detector === "bulk_pii"), false);
  // Every individual occurrence is still its own (non-bulk) email finding.
  assert.equal(r.findings.filter((f) => f.detector === "email").length, 10);
});

test("bulk_pii: bulkPiiThreshold overrides the default of 5", () => {
  const policy = bulkPolicy({ bulkPiiThreshold: 3 });
  const threeEmails = "a@example.com b@example.com c@example.com";
  const twoEmails = "a@example.com b@example.com";

  assert.equal(evaluate(threeEmails, policy).findings.some((f) => f.detector === "bulk_pii"), true);
  assert.equal(evaluate(twoEmails, policy).findings.some((f) => f.detector === "bulk_pii"), false);
});

test("bulk_pii: distinct matches across categories (not just one) count toward the threshold", () => {
  const policy = bulkPolicy();
  // 2 emails + 1 iban + 1 phone = 4 distinct matches across categories: not enough.
  const fourDistinctAcrossCategories =
    "a@example.com b@example.com pay to AT61 1904 3002 3457 3201 please call +43 660 1234567 about the ticket";
  assert.equal(
    evaluate(fourDistinctAcrossCategories, policy).findings.some((f) => f.detector === "bulk_pii"),
    false,
  );
  // Adding a 5th distinct match (an SVNR) from yet another category tips it over.
  const fiveDistinctAcrossCategories = `${fourDistinctAcrossCategories} svnr 1237 010180 on file`;
  assert.equal(
    evaluate(fiveDistinctAcrossCategories, policy).findings.some((f) => f.detector === "bulk_pii"),
    true,
  );
});

test("bulk_pii: an allow-ruled bulk_pii stays silent even past the threshold", () => {
  const policy = bulkPolicy({ rules: [{ detector: "bulk_pii", action: "allow" }] });
  const r = evaluate(FIVE_EMAILS, policy);
  assert.equal(r.findings.some((f) => f.detector === "bulk_pii"), false);
});

test("observe action: findings are recorded but nothing warns, blocks, or redacts", () => {
  const policy = bulkPolicy({
    defaultAction: "observe",
    rules: [
      { detector: "credit_card", action: "observe" },
      { detector: "iban", action: "observe" },
    ],
  });
  const text = "pay AT61 1904 3002 3457 3201 with card 4532 0151 1283 0366";
  const r = evaluate(text, policy);
  assert.ok(r.findings.length >= 2);
  assert.equal(r.blocked, false);
  assert.equal(r.needsWarning, false);
  assert.equal(r.redactedText, text);
  const rec = toLogRecord(r, policy, "chatgpt.com");
  assert.ok(rec, "observe findings must produce a log record");
  assert.deepEqual([...(rec.categories as string[])].sort(), ["credit_card", "iban"]);
});

test("bulk_pii: redact action redacts the contributing matches, never the whole prompt", () => {
  const policy = bulkPolicy({
    rules: [
      { detector: "email", action: "allow" },
      { detector: "bulk_pii", action: "redact", label: "[BULK]" },
    ],
  });
  const text = `Please check ${FIVE_EMAILS} for the order, thanks!`;
  const r = evaluate(text, policy);
  // Surrounding legitimate text survives; every contributing email is gone.
  assert.ok(r.redactedText.startsWith("Please check "));
  assert.ok(r.redactedText.endsWith("for the order, thanks!"));
  assert.ok(r.redactedText.includes("[BULK]"));
  assert.equal(/@/.test(r.redactedText), false);
  assert.ok(r.findings.every((f) => f.detector === "bulk_pii" && f.end - f.start < text.length));
});

test("bulk_pii: an individually-allowed detector's matches still count toward the bulk threshold", () => {
  // email is allow-listed on its own (so no individual email findings appear)
  // but 5 distinct emails must still trip bulk_pii — an allowed category is
  // fine one-at-a-time but not as a mass export.
  const policy = bulkPolicy({
    rules: [
      { detector: "email", action: "allow" },
      { detector: "bulk_pii", action: "block" },
    ],
  });
  const r = evaluate(FIVE_EMAILS, policy);
  assert.deepEqual(r.findings.map((f) => f.detector), ["bulk_pii"]);
  assert.equal(r.blocked, true);
});

test("bulk_pii: toLogRecord categories include bulk_pii when it fires", () => {
  const policy = bulkPolicy();
  const r = evaluate(FIVE_EMAILS, policy);
  const rec = toLogRecord(r, policy, "chatgpt.com");
  assert.ok(rec);
  assert.ok((rec!.categories as string[]).includes("bulk_pii"));
  // Event-mode logging still never contains matched content, bulk_pii included.
  assert.equal(JSON.stringify(rec).includes("a@example.com"), false);
});

test("bulk_pii: parsePolicy rejects a non-positive-integer bulkPiiThreshold", () => {
  const base = { version: 1, name: "t", hosts: [], defaultAction: "warn", logging: "off", rules: [] };
  assert.throws(() => parsePolicy({ ...base, bulkPiiThreshold: 0 }), /bulkPiiThreshold/);
  assert.throws(() => parsePolicy({ ...base, bulkPiiThreshold: -1 }), /bulkPiiThreshold/);
  assert.throws(() => parsePolicy({ ...base, bulkPiiThreshold: 2.5 }), /bulkPiiThreshold/);
  assert.throws(() => parsePolicy({ ...base, bulkPiiThreshold: "5" }), /bulkPiiThreshold/);
  assert.equal(parsePolicy({ ...base, bulkPiiThreshold: 10 }).bulkPiiThreshold, 10);
  assert.equal(parsePolicy(base).bulkPiiThreshold, undefined); // optional, defaults to 5 in evaluate()
});
