import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, toLogRecord } from "../src/engine.js";
import { parsePolicy, hostMatches, Policy } from "../src/policy.js";
import { openAiStyleKey } from "./fixtures.js";

const strict: Policy = parsePolicy({
  version: 1,
  name: "test-strict",
  hosts: ["chatgpt.com", "*.anthropic.com"],
  defaultAction: "warn",
  logging: "event",
  rules: [
    { detector: "credit_card", action: "block" },
    { detector: "iban", action: "redact" },
    { detector: "email", action: "redact" },
    { detector: "api_key", action: "block" },
    { detector: "at_svnr", action: "redact" },
    { detector: "customer_id", action: "redact", pattern: "\\bCUST-\\d{6}\\b", label: "[REDACTED:CUSTOMER]" },
  ],
});

test("valid credit card (Luhn) is blocked; invalid one is ignored", () => {
  const valid = evaluate("card: 4532 0151 1283 0366", strict); // Luhn-valid Visa test number
  assert.equal(valid.blocked, true);
  assert.equal(valid.findings[0].detector, "credit_card");

  const invalid = evaluate("card: 4532 0151 1283 0367", strict);
  assert.equal(invalid.findings.some((f) => f.detector === "credit_card"), false);
});

test("valid IBAN (mod-97) is redacted; corrupted IBAN is ignored", () => {
  const valid = evaluate("pay to AT61 1904 3002 3457 3201 please", strict);
  assert.equal(valid.findings[0].detector, "iban");
  assert.ok(valid.redactedText.includes("[REDACTED:IBAN]"));
  assert.ok(!valid.redactedText.includes("1904"));

  const invalid = evaluate("pay to AT62 1904 3002 3457 3201 please", strict);
  assert.equal(invalid.findings.some((f) => f.detector === "iban"), false);
});

test("onError accepts open/closed, rejects anything else, and is optional", () => {
  const base = { version: 1, name: "t", hosts: [], defaultAction: "warn", logging: "off", rules: [] };
  assert.equal(parsePolicy({ ...base, onError: "open" }).onError, "open");
  assert.equal(parsePolicy({ ...base, onError: "closed" }).onError, "closed");
  assert.equal(parsePolicy(base).onError, undefined); // default: fail open
  assert.throws(() => parsePolicy({ ...base, onError: "strict" }), /onError/);
});

test("lowercase and mixed-case IBANs are detected (validator normalizes case)", () => {
  const lower = evaluate("pay to at61 1904 3002 3457 3201 please", strict);
  assert.equal(lower.findings.some((f) => f.detector === "iban"), true);

  const mixed = evaluate("pay to At61 1904 3002 3457 3201 please", strict);
  assert.equal(mixed.findings.some((f) => f.detector === "iban"), true);
});

test("emails are redacted with surrounding text intact", () => {
  const r = evaluate("contact anna.maier@example.at about the claim", strict);
  assert.equal(r.redactedText, "contact [REDACTED:EMAIL] about the claim");
});

test("API keys are blocked", () => {
  const r = evaluate(`use ${openAiStyleKey("abcdefghijklmnopqrstuvwx123456")} for the demo`, strict);
  assert.equal(r.blocked, true);
});

test("Austrian SVNR with valid check digit is redacted", () => {
  // 1237 010180: check digit 7 == (1*3+2*7+3*9) + (0*5+1*8+0*4+1*2+8*1+0*6) = 44+18 = 62 % 11 = 7
  const r = evaluate("svnr 1237 010180 on file", strict);
  assert.equal(r.findings[0]?.detector, "at_svnr");
  const bad = evaluate("svnr 1238 010180 on file", strict);
  assert.equal(bad.findings.some((f) => f.detector === "at_svnr"), false);
});

test("custom org rule fires with custom label", () => {
  const r = evaluate("see ticket for CUST-004211 today", strict);
  assert.equal(r.redactedText, "see ticket for [REDACTED:CUSTOMER] today");
});

test("multiple findings redact right-to-left without offset corruption", () => {
  const r = evaluate("a@b.co and c@d.co and AT611904300234573201", strict);
  assert.equal(r.redactedText, "[REDACTED:EMAIL] and [REDACTED:EMAIL] and [REDACTED:IBAN]");
});

test("block wins over warn; needsWarning only when nothing blocks", () => {
  const warnOnly = evaluate("+43 660 1234567 is my number", strict); // phone falls to defaultAction=warn
  assert.equal(warnOnly.blocked, false);
  assert.equal(warnOnly.needsWarning, true);

  const mixed = evaluate("+43 660 1234567 and 4532015112830366", strict);
  assert.equal(mixed.blocked, true);
  assert.equal(mixed.needsWarning, false);
});

test("event-mode logging never contains matched content", () => {
  const r = evaluate("anna.maier@example.at", strict);
  const rec = toLogRecord(r, strict, "chatgpt.com");
  assert.ok(rec);
  assert.equal(JSON.stringify(rec).includes("anna.maier"), false);
  assert.deepEqual(rec!.categories, ["email"]);
});

test("content-mode logging includes matches (explicit opt-in path)", () => {
  const contentPolicy = { ...strict, logging: "content" as const };
  const r = evaluate("anna.maier@example.at", contentPolicy);
  const rec = toLogRecord(r, contentPolicy, "chatgpt.com");
  assert.ok(JSON.stringify(rec).includes("anna.maier"));
});

test("logging off produces no record at all", () => {
  const offPolicy = { ...strict, logging: "off" as const };
  const r = evaluate("anna.maier@example.at", offPolicy);
  assert.equal(toLogRecord(r, offPolicy, "chatgpt.com"), null);
});

test("host matching: exact and wildcard", () => {
  assert.equal(hostMatches(strict, "chatgpt.com"), true);
  assert.equal(hostMatches(strict, "claude.anthropic.com"), true);
  assert.equal(hostMatches(strict, "anthropic.com"), true);
  assert.equal(hostMatches(strict, "evil-chatgpt.com"), false);
});

test("invalid policies are rejected with readable errors", () => {
  assert.throws(() => parsePolicy({ version: 2 }), /version/);
  assert.throws(
    () => parsePolicy({ version: 1, name: "x", hosts: [], defaultAction: "nuke", logging: "event", rules: [] }),
    /defaultAction/,
  );
});

test('a bare "*" host entry is rejected instead of silently matching nothing', () => {
  const base = {
    version: 1,
    name: "x",
    defaultAction: "warn",
    logging: "event",
    rules: [],
  };
  assert.throws(() => parsePolicy({ ...base, hosts: ["*"] }), /bare "\*"/);
  // Mixed in with real hosts, still rejected — not just a special-case for the sole entry.
  assert.throws(() => parsePolicy({ ...base, hosts: ["claude.ai", "*"] }), /bare "\*"/);
  // Whitespace-padded bare wildcard is caught too.
  assert.throws(() => parsePolicy({ ...base, hosts: [" * "] }), /bare "\*"/);
  // A subdomain wildcard is a different, still-supported shape and must not be rejected.
  assert.equal(parsePolicy({ ...base, hosts: ["*.example.com"] }).hosts[0], "*.example.com");
});

test("zero-width custom pattern cannot hang the engine", () => {
  const p = parsePolicy({
    version: 1,
    name: "weird",
    hosts: ["chatgpt.com"],
    defaultAction: "allow",
    logging: "event",
    rules: [{ detector: "weird", action: "redact", pattern: "x*" }],
  });
  const r = evaluate("hello", p);
  assert.ok(Array.isArray(r.findings)); // completed without hanging
});

/* ------------------------ retentionDays ceiling (ROADMAP §1.1 #12) -------------------- */

test("retentionDays: accepts the 365-day boundary, rejects one day past it, and rejects the original 36500 regression", () => {
  const base = { version: 1, name: "t", hosts: [], defaultAction: "warn", logging: "off", rules: [] };
  assert.equal(parsePolicy({ ...base, retentionDays: 365 }).retentionDays, 365);
  assert.throws(() => parsePolicy({ ...base, retentionDays: 366 }), /retentionDays/);
  assert.throws(() => parsePolicy({ ...base, retentionDays: 36500 }), /retentionDays/);
  // Existing lower-bound behaviour (positive, finite) must still hold.
  assert.throws(() => parsePolicy({ ...base, retentionDays: 0 }), /retentionDays/);
  assert.throws(() => parsePolicy({ ...base, retentionDays: -1 }), /retentionDays/);
  assert.throws(() => parsePolicy({ ...base, retentionDays: Infinity }), /retentionDays/);
  assert.equal(parsePolicy(base).retentionDays, undefined); // still optional
});

/* --------------------------- toLogRecord pairs (ROADMAP §1.4 #18, contract A) ---------- */

test("toLogRecord pairs: binds each detector to the action it actually took, deduped and sorted by detector then action", () => {
  // IBAN at redact, credit card at block — categories/actions alone would
  // say "redact, block" happened and "iban, credit_card" fired, but not
  // which detector took which action.
  const policy = parsePolicy({
    version: 1,
    name: "pairs-test",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [
      { detector: "iban", action: "redact" },
      { detector: "credit_card", action: "block" },
    ],
  });
  const text = "card 4532 0151 1283 0366 and iban AT61 1904 3002 3457 3201";
  const r = evaluate(text, policy);
  const rec = toLogRecord(r, policy, "chatgpt.com")!;
  assert.ok(rec);
  assert.deepEqual(rec.pairs, [
    { detector: "credit_card", action: "block" },
    { detector: "iban", action: "redact" },
  ]);
  // categories/actions are unchanged in shape and content.
  assert.deepEqual([...(rec.categories as string[])].sort(), ["credit_card", "iban"]);
  assert.deepEqual([...(rec.actions as string[])].sort(), ["block", "redact"]);
});

test("toLogRecord pairs: present under logging:\"content\" too, and never carries matched text", () => {
  const policy = parsePolicy({
    version: 1,
    name: "pairs-content-test",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "content",
    rules: [
      { detector: "iban", action: "redact" },
      { detector: "credit_card", action: "block" },
    ],
  });
  const distinctiveIban = "AT611904300234573201";
  const distinctiveCard = "4532015112830366";
  const text = `card ${distinctiveCard} and iban ${distinctiveIban}`;
  const r = evaluate(text, policy);
  const rec = toLogRecord(r, policy, "chatgpt.com")!;
  assert.ok(rec);
  assert.deepEqual(rec.pairs, [
    { detector: "credit_card", action: "block" },
    { detector: "iban", action: "redact" },
  ]);
  // The `matches` field (content mode only) may legitimately carry the
  // matched text — but `pairs` itself, serialized on its own, must not.
  assert.equal(JSON.stringify(rec.pairs).includes(distinctiveIban), false);
  assert.equal(JSON.stringify(rec.pairs).includes(distinctiveCard), false);
});

test("toLogRecord pairs: deduped when the same detector/action combination appears in multiple findings", () => {
  const policy = parsePolicy({
    version: 1,
    name: "pairs-dedup-test",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [{ detector: "email", action: "redact" }],
  });
  const r = evaluate("a@example.com and b@example.com and c@example.com", policy);
  assert.equal(r.findings.length, 3); // three separate findings, same detector+action
  const rec = toLogRecord(r, policy, "chatgpt.com")!;
  assert.deepEqual(rec.pairs, [{ detector: "email", action: "redact" }]);
});

/* --------------------------------- exceptions (ROADMAP §1.4 #17, contract B) ----------- */

test("exceptions: a matching pattern drops the finding entirely — no block, no warning, no redaction", () => {
  const policy = parsePolicy({
    version: 1,
    name: "exceptions-basic",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [{ detector: "credit_card", action: "block" }],
    exceptions: [
      { detector: "credit_card", pattern: "^4111[ -]?1111[ -]?1111[ -]?1111$", note: "reserved Visa test PAN" },
    ],
  });
  const testCard = evaluate("card on file: 4111 1111 1111 1111", policy);
  assert.equal(testCard.findings.length, 0);
  assert.equal(testCard.blocked, false);
  assert.equal(testCard.redactedText, "card on file: 4111 1111 1111 1111");

  // A different, real-shaped card is unaffected by the exception.
  const realCard = evaluate("card on file: 4532 0151 1283 0366", policy);
  assert.equal(realCard.blocked, true);
});

test("exceptions: detector scoping — an exception for one detector id does not suppress another", () => {
  const policy = parsePolicy({
    version: 1,
    name: "exceptions-detector-scope",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [
      { detector: "credit_card", action: "block" },
      { detector: "iban", action: "block" },
    ],
    exceptions: [{ detector: "credit_card", pattern: ".*" }], // disables credit_card entirely
  });
  const r = evaluate("card 4532 0151 1283 0366 and iban AT61 1904 3002 3457 3201", policy);
  assert.equal(r.findings.some((f) => f.detector === "credit_card"), false);
  assert.equal(r.findings.some((f) => f.detector === "iban"), true);
  assert.equal(r.blocked, true); // iban still blocks
});

test("exceptions: host scoping — applies only on the listed host, and never applies when evaluate() is called without a host", () => {
  const policy = parsePolicy({
    version: 1,
    name: "exceptions-host-scope",
    hosts: ["chatgpt.com", "internal-tool.example"],
    defaultAction: "warn",
    logging: "event",
    rules: [{ detector: "credit_card", action: "block" }],
    exceptions: [
      { detector: "credit_card", pattern: "^4111[ -]?1111[ -]?1111[ -]?1111$", hosts: ["internal-tool.example"] },
    ],
  });
  const text = "card 4111 1111 1111 1111 on file";
  assert.equal(evaluate(text, policy, "internal-tool.example").blocked, false, "excepted on the listed host");
  assert.equal(evaluate(text, policy, "chatgpt.com").blocked, true, "not excepted elsewhere");
  assert.equal(evaluate(text, policy).blocked, true, "not excepted when no host is passed at all");
});

test("exceptions: dropped BEFORE the bulk_pii distinct-count post-pass counts it — an excepted value is not exposure", () => {
  const policy = parsePolicy({
    version: 1,
    name: "exceptions-bulk-pii-interaction",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [{ detector: "bulk_pii", action: "block" }],
    exceptions: [{ detector: "email", pattern: "^noreply@internal\\.example$", note: "our own system sender" }],
  });
  // 4 genuine distinct customer emails + 1 excepted internal address: without
  // the exception this would be 5 distinct emails (meets the threshold);
  // with it, only 4 count, so bulk_pii must not fire.
  const text =
    "a@example.com b@example.com c@example.com d@example.com noreply@internal.example";
  const r = evaluate(text, policy);
  assert.equal(r.findings.some((f) => f.detector === "bulk_pii"), false);
  assert.equal(r.findings.some((f) => f.detector === "email" && f.match === "noreply@internal.example"), false);
});

test("exceptions: an invalid pattern in a hand-built Policy is skipped, not thrown, mirroring custom-rule pattern handling", () => {
  // Bypasses parsePolicy's own validation (which would reject this) to
  // exercise evaluate()'s independent guard directly.
  const policy = {
    version: 1,
    name: "exceptions-invalid-pattern",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [{ detector: "credit_card", action: "block" }],
    exceptions: [{ detector: "credit_card", pattern: "(unclosed" }],
  } as unknown as Policy;
  const r = evaluate("card 4532 0151 1283 0366", policy);
  assert.equal(r.blocked, true); // invalid exception ignored, detection still runs
});

test("exceptions: parsePolicy validates shape — pattern must compile as RegExp, detector/note strings, hosts an array of strings", () => {
  const base = {
    version: 1,
    name: "exceptions-validation",
    hosts: [],
    defaultAction: "warn",
    logging: "event",
    rules: [],
  };
  assert.throws(() => parsePolicy({ ...base, exceptions: "nope" }), /exceptions must be an array/);
  assert.throws(() => parsePolicy({ ...base, exceptions: [{ pattern: 123 }] }), /pattern/);
  assert.throws(() => parsePolicy({ ...base, exceptions: [{ pattern: "(unclosed" }] }), /regular expression/);
  assert.throws(() => parsePolicy({ ...base, exceptions: [{ pattern: "x", detector: 5 }] }), /detector/);
  assert.throws(() => parsePolicy({ ...base, exceptions: [{ pattern: "x", note: 5 }] }), /note/);
  assert.throws(() => parsePolicy({ ...base, exceptions: [{ pattern: "x", hosts: "chatgpt.com" }] }), /hosts/);
  assert.throws(() => parsePolicy({ ...base, exceptions: [{ pattern: "x", hosts: [5] }] }), /hosts/);
  assert.equal(parsePolicy(base).exceptions, undefined); // optional
  const valid = parsePolicy({
    ...base,
    exceptions: [{ detector: "credit_card", pattern: "^4111", hosts: ["a.example"], note: "test PAN" }],
  });
  assert.equal(valid.exceptions?.length, 1);
});
