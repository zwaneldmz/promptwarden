import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, toLogRecord } from "../src/engine.js";
import { parsePolicy, hostMatches, Policy } from "../src/policy.js";

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
  const r = evaluate("use sk-abcdefghijklmnopqrstuvwx123456 for the demo", strict);
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
