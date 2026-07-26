import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, toLogRecord, toUserMessage } from "../src/engine.js";
import { parsePolicy, Policy } from "../src/policy.js";
import {
  pemArmor,
  pemBlock,
  jwtLike,
  stripeKey,
  awsAccessKeyId,
  githubFineGrainedPat,
  connectionUri,
  mssqlConnectionString,
  azureStorageConnectionString,
} from "./fixtures.js";

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
    { detector: "private_key", action: "block" },
    { detector: "jwt", action: "block" },
    { detector: "connection_string", action: "block" },
    { detector: "bulk_pii", action: "block" },
  ],
});

// JWT-shaped (three dot-separated base64url segments) but the first segment
// decodes to plain text ("not json at all, just text"), not JSON — reused
// below both as an FP-corpus entry and in the dedicated jwt negative test.
// Assembled via jwtLike() (test/fixtures.ts) rather than written out whole.
const NOT_A_JWT = jwtLike(
  "bm90IGpzb24gYXQgYWxsLCBqdXN0IHRleHQ",
  "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
);

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
  [
    "ops identifier, IBAN-shaped country+checkdigit prefix but unrecognized country code",
    "backup job VM03WINSRV2019DCPRODBACKUP07 failed",
  ],
  [
    "IBAN-shaped, valid prefix but embedded in a longer alphanumeric run (not standalone)",
    "order ref AT611904300234573201EXTRA processed",
  ],
  ["JWT-shaped three-segment string whose header decodes but is not JSON", `token ${NOT_A_JWT} is not real`],
  ["postgres connection string with no embedded credentials", "connect to postgres://localhost/db for the read replica"],
  [
    "long base64 blob that is not JWT-shaped (no dot-separated segments)",
    "config: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIn0 is the encoded blob",
  ],
  ["AWS-access-key-shaped string that fails the 16-char length check", "key AKIA1234567890 is only 14 chars after the prefix"],
  ["bare 'Password=' label with no connection-string context", "Password= is a required field on the form"],
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

/* ------------------------------ IBAN precision (ROADMAP §1.4 #14) --------------------- */

test("IBAN: per-country length table replaces the right-trim retry loop — random long alphanumeric runs are not flagged", () => {
  const policy = parsePolicy({
    version: 1,
    name: "iban-fp-rate",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [{ detector: "iban", action: "block" }],
  });
  const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = "0123456789";
  const alnum = letters + digits;
  function randCandidate(len: number): string {
    let s =
      letters[Math.floor(Math.random() * 26)] +
      letters[Math.floor(Math.random() * 26)] +
      digits[Math.floor(Math.random() * 10)] +
      digits[Math.floor(Math.random() * 10)];
    for (let i = 4; i < len; i++) s += alnum[Math.floor(Math.random() * alnum.length)];
    return s;
  }
  let falsePositives = 0;
  const trials = 2000;
  for (let i = 0; i < trials; i++) {
    const r = evaluate(randCandidate(26), policy);
    if (r.findings.length > 0) falsePositives++;
  }
  // The old right-trim loop measured ~13% FP at this length; the per-country
  // table + single mod-97 trial should land at (effectively) zero.
  assert.ok(
    falsePositives / trials < 0.01,
    `expected near-zero IBAN false positives on random text, got ${falsePositives}/${trials}`,
  );
});

test("IBAN: a country other than Austria is still recognized (per-country length table, not AT-only)", () => {
  const policy = parsePolicy({
    version: 1,
    name: "iban-multi-country",
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [{ detector: "iban", action: "redact" }],
  });
  // DE89370400440532013000 — canonical, well-known-valid example IBAN, 22 chars (DE official length).
  const r = evaluate("wire to DE89 3704 0044 0532 0130 00 today", policy);
  assert.equal(r.findings.some((f) => f.detector === "iban"), true);
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

/* ------------------------------ secrets family (ROADMAP §1.4 #13) --------------------- */

function secretPolicy(detector: string): Policy {
  return parsePolicy({
    version: 1,
    name: `secret-${detector}`,
    hosts: ["chatgpt.com"],
    defaultAction: "warn",
    logging: "event",
    rules: [{ detector, action: "block" }],
  });
}

test("private_key: a full PEM RSA private key block is blocked, header through footer", () => {
  const { header, footer } = pemArmor("RSA");
  const pem = pemBlock("RSA", "MIIEowIBAAKCAQEAtestkeymaterialAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  const r = evaluate(`please debug this: ${pem}`, secretPolicy("private_key"));
  assert.equal(r.blocked, true);
  const finding = r.findings.find((f) => f.detector === "private_key")!;
  assert.ok(finding.match.includes(header));
  assert.ok(finding.match.includes(footer));
});

test("private_key: OPENSSH, EC, PKCS#8 (plain + encrypted), and PGP blocks are all recognized", () => {
  const variants = [
    pemBlock("OPENSSH", "b3BlbnNzaC1rZXktdjEA"),
    pemBlock("EC", "MHcCAQEEIA=="),
    pemBlock("", "MIIEvQIBADANBg=="), // PKCS#8, plain
    pemBlock("ENCRYPTED", "MIIFHDBOBgkqhkiG=="), // PKCS#8, encrypted
    pemBlock("PGP", "lQPGBGAAAA==", true), // PGP PRIVATE KEY BLOCK
  ];
  for (const pem of variants) {
    const r = evaluate(pem, secretPolicy("private_key"));
    assert.equal(r.blocked, true, `expected a private_key finding for: ${pem.split("\n")[0]}`);
  }
});

test("private_key: a truncated paste (header with no matching END marker) is still flagged", () => {
  const { header } = pemArmor("RSA");
  const r = evaluate(`here's what I have so far: ${header}\nMIIEow`, secretPolicy("private_key"));
  assert.equal(r.blocked, true);
});

test("jwt: a real three-segment token with a decodable {alg} header is blocked", () => {
  // header {"alg":"HS256","typ":"JWT"}, payload {"sub":"1234567890"}
  const token = jwtLike(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  );
  const r = evaluate(`Authorization: Bearer ${token}`, secretPolicy("jwt"));
  assert.equal(r.blocked, true);
  assert.equal(r.findings[0].match, token);
});

test("jwt: an undecodable or non-JSON header is not flagged (decode-and-check, not pattern match)", () => {
  // Same shape (three long base64url segments) but the first segment decodes
  // to plain text, not JSON — must not be treated as a JWT.
  const r = evaluate(NOT_A_JWT, secretPolicy("jwt"));
  assert.equal(r.findings.some((f) => f.detector === "jwt"), false);
});

test("connection_string: postgres/mysql/mongodb+srv/redis/amqp URIs with embedded credentials are blocked", () => {
  const examples = [
    connectionUri("postgres", "admin", "S3cretPW", "db.internal:5432/prod"),
    connectionUri("mysql", "root", "hunter2", "127.0.0.1:3306/app"),
    connectionUri("mongodb+srv", "svc_user", "p4ssword", "cluster0.mongodb.net/mydb"),
    connectionUri("redis", "default", "redispass", "cache.internal:6379"),
    connectionUri("amqp", "guest", "guestpass", "broker.internal:5672/vhost"),
  ];
  for (const uri of examples) {
    const r = evaluate(`connect using ${uri} please`, secretPolicy("connection_string"));
    assert.equal(r.blocked, true, `expected connection_string finding for ${uri}`);
  }
});

test("connection_string: MSSQL/ODBC and Azure-style key=value forms with a populated password are blocked", () => {
  const mssql = mssqlConnectionString("myserver.database.windows.net", "mydb", "admin", "Sup3rSecret!");
  const azure = azureStorageConnectionString("mystorage", "abcd1234efgh5678ijkl==");
  for (const cs of [mssql, azure]) {
    const r = evaluate(cs, secretPolicy("connection_string"));
    assert.equal(r.blocked, true, `expected connection_string finding for ${cs}`);
  }
});

test("api_key: AWS temporary (ASIA) access key ids are recognized alongside AKIA", () => {
  const key = awsAccessKeyId("ASIA", "ABCDEFGHIJ123456");
  const r = evaluate(`export AWS_ACCESS_KEY_ID=${key}`, secretPolicy("api_key"));
  assert.equal(r.blocked, true);
});

test("api_key: GitHub fine-grained PAT (github_pat_) is recognized", () => {
  const pat = githubFineGrainedPat("11ABCDEFG0abcdefghijklmnopqrstuvwxyz1234567890");
  const r = evaluate(`token: ${pat}`, secretPolicy("api_key"));
  assert.equal(r.blocked, true);
});

test("api_key: Stripe live secret and restricted keys (sk_live_/rk_live_) are recognized", () => {
  // Assembled at runtime via stripeKey() (test/fixtures.ts) rather than
  // written out: a key-shaped literal here trips GitHub's push protection,
  // which cannot tell a fixture from a leak.
  const body = "51H7qXKG5Y6ZQvW3vN9pQrStUvWxYz";
  const secret = evaluate(`STRIPE_KEY=${stripeKey("sk", body)}`, secretPolicy("api_key"));
  assert.equal(secret.blocked, true);
  const restricted = evaluate(`STRIPE_KEY=${stripeKey("rk", body)}`, secretPolicy("api_key"));
  assert.equal(restricted.blocked, true);
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

/* ------------------------- privacy gate holes (ROADMAP §1.3) ------------------------- */

test("content-mode records never contain a match longer than the 64-char cap", () => {
  // A custom org rule whose pattern can capture an arbitrarily long span —
  // stands in for "whatever a distributed policy's own regex happens to
  // match" so the cap is a backstop independent of any one detector.
  const policy = parsePolicy({
    version: 1,
    name: "long-match-test",
    hosts: ["example.com"],
    defaultAction: "allow",
    logging: "content",
    rules: [{ detector: "big_blob", action: "warn", pattern: "BLOB[\\s\\S]*" }],
  });
  const text = "BLOB" + "x".repeat(300);
  const r = evaluate(text, policy);
  const rec = toLogRecord(r, policy, "example.com")!;
  assert.ok(rec);
  const matches = rec.matches as Array<{ detector: string; match: string }>;
  assert.equal(matches.length, 1);
  // Capped to the leading 64 chars plus an explicit truncation marker — not
  // a new field, just a shorter string with a visible "this was cut" sign.
  assert.equal(matches[0].match, text.slice(0, 64) + "…");
  assert.equal(matches[0].match.length, 65);
  assert.equal(JSON.stringify(rec).includes(text), false);
});

test("content-mode record for a short (uncapped) match is left untouched", () => {
  const policy = parsePolicy({
    version: 1,
    name: "short-match-test",
    hosts: ["example.com"],
    defaultAction: "redact",
    logging: "content",
    rules: [{ detector: "email", action: "redact" }],
  });
  const r = evaluate("contact anna.maier@example.at please", policy);
  const rec = toLogRecord(r, policy, "example.com")!;
  const matches = rec.matches as Array<{ detector: string; match: string }>;
  assert.equal(matches[0].match, "anna.maier@example.at");
  assert.ok(!matches[0].match.includes("…"));
});

test("bulk_pii: a triggering prompt's content-mode record does not contain the full prompt text", () => {
  const policy = parsePolicy({
    version: 1,
    name: "bulk-content-test",
    hosts: ["example.com"],
    defaultAction: "warn",
    logging: "content",
    rules: [{ detector: "bulk_pii", action: "warn" }],
  });
  const text = `Customer export for the weekly sync: ${FIVE_EMAILS} — please process today, thanks!`;
  const r = evaluate(text, policy);
  const rec = toLogRecord(r, policy, "example.com")!;
  assert.ok(rec);
  const matches = rec.matches as Array<{ detector: string; match: string }>;
  const bulk = matches.find((m) => m.detector === "bulk_pii");
  assert.ok(bulk, "bulk_pii finding must be present in the record");
  // The whole-text value must never reach the record: not equal to the full
  // prompt, and short enough that it plainly isn't the prompt.
  assert.notEqual(bulk!.match, text);
  assert.ok(bulk!.match.length < 64);
  assert.equal(JSON.stringify(rec).includes(text), false);
});

test("bulk_pii: redact behavior (contributing spans, not the whole text) still works after the match-shape change", () => {
  const policy = bulkPolicy({
    rules: [
      { detector: "email", action: "allow" },
      { detector: "bulk_pii", action: "redact", label: "[BULK]" },
    ],
  });
  const text = `Please check ${FIVE_EMAILS} for the order, thanks!`;
  const r = evaluate(text, policy);
  assert.ok(r.redactedText.startsWith("Please check "));
  assert.ok(r.redactedText.endsWith("for the order, thanks!"));
  assert.equal(/@/.test(r.redactedText), false);
  assert.ok(r.findings.every((f) => f.detector === "bulk_pii" && f.end - f.start < text.length));
});

test("toUserMessage: contains only categories and actions, never a matched value — even under logging:content", () => {
  const policy = parsePolicy({
    version: 1,
    name: "user-message-test",
    hosts: ["example.com"],
    defaultAction: "warn",
    logging: "content", // the whole point: this gate ignores the logging mode
    rules: [
      { detector: "iban", action: "redact" },
      { detector: "credit_card", action: "block" },
    ],
  });
  const distinctiveIban = "AT611904300234573201"; // mod-97 valid, no spaces
  const distinctiveCard = "4532015112830366"; // Luhn-valid Visa test number
  // Punctuation right after the IBAN keeps the greedy IBAN_CANDIDATE regex
  // from overrunning into "Then" — not what this test is about.
  const text = `Please wire to ${distinctiveIban}. Then charge card ${distinctiveCard} now.`;
  const r = evaluate(text, policy);
  assert.ok(r.findings.length >= 2);

  const message = toUserMessage(r);
  assert.equal(message.includes(distinctiveIban), false);
  assert.equal(message.includes(distinctiveCard), false);
  assert.equal(message.includes("1904"), false);
  assert.equal(message.includes("4532"), false);
  // Still informative: names the categories and the actions that fired.
  assert.ok(message.includes("iban"));
  assert.ok(message.includes("credit_card"));
  assert.ok(message.includes("redact"));
  assert.ok(message.includes("block"));
});

test("toUserMessage: no findings produces a message with no categories or matched values", () => {
  const policy = bulkPolicy({ defaultAction: "allow", rules: [] });
  const r = evaluate("nothing sensitive here", policy);
  assert.equal(r.findings.length, 0);
  assert.equal(toUserMessage(r), "No policy findings.");
});

test("event-mode logging still has no matches field at all, even for an oversized custom match (existing no-content guarantee holds)", () => {
  const policy = parsePolicy({
    version: 1,
    name: "event-mode-guard",
    hosts: ["example.com"],
    defaultAction: "allow",
    logging: "event",
    rules: [{ detector: "big_blob", action: "warn", pattern: "BLOB[\\s\\S]*" }],
  });
  const text = "BLOB" + "y".repeat(300);
  const r = evaluate(text, policy);
  const rec = toLogRecord(r, policy, "example.com")!;
  assert.ok(rec);
  assert.equal("matches" in rec, false);
  assert.equal(JSON.stringify(rec).includes(text), false);
  assert.equal(JSON.stringify(rec).includes("yyyy"), false);
});
