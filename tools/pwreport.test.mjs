import test from "node:test";
import assert from "node:assert/strict";
import { MIN_COHORT, mergeAggregates, renderReport } from "./pwreport.mjs";

/** Build a per-device aggregate export shaped like apps/extension/popup.js's buildAggregate(). */
function deviceAggregate(hosts, counts) {
  return { extensionVersion: "0.1.0", policyName: "test-policy", hosts, generatedDay: "2026-07-25", counts };
}

test("cohort suppression: a host×category seen on fewer than MIN_COHORT devices is folded into 'other'", () => {
  assert.equal(MIN_COHORT, 5);
  const aggregates = [];
  for (let i = 0; i < MIN_COHORT - 2; i++) {
    aggregates.push(
      deviceAggregate(["chatgpt.com"], {
        "2026-07-20": { "chatgpt.com": { iban: { warn: 1 } } },
      }),
    );
  }
  const merged = mergeAggregates(aggregates);
  assert.equal(merged.totalsByCategory.iban, undefined, "suppressed category must not appear by name");
  assert.equal(merged.totalsByCategory.other, MIN_COHORT - 2, "suppressed counts move to 'other', not dropped");
  assert.equal(merged.totalsByAction.warn, MIN_COHORT - 2, "action totals are never suppressed");
  assert.equal(merged.suppressedCombos, 1);
});

test("cohort met: a host×category seen on at least MIN_COHORT devices keeps its own label", () => {
  const aggregates = [];
  for (let i = 0; i < MIN_COHORT; i++) {
    aggregates.push(
      deviceAggregate(["chatgpt.com"], {
        "2026-07-20": { "chatgpt.com": { credit_card: { block: 1 } } },
      }),
    );
  }
  const merged = mergeAggregates(aggregates);
  assert.equal(merged.totalsByCategory.credit_card, MIN_COHORT);
  assert.equal(merged.totalsByCategory.other ?? 0, 0);
  assert.equal(merged.suppressedCombos, 0);
});

test("a device reporting the same host×category on multiple days only counts once toward the cohort", () => {
  // One device, two days — still one distinct device, so this alone stays suppressed.
  const single = deviceAggregate(["chatgpt.com"], {
    "2026-07-20": { "chatgpt.com": { email: { redact: 1 } } },
    "2026-07-21": { "chatgpt.com": { email: { redact: 1 } } },
  });
  const merged = mergeAggregates([single]);
  assert.equal(merged.totalsByCategory.email, undefined);
  assert.equal(merged.totalsByCategory.other, 2);
});

test("no key or value in the merged output or rendered report resembles an ISO-second timestamp", () => {
  const aggregates = [
    deviceAggregate(["claude.ai"], { "2026-07-21T10:15:30Z": { "claude.ai": { email: { redact: 2 } } } }),
    deviceAggregate(["claude.ai"], { "2026-07-21": { "claude.ai": { email: { redact: 2 } } } }),
  ];
  const merged = mergeAggregates(aggregates);
  const isoSecondPattern = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
  assert.doesNotMatch(JSON.stringify(merged), isoSecondPattern);
  // The malformed second-precision key above must have been dropped entirely, not truncated in.
  assert.equal(merged.totalsByCategory.email ?? merged.totalsByCategory.other, 2);

  const html = renderReport(merged, "2026-07-25");
  assert.doesNotMatch(html, isoSecondPattern);
});

test("counts add up: the sum of every raw per-device count equals the merged totals, exactly", () => {
  const aggregates = [
    deviceAggregate(["chatgpt.com", "claude.ai"], {
      "2026-07-14": { "chatgpt.com": { iban: { warn: 2 }, credit_card: { block: 1 } } },
      "2026-07-21": { "claude.ai": { email: { redact: 3 } } },
    }),
    deviceAggregate(["chatgpt.com"], { "2026-07-14": { "chatgpt.com": { iban: { warn: 1 } } } }),
    deviceAggregate(["chatgpt.com"], { "2026-07-15": { "chatgpt.com": { iban: { warn: 4 } } } }),
    deviceAggregate(["chatgpt.com"], { "2026-07-15": { "chatgpt.com": { iban: { warn: 1 } } } }),
    deviceAggregate(["chatgpt.com"], { "2026-07-15": { "chatgpt.com": { iban: { warn: 1 } } } }),
  ];
  // Raw total: iban 2+1+4+1+1=9 (5 distinct devices -> stays "iban"),
  // credit_card 1 (1 device -> suppressed), email 3 (1 device -> suppressed). Grand total 13.
  const merged = mergeAggregates(aggregates);

  const sumOf = (obj) => Object.values(obj).reduce((a, b) => a + b, 0);
  assert.equal(sumOf(merged.totalsByCategory), 13);
  assert.equal(sumOf(merged.totalsByAction), 13);
  assert.equal(merged.totalEvents, 13);
  assert.equal(
    merged.weeklyTrend.reduce((a, w) => a + w.count, 0),
    13,
  );

  assert.equal(merged.totalsByCategory.iban, 9);
  assert.equal(merged.totalsByCategory.other, 4);
  assert.equal(merged.seatCount, 5);
  assert.deepEqual(merged.hosts, ["chatgpt.com", "claude.ai"]);
});

test("renderReport produces a self-contained HTML page with no external resource references", () => {
  const merged = mergeAggregates([deviceAggregate(["chatgpt.com"], {})]);
  const html = renderReport(merged, "2026-07-25");
  assert.match(html, /<!doctype html>/i);
  assert.doesNotMatch(html, /https?:\/\//i);
  assert.doesNotMatch(html, /<script/i);
});
