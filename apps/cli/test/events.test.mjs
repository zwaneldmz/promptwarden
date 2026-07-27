import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { recordEvent } from "../dist/events.js";

async function tmpDir(prefix) {
  return mkdtemp(join(tmpdir(), prefix));
}

function policy(overrides = {}) {
  return {
    version: 1,
    name: "events-test",
    hosts: [],
    defaultAction: "allow",
    logging: "event",
    rules: [],
    ...overrides,
  };
}

function findingResult(overrides = {}) {
  const finding = {
    detector: "credit_card",
    action: "warn",
    start: 0,
    end: 4,
    match: "1234",
    label: "[REDACTED:CARD]",
    ...overrides,
  };
  return { findings: [finding], redactedText: "", blocked: false, needsWarning: true };
}

async function withStateHome(prefix, fn) {
  const stateHome = await tmpDir(prefix);
  const saved = process.env.XDG_STATE_HOME;
  process.env.XDG_STATE_HOME = stateHome;
  try {
    return await fn(stateHome);
  } finally {
    if (saved === undefined) delete process.env.XDG_STATE_HOME;
    else process.env.XDG_STATE_HOME = saved;
  }
}

function eventsPath(stateHome) {
  return join(stateHome, "wardkeep", "events.jsonl");
}

test("recordEvent appends one JSONL line, file mode 0600, creating dirs as needed", async () => {
  await withStateHome("pw-events-basic-", async (stateHome) => {
    await recordEvent(findingResult(), policy(), "cli:test");
    const filePath = eventsPath(stateHome);
    const raw = await readFile(filePath, "utf8");
    const lines = raw.split("\n").filter((l) => l.length > 0);
    assert.equal(lines.length, 1);
    const record = JSON.parse(lines[0]);
    assert.equal(record.host, "cli:test");
    assert.equal(record.policy, "events-test");
    assert.deepEqual(record.categories, ["credit_card"]);
    assert.deepEqual(record.actions, ["warn"]);

    const st = await stat(filePath);
    assert.equal((st.mode & 0o777).toString(8), "600");
  });
});

test("recordEvent is a no-op when logging is off", async () => {
  await withStateHome("pw-events-off-", async (stateHome) => {
    await recordEvent(findingResult(), policy({ logging: "off" }), "cli:test");
    await assert.rejects(() => readFile(eventsPath(stateHome), "utf8"));
  });
});

test("recordEvent is a no-op when there are no findings", async () => {
  await withStateHome("pw-events-empty-", async (stateHome) => {
    const clean = { findings: [], redactedText: "", blocked: false, needsWarning: false };
    await recordEvent(clean, policy(), "cli:test");
    await assert.rejects(() => readFile(eventsPath(stateHome), "utf8"));
  });
});

test("recordEvent never throws even when the state directory cannot be created", async () => {
  const blocker = await tmpDir("pw-events-blocker-");
  const blockerFile = join(blocker, "im-a-file-not-a-dir");
  await writeFile(blockerFile, "x");
  const saved = process.env.XDG_STATE_HOME;
  // A regular file sits where a directory needs to be created underneath it.
  process.env.XDG_STATE_HOME = blockerFile;
  try {
    await assert.doesNotReject(() => recordEvent(findingResult(), policy(), "cli:test"));
  } finally {
    if (saved === undefined) delete process.env.XDG_STATE_HOME;
    else process.env.XDG_STATE_HOME = saved;
  }
});

test("cap: appending past 500 records drops the oldest and keeps exactly 500", async () => {
  await withStateHome("pw-events-cap-", async (stateHome) => {
    const filePath = eventsPath(stateHome);
    await mkdir(join(stateHome, "wardkeep"), { recursive: true });
    const now = new Date().toISOString();
    const seeded = Array.from({ length: 500 }, (_, i) =>
      JSON.stringify({ ts: now, host: "seed", policy: `seed-${i}`, categories: ["credit_card"], actions: ["warn"] }),
    ).join("\n") + "\n";
    await writeFile(filePath, seeded, { mode: 0o600 });

    await recordEvent(findingResult(), policy({ name: "the-501st" }), "cli:test");

    const raw = await readFile(filePath, "utf8");
    const lines = raw.split("\n").filter((l) => l.length > 0);
    assert.equal(lines.length, 500);
    const parsed = lines.map((l) => JSON.parse(l));
    assert.ok(!parsed.some((r) => r.policy === "seed-0"), "oldest seeded entry must be pruned");
    assert.equal(parsed[0].policy, "seed-1", "the new oldest surviving entry should be seed-1");
    assert.equal(parsed[parsed.length - 1].policy, "the-501st", "the just-appended entry must survive, last");
  });
});

test("age pruning: an entry older than retentionDays is dropped, a recent one is kept", async () => {
  await withStateHome("pw-events-age-", async (stateHome) => {
    const filePath = eventsPath(stateHome);
    await mkdir(join(stateHome, "wardkeep"), { recursive: true });
    const dayMs = 24 * 60 * 60 * 1000;
    const old = new Date(Date.now() - 200 * dayMs).toISOString(); // older than the 90-day default
    const recent = new Date(Date.now() - 1 * dayMs).toISOString();
    const seeded =
      [
        JSON.stringify({ ts: old, host: "seed", policy: "too-old", categories: ["email"], actions: ["warn"] }),
        JSON.stringify({ ts: recent, host: "seed", policy: "still-fresh", categories: ["email"], actions: ["warn"] }),
      ].join("\n") + "\n";
    await writeFile(filePath, seeded, { mode: 0o600 });

    // No retentionDays set -> falls back to the documented default of 90.
    await recordEvent(findingResult(), policy(), "cli:test");

    const raw = await readFile(filePath, "utf8");
    const parsed = raw
      .split("\n")
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l));
    assert.ok(!parsed.some((r) => r.policy === "too-old"));
    assert.ok(parsed.some((r) => r.policy === "still-fresh"));
  });
});

test("policy.retentionDays overrides the default 90-day window", async () => {
  await withStateHome("pw-events-retention-override-", async (stateHome) => {
    const filePath = eventsPath(stateHome);
    await mkdir(join(stateHome, "wardkeep"), { recursive: true });
    const dayMs = 24 * 60 * 60 * 1000;
    const tenDaysAgo = new Date(Date.now() - 10 * dayMs).toISOString();
    const seeded =
      JSON.stringify({ ts: tenDaysAgo, host: "seed", policy: "ten-days-old", categories: ["email"], actions: ["warn"] }) +
      "\n";
    await writeFile(filePath, seeded, { mode: 0o600 });

    // retentionDays: 5 means the 10-day-old seeded entry must be pruned even
    // though it's well within the *default* 90-day window.
    await recordEvent(findingResult(), policy({ retentionDays: 5 }), "cli:test");

    const raw = await readFile(filePath, "utf8");
    const parsed = raw
      .split("\n")
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l));
    assert.ok(!parsed.some((r) => r.policy === "ten-days-old"));
  });
});
