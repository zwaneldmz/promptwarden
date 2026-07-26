import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// Black-box tests: spawn the actual built bin (apps/cli/dist/cli.js) as a
// subprocess with a fully controlled, minimal environment, exactly like
// apps/cli/test/scan.test.mjs — policy discovery reads real env vars and
// walks the real filesystem, so it must never touch the developer's/CI
// runner's real ~/.config, ~/.local/state, or /etc. node:child_process is a
// test-only tool for driving the CLI end-to-end; it is not part of the
// shipped source the no-egress/no-child_process gate scans.
const cliPath = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

// A Luhn-valid Visa test number and a mod-97-valid test IBAN — the same
// fixtures the engine's own test suite and scan.test.mjs use. Never real
// data; safe to commit and to paste into a live canary run.
const CARD = "4532 0151 1283 0366";
const CARD_DIGITS = "4532015112830366";
const IBAN = "AT61 1904 3002 3457 3201";

async function tmpDir(prefix) {
  return mkdtemp(join(tmpdir(), prefix));
}

async function isolatedEnv(prefix) {
  const home = await tmpDir(`${prefix}-home-`);
  const xdgConfigHome = await tmpDir(`${prefix}-xdgcfg-`);
  const xdgStateHome = await tmpDir(`${prefix}-xdgstate-`);
  return {
    xdgStateHome,
    env: {
      PATH: process.env.PATH ?? "",
      HOME: home,
      XDG_CONFIG_HOME: xdgConfigHome,
      XDG_STATE_HOME: xdgStateHome,
    },
  };
}

async function writePolicy(env, overrides) {
  const dir = await tmpDir("pw-hooks-policy-");
  const policyPath = join(dir, "policy.json");
  await writeFile(
    policyPath,
    JSON.stringify({
      version: 1,
      name: "hooks-test-policy",
      hosts: [],
      defaultAction: "allow",
      logging: "event",
      rules: [],
      ...overrides,
    }),
  );
  return { ...env, PROMPTWARDEN_POLICY: policyPath };
}

function runHook(envelope, { env, extraArgs = [] } = {}) {
  const input = envelope === undefined ? "" : JSON.stringify(envelope);
  const result = spawnSync(process.execPath, [cliPath, "hook", "claude-code", ...extraArgs], {
    input,
    env,
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function assertNoLeak(text, label) {
  for (const fragment of [CARD, CARD_DIGITS, "0151", "1283", "0366", IBAN, "1904", "3002", "3457", "3201"]) {
    assert.ok(!text.includes(fragment), `${label} leaked "${fragment}": ${text}`);
  }
}

async function readEvents(xdgStateHome) {
  const eventsPath = join(xdgStateHome, "promptwarden", "events.jsonl");
  try {
    const raw = await readFile(eventsPath, "utf8");
    return raw
      .split("\n")
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

/* ------------------------------ malformed stdin ------------------------------ */

test("hook: closed/empty stdin exits 0 with no stdout", async () => {
  const { env } = await isolatedEnv("pw-hook-empty");
  const { status, stdout, stderr } = runHook(undefined, { env });
  assert.equal(status, 0);
  assert.equal(stdout, "");
  assertNoLeak(stderr, "stderr");
});

test("hook: malformed JSON on stdin exits 0 with no stdout, never crashes", async () => {
  const { env } = await isolatedEnv("pw-hook-malformed");
  const result = spawnSync(process.execPath, [cliPath, "hook", "claude-code"], {
    input: "this is not json {{{",
    env,
    encoding: "utf8",
  });
  assert.equal(result.status, 0);
  assert.equal(result.stdout, "");
});

test("hook: an envelope with an unrecognized hook_event_name exits 0 with no stdout (fail open)", async () => {
  const { env } = await isolatedEnv("pw-hook-unknown-event");
  const { status, stdout } = runHook({ hook_event_name: "Notification" }, { env });
  assert.equal(status, 0);
  assert.equal(stdout, "");
});

/* ------------------------------ UserPromptSubmit ------------------------------ */

test("UserPromptSubmit: clean prompt exits 0 with no stdout", async () => {
  const { env } = await isolatedEnv("pw-hook-ups-clean");
  const { status, stdout } = runHook(
    { hook_event_name: "UserPromptSubmit", prompt: "write me a haiku about the ocean" },
    { env },
  );
  assert.equal(status, 0);
  assert.equal(stdout, "");
});

test("UserPromptSubmit: warn-level finding defaults to BLOCK, since this event cannot redact", async () => {
  const base = await isolatedEnv("pw-hook-ups-warn-block");
  const env = await writePolicy(base.env, { rules: [{ detector: "credit_card", action: "warn" }] });
  const { status, stdout } = runHook({ hook_event_name: "UserPromptSubmit", prompt: `card on file: ${CARD}` }, { env });
  assert.equal(status, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.decision, "block");
  assert.match(out.reason, /warn: credit_card/);
  assert.match(out.reason, /cannot redact/i);
  assertNoLeak(stdout, "UserPromptSubmit warn->block stdout");

  const events = await readEvents(base.xdgStateHome);
  assert.equal(events.length, 1);
  assert.equal(events[0].host, "claude-code:UserPromptSubmit");
  assert.deepEqual(events[0].actions, ["warn"]);
});

test("UserPromptSubmit: redact-level finding also degrades to BLOCK by default (no updatedPrompt channel exists)", async () => {
  const base = await isolatedEnv("pw-hook-ups-redact-block");
  const env = await writePolicy(base.env, { rules: [{ detector: "credit_card", action: "redact" }] });
  const { status, stdout } = runHook({ hook_event_name: "UserPromptSubmit", prompt: `card: ${CARD}` }, { env });
  assert.equal(status, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.decision, "block");
  assert.match(out.reason, /redact: credit_card/);
  assertNoLeak(stdout, "UserPromptSubmit redact->block stdout");
});

test("UserPromptSubmit: PROMPTWARDEN_HOOK_ALLOW_WARN=1 downgrades warn to allow-with-warning", async () => {
  const base = await isolatedEnv("pw-hook-ups-warn-downgrade");
  const env = await writePolicy(base.env, { rules: [{ detector: "credit_card", action: "warn" }] });
  const { status, stdout } = runHook(
    { hook_event_name: "UserPromptSubmit", prompt: `card on file: ${CARD}` },
    { env: { ...env, PROMPTWARDEN_HOOK_ALLOW_WARN: "1" } },
  );
  assert.equal(status, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.decision, undefined, "must not block once downgraded");
  assert.match(out.systemMessage, /warn: credit_card/);
  assert.equal(out.hookSpecificOutput.hookEventName, "UserPromptSubmit");
  assert.match(out.hookSpecificOutput.additionalContext, /warn: credit_card/);
  assertNoLeak(stdout, "UserPromptSubmit allow-warn stdout");
});

test("UserPromptSubmit: --allow-warn flag has the same effect as the env var", async () => {
  const base = await isolatedEnv("pw-hook-ups-warn-flag");
  const env = await writePolicy(base.env, { rules: [{ detector: "credit_card", action: "warn" }] });
  const { status, stdout } = runHook(
    { hook_event_name: "UserPromptSubmit", prompt: `card on file: ${CARD}` },
    { env, extraArgs: ["--allow-warn"] },
  );
  assert.equal(status, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.decision, undefined);
  assert.ok(out.systemMessage);
});

test("UserPromptSubmit: block-level finding blocks even when PROMPTWARDEN_HOOK_ALLOW_WARN=1 is set", async () => {
  const base = await isolatedEnv("pw-hook-ups-block-not-downgradable");
  const env = await writePolicy(base.env, { rules: [{ detector: "credit_card", action: "block" }] });
  const { status, stdout } = runHook(
    { hook_event_name: "UserPromptSubmit", prompt: `card on file: ${CARD}` },
    { env: { ...env, PROMPTWARDEN_HOOK_ALLOW_WARN: "1" } },
  );
  assert.equal(status, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.decision, "block");
  assert.match(out.reason, /block: credit_card/);
  assertNoLeak(stdout, "UserPromptSubmit block (allow-warn set) stdout");
});

test("UserPromptSubmit: observe-level finding records the event and allows silently", async () => {
  const base = await isolatedEnv("pw-hook-ups-observe");
  const env = await writePolicy(base.env, { rules: [{ detector: "credit_card", action: "observe" }] });
  const { status, stdout } = runHook({ hook_event_name: "UserPromptSubmit", prompt: `card on file: ${CARD}` }, { env });
  assert.equal(status, 0);
  assert.equal(stdout, "");

  const events = await readEvents(base.xdgStateHome);
  assert.equal(events.length, 1);
  assert.equal(events[0].host, "claude-code:UserPromptSubmit");
  assert.deepEqual(events[0].actions, ["observe"]);
});

/* ---------------------------------- PreToolUse --------------------------------- */

test("PreToolUse: clean tool_input exits 0 with no stdout", async () => {
  const { env } = await isolatedEnv("pw-hook-ptu-clean");
  const { status, stdout } = runHook(
    { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "npm test" } },
    { env },
  );
  assert.equal(status, 0);
  assert.equal(stdout, "");
});

test("PreToolUse: warn-level finding allows the call and records it, with no updatedInput", async () => {
  const base = await isolatedEnv("pw-hook-ptu-warn");
  const env = await writePolicy(base.env, { rules: [{ detector: "iban", action: "warn" }] });
  const { status, stdout } = runHook(
    { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `wire to ${IBAN}` } },
    { env },
  );
  assert.equal(status, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(out.hookSpecificOutput.permissionDecision, "allow");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /warn: iban/);
  assert.equal(out.hookSpecificOutput.updatedInput, undefined);
  assertNoLeak(stdout, "PreToolUse warn stdout");

  const events = await readEvents(base.xdgStateHome);
  assert.equal(events.length, 1);
  assert.equal(events[0].host, "claude-code:PreToolUse");
});

test("PreToolUse: block-level finding denies the call before any permission check", async () => {
  const base = await isolatedEnv("pw-hook-ptu-block");
  const env = await writePolicy(base.env, { rules: [{ detector: "credit_card", action: "block" }] });
  const { status, stdout } = runHook(
    { hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: "notes.txt", content: `card: ${CARD}` } },
    { env },
  );
  assert.equal(status, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /block: credit_card/);
  assertNoLeak(stdout, "PreToolUse block stdout");
});

test("PreToolUse: redact-level finding rewrites the offending field via updatedInput and allows", async () => {
  const base = await isolatedEnv("pw-hook-ptu-redact");
  const env = await writePolicy(base.env, { rules: [{ detector: "credit_card", action: "redact" }] });
  const { status, stdout } = runHook(
    {
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: `echo card=${CARD_DIGITS}`, description: "print the card" },
    },
    { env },
  );
  assert.equal(status, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "allow");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /redact: credit_card/);
  assert.match(out.hookSpecificOutput.updatedInput.command, /\[REDACTED:CARD\]/);
  // updatedInput REPLACES the tool's arguments, so untouched siblings must
  // still be present — dropping them would break the call (a Write would
  // lose its file_path).
  assert.equal(out.hookSpecificOutput.updatedInput.description, "print the card");
  assertNoLeak(stdout, "PreToolUse redact stdout");
});

test("PreToolUse: redact reaches an unlisted tool's arbitrarily nested field, not just top-level known fields", async () => {
  const base = await isolatedEnv("pw-hook-ptu-nested");
  const env = await writePolicy(base.env, { rules: [{ detector: "credit_card", action: "redact" }] });
  const { status, stdout } = runHook(
    {
      hook_event_name: "PreToolUse",
      tool_name: "mcp__some_plugin_server__do_thing", // a tool name never hardcoded anywhere in the hook
      tool_input: {
        payload: {
          nested: { secret: `card on file: ${CARD}` },
          untouched: "this field has nothing sensitive in it",
        },
      },
    },
    { env },
  );
  assert.equal(status, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "allow");
  const rewritten = out.hookSpecificOutput.updatedInput.payload;
  assert.match(rewritten.nested.secret, /\[REDACTED:CARD\]/);
  // The full top-level key ("payload") comes back with the sibling field
  // preserved verbatim, since the merge Claude Code performs is shallow at
  // the top level of tool_input.
  assert.equal(rewritten.untouched, "this field has nothing sensitive in it");
  assertNoLeak(stdout, "PreToolUse nested redact stdout");
});

test("PreToolUse: observe-level finding records the event and allows silently, no stdout", async () => {
  const base = await isolatedEnv("pw-hook-ptu-observe");
  const env = await writePolicy(base.env, { rules: [{ detector: "credit_card", action: "observe" }] });
  const { status, stdout } = runHook(
    { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `echo ${CARD_DIGITS}` } },
    { env },
  );
  assert.equal(status, 0);
  assert.equal(stdout, "");

  const events = await readEvents(base.xdgStateHome);
  assert.equal(events.length, 1);
  assert.deepEqual(events[0].actions, ["observe"]);
});

test("PreToolUse: a non-object tool_input (malformed envelope) fails open rather than crashing", async () => {
  const { env } = await isolatedEnv("pw-hook-ptu-malformed-input");
  const { status, stdout } = runHook(
    { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: "not an object" },
    { env },
  );
  assert.equal(status, 0);
  assert.equal(stdout, "");
});

/* --------------------------- surface labels & privacy gate --------------------------- */

test("both events record under the documented claude-code:<EventName> surface labels", async () => {
  const base = await isolatedEnv("pw-hook-surfaces");
  const env = await writePolicy(base.env, { rules: [{ detector: "credit_card", action: "warn" }] });

  runHook({ hook_event_name: "UserPromptSubmit", prompt: `card: ${CARD}` }, { env });
  runHook({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `echo ${CARD_DIGITS}` } }, { env });

  const events = await readEvents(base.xdgStateHome);
  const hosts = events.map((e) => e.host).sort();
  assert.deepEqual(hosts, ["claude-code:PreToolUse", "claude-code:UserPromptSubmit"]);
});

test("no matched literal ever reaches stdout across every non-clean outcome, for either event", async () => {
  const base = await isolatedEnv("pw-hook-noleak-sweep");
  // Each scenario's payload deliberately contains ONLY the fixture its own
  // rule targets. Mixing an unrelated, allow-by-default category into the
  // same payload would be a test bug, not a hook bug: on a `redact`
  // decision, `updatedInput` is a legitimate pass-through for any field (or
  // sub-value) that was never itself a finding — an allowed IBAN sitting
  // next to a redacted card is expected to survive untouched in
  // `updatedInput`, exactly as it would with no hook installed at all.
  const scenarios = [
    { policy: { rules: [{ detector: "credit_card", action: "warn" }] }, text: `data: ${CARD}` },
    { policy: { rules: [{ detector: "credit_card", action: "redact" }] }, text: `data: ${CARD}` },
    { policy: { rules: [{ detector: "credit_card", action: "block" }] }, text: `data: ${CARD}` },
    { policy: { rules: [{ detector: "iban", action: "warn" }] }, text: `data: ${IBAN}` },
  ];

  for (const scenario of scenarios) {
    const env = await writePolicy(base.env, scenario.policy);
    const upsResult = runHook({ hook_event_name: "UserPromptSubmit", prompt: scenario.text }, { env });
    assertNoLeak(upsResult.stdout, `UserPromptSubmit stdout (${JSON.stringify(scenario.policy)})`);
    assertNoLeak(upsResult.stderr, `UserPromptSubmit stderr (${JSON.stringify(scenario.policy)})`);

    const ptuResult = runHook(
      { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `echo ${scenario.text}` } },
      { env },
    );
    assertNoLeak(ptuResult.stdout, `PreToolUse stdout (${JSON.stringify(scenario.policy)})`);
    assertNoLeak(ptuResult.stderr, `PreToolUse stderr (${JSON.stringify(scenario.policy)})`);
  }
});
