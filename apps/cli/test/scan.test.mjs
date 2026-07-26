import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// Black-box tests: spawn the actual built bin (apps/cli/dist/cli.js) as a
// subprocess with a fully controlled, minimal environment, so policy
// discovery (which reads real env vars and walks the real filesystem) is
// deterministic and never touches the developer's/CI runner's real
// ~/.config, ~/.local/state, or /etc. Using node:child_process here is a
// test-only tool for driving the CLI end-to-end — it is not part of the
// shipped source the no-egress/no-child_process gate scans.
const cliPath = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

async function tmpDir(prefix) {
  return mkdtemp(join(tmpdir(), prefix));
}

async function isolatedEnv(prefix) {
  const home = await tmpDir(`${prefix}-home-`);
  const xdgConfigHome = await tmpDir(`${prefix}-xdgcfg-`);
  const xdgStateHome = await tmpDir(`${prefix}-xdgstate-`);
  const cwd = await tmpDir(`${prefix}-cwd-`);
  return {
    cwd,
    env: {
      PATH: process.env.PATH ?? "",
      HOME: home,
      XDG_CONFIG_HOME: xdgConfigHome,
      XDG_STATE_HOME: xdgStateHome,
    },
  };
}

function runCli(args, { input, cwd, env }) {
  const result = spawnSync(process.execPath, [cliPath, ...args], {
    input: input ?? "",
    cwd,
    env,
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

test("scan: clean stdin exits 0 and says clean", async () => {
  const { cwd, env } = await isolatedEnv("pw-scan-clean");
  const { status, stdout } = runCli(["scan", "--stdin"], { input: "just some ordinary text\n", cwd, env });
  assert.equal(status, 0);
  assert.match(stdout, /clean/i);
});

test("scan: warn without --strict exits 0; the same input with --strict exits 2", async () => {
  const { cwd, env } = await isolatedEnv("pw-scan-warn");
  const cardText = "card on file: 4532 0151 1283 0366\n"; // Luhn-valid Visa test number
  const lenient = runCli(["scan", "--stdin"], { input: cardText, cwd, env });
  assert.equal(lenient.status, 0);
  assert.match(lenient.stdout, /warn/i);

  const strict = runCli(["scan", "--stdin", "--strict"], { input: cardText, cwd, env });
  assert.equal(strict.status, 2);
  assert.match(strict.stdout, /warn/i);
});

test("scan: blocked input exits 1, under a policy that blocks credit_card", async () => {
  const { cwd, env } = await isolatedEnv("pw-scan-block");
  const policyPath = join(cwd, "block-policy.json");
  await writeFile(
    policyPath,
    JSON.stringify({
      version: 1,
      name: "blocks-cards",
      hosts: [],
      defaultAction: "warn",
      logging: "event",
      rules: [{ detector: "credit_card", action: "block" }],
    }),
  );
  const { status, stdout } = runCli(["scan", "--stdin"], {
    input: "card on file: 4532 0151 1283 0366\n",
    cwd,
    env: { ...env, PROMPTWARDEN_POLICY: policyPath },
  });
  assert.equal(status, 1);
  assert.match(stdout, /block/i);
});

test("scan: no --stdin and no --file is a config error, exit 3", async () => {
  const { cwd, env } = await isolatedEnv("pw-scan-noinput");
  const { status, stderr } = runCli(["scan"], { cwd, env });
  assert.equal(status, 3);
  assert.match(stderr, /no input/i);
});

test("scan: --file scans a plain text file the same way --stdin would", async () => {
  const { cwd, env } = await isolatedEnv("pw-scan-file");
  const filePath = join(cwd, "prompt.txt");
  await writeFile(filePath, "card on file: 4532 0151 1283 0366\n");
  const { status, stdout } = runCli(["scan", "--file", filePath], { cwd, env });
  assert.equal(status, 0);
  assert.match(stdout, /warn/i);
});

test("scan: --file with a nonexistent path is a config error, exit 3", async () => {
  const { cwd, env } = await isolatedEnv("pw-scan-missing-file");
  const { status, stderr } = runCli(["scan", "--file", join(cwd, "nope.txt")], { cwd, env });
  assert.equal(status, 3);
  assert.match(stderr, /could not read/i);
});

test("scan: --json prints structured output with no raw match values", async () => {
  const { cwd, env } = await isolatedEnv("pw-scan-json");
  const { status, stdout } = runCli(["scan", "--stdin", "--json"], {
    input: "card on file: 4532 0151 1283 0366\n",
    cwd,
    env,
  });
  assert.equal(status, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.blocked, false);
  assert.equal(out.needsWarning, true);
  assert.ok(Array.isArray(out.findings));
  assert.equal(out.findings.length, 1);
  assert.deepEqual(Object.keys(out.findings[0]).sort(), ["action", "detector", "source"]);
  assert.equal(out.findings[0].detector, "credit_card");
  // The raw card digits must not appear anywhere in the JSON text.
  assert.ok(!stdout.includes("4532"));
});

test("scan: --surface labels the recorded event", async () => {
  const { cwd, env } = await isolatedEnv("pw-scan-surface");
  const policyPath = join(cwd, "logging-policy.json");
  await writeFile(
    policyPath,
    JSON.stringify({
      version: 1,
      name: "logs-events",
      hosts: [],
      defaultAction: "warn",
      logging: "event",
      rules: [],
    }),
  );
  const { status } = runCli(["scan", "--stdin", "--surface", "cli:custom-surface"], {
    input: "card on file: 4532 0151 1283 0366\n",
    cwd,
    env: { ...env, PROMPTWARDEN_POLICY: policyPath },
  });
  assert.equal(status, 0);

  const eventsPath = join(env.XDG_STATE_HOME, "promptwarden", "events.jsonl");
  const { readFile } = await import("node:fs/promises");
  const raw = await readFile(eventsPath, "utf8");
  const record = JSON.parse(raw.trim());
  assert.equal(record.host, "cli:custom-surface");
});

test("scan: no matched literal ever reaches stdout, human or --json, even under --strict", async () => {
  const { cwd, env } = await isolatedEnv("pw-scan-noleak");
  // A distinctive, mod-97-valid test IBAN (the same fixture used in the
  // engine's own test suite) — the built-in default's iban rule is "warn".
  const spaced = "AT61 1904 3002 3457 3201";
  const compact = "AT611904300234573201";
  const input = `please wire funds to ${spaced} before Friday\n`;
  const distinctiveFragments = ["1904", "3002", "3457", "3201", spaced, compact, "300234573201"];

  const human = runCli(["scan", "--stdin", "--strict"], { input, cwd, env });
  assert.equal(human.status, 2);
  assert.match(human.stdout, /iban/i);
  for (const fragment of distinctiveFragments) {
    assert.ok(!human.stdout.includes(fragment), `human stdout leaked "${fragment}"`);
    assert.ok(!human.stderr.includes(fragment), `human stderr leaked "${fragment}"`);
  }

  const json = runCli(["scan", "--stdin", "--strict", "--json"], { input, cwd, env });
  assert.equal(json.status, 2);
  const out = JSON.parse(json.stdout);
  assert.equal(out.findings.some((f) => f.detector === "iban"), true);
  for (const fragment of distinctiveFragments) {
    assert.ok(!json.stdout.includes(fragment), `--json stdout leaked "${fragment}"`);
    assert.ok(!json.stderr.includes(fragment), `--json stderr leaked "${fragment}"`);
  }
});

test("scan: --help and unknown-flag both exit 3 with usage on stderr", async () => {
  const { cwd, env } = await isolatedEnv("pw-scan-usage");
  const help = runCli(["scan", "--help"], { cwd, env });
  assert.equal(help.status, 3);
  assert.match(help.stderr, /Usage: promptwarden scan/);

  const unknown = runCli(["scan", "--nonsense"], { cwd, env });
  assert.equal(unknown.status, 3);
  assert.match(unknown.stderr, /unknown argument/i);
});
