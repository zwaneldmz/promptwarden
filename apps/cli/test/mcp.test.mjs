import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn as nodeSpawn, spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// Black-box tests: spawn the actual built bin (apps/cli/dist/cli.js) as a
// subprocess — same pattern as scan.test.mjs — pointed at a tiny fake MCP
// server fixture (test/fixtures/fake-mcp-server.mjs, not part of the
// shipped package) so the gateway has something real to proxy to/from.
const cliPath = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const fakeServerPath = fileURLToPath(new URL("./fixtures/fake-mcp-server.mjs", import.meta.url));

const IBAN_SPACED = "AT61 1904 3002 3457 3201"; // mod-97 valid test fixture, reused across the suite
const IBAN_COMPACT = "AT611904300234573201";
const CARD = "4532 0151 1283 0366"; // Luhn-valid Visa test number
const CARD_DIGITS = "4532";

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

async function writePolicy(cwd, overrides) {
  const policyPath = join(cwd, "policy.json");
  await writeFile(
    policyPath,
    JSON.stringify({
      version: 1,
      name: "mcp-test-policy",
      hosts: [],
      defaultAction: "warn",
      logging: "event",
      rules: [],
      ...overrides,
    }),
  );
  return policyPath;
}

function ndjson(messages) {
  return messages.map((m) => JSON.stringify(m)).join("\n") + "\n";
}

function parseNdjson(text) {
  return text
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l));
}

/** Batch mode: write every message up front (spawnSync closes stdin after `input`), collect all output once the child (and its child, the fake server) has exited. */
function runGateway({ cwd, env, messages }) {
  const result = spawnSync(process.execPath, [cliPath, "mcp", "--", process.execPath, fakeServerPath], {
    input: ndjson(messages),
    cwd,
    env,
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

/** Streaming mode, for tests that need to control exactly how bytes are chunked onto stdin. */
function spawnGatewayAsync({ cwd, env }) {
  const child = nodeSpawn(process.execPath, [cliPath, "mcp", "--", process.execPath, fakeServerPath], { cwd, env });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (c) => {
    stdout += c.toString("utf8");
  });
  child.stderr.on("data", (c) => {
    stderr += c.toString("utf8");
  });
  const closed = new Promise((resolve) => child.on("close", (code) => resolve(code)));
  return { child, closed, stdout: () => stdout, stderr: () => stderr };
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function fakeServerReceivedLines(stderr) {
  return stderr
    .split("\n")
    .filter((l) => l.startsWith("FAKE-SERVER-RECEIVED:"))
    .map((l) => l.slice("FAKE-SERVER-RECEIVED:".length));
}

test("mcp: non-tools/call traffic (initialize, tools/list, an unsolicited server notification) passes through byte-identical", async () => {
  const { cwd, env } = await isolatedEnv("pw-mcp-passthrough");
  const initReq = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05" } };
  const listReq = { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} };

  const { status, stdout, stderr } = runGateway({ cwd, env, messages: [initReq, listReq] });
  assert.equal(status, 0);

  // The child forwards the exact same bytes we sent — the fake server's own
  // receipt log must contain each request verbatim.
  const received = fakeServerReceivedLines(stderr);
  assert.ok(received.includes(JSON.stringify(initReq)), "initialize must reach the child unmodified");
  assert.ok(received.includes(JSON.stringify(listReq)), "tools/list must reach the child unmodified");

  const outLines = parseNdjson(stdout);
  // The fake server emits this unsolicited, before reading anything — it
  // must be the very first thing the gateway ever writes to our stdout.
  assert.deepEqual(outLines[0], { jsonrpc: "2.0", method: "notifications/ready" });

  const initRes = outLines.find((m) => m.id === 1);
  assert.equal(initRes.result.serverInfo.name, "fake-mcp-server");
  const listRes = outLines.find((m) => m.id === 2);
  assert.equal(listRes.result.tools.length, 2);
});

test("mcp: a blocked tools/call never reaches the child; a synthesized JSON-RPC error carries no raw match text", async () => {
  const { cwd, env } = await isolatedEnv("pw-mcp-block");
  const policyPath = await writePolicy(cwd, { rules: [{ detector: "credit_card", action: "block" }] });
  const call = {
    jsonrpc: "2.0",
    id: "call-1",
    method: "tools/call",
    params: { name: "echo_tool", arguments: { note: `card on file: ${CARD}` } },
  };

  const { status, stdout, stderr } = runGateway({
    cwd,
    env: { ...env, PROMPTWARDEN_POLICY: policyPath },
    messages: [call],
  });
  assert.equal(status, 0); // the fake server itself still exits cleanly — nothing broke downstream

  // Never reached the child at all.
  const received = fakeServerReceivedLines(stderr);
  assert.ok(!received.some((l) => l.includes(CARD_DIGITS)), "blocked call must never reach the child");
  assert.ok(!received.some((l) => l.includes("call-1")), "blocked call's request must never reach the child");

  const outLines = parseNdjson(stdout);
  const response = outLines.find((m) => m.id === "call-1");
  assert.ok(response, "the client must still get a correlated response for the blocked id");
  assert.ok(response.error, "a blocked call synthesizes a JSON-RPC error, not a result");
  assert.equal(response.error.code, -32001);
  assert.match(response.error.message, /credit_card/);
  assert.match(response.error.message, /block/);

  // No raw card digits anywhere in anything we emitted.
  assert.ok(!stdout.includes(CARD), "stdout must never contain the raw card number");
  assert.ok(!stdout.includes(CARD_DIGITS), "stdout must never contain the raw card digits");
});

test("mcp: a redact-action tools/call arrives at the child with the sensitive value substituted", async () => {
  const { cwd, env } = await isolatedEnv("pw-mcp-redact-outbound");
  const policyPath = await writePolicy(cwd, { rules: [{ detector: "iban", action: "redact" }] });
  const call = {
    jsonrpc: "2.0",
    id: "call-2",
    method: "tools/call",
    params: { name: "echo_tool", arguments: { note: `please wire to ${IBAN_SPACED} today` } },
  };

  const { status, stdout, stderr } = runGateway({
    cwd,
    env: { ...env, PROMPTWARDEN_POLICY: policyPath },
    messages: [call],
  });
  assert.equal(status, 0);

  const received = fakeServerReceivedLines(stderr);
  const forwarded = received.find((l) => l.includes('"call-2"'));
  assert.ok(forwarded, "the (redacted) call must still reach the child");
  assert.ok(forwarded.includes("[REDACTED:IBAN]"), "the child must receive the redacted placeholder");
  assert.ok(!forwarded.includes(IBAN_COMPACT), "the child must never receive the raw IBAN");
  assert.ok(!forwarded.includes("1904"), "the child must never receive an IBAN fragment");

  // The fake server echoes back exactly what it received as the arguments —
  // so the tool result the client sees also carries the redacted form.
  const outLines = parseNdjson(stdout);
  const response = outLines.find((m) => m.id === "call-2");
  assert.equal(response.result.content[0].text, JSON.stringify({ note: `please wire to [REDACTED:IBAN] today` }));
  assert.ok(!stdout.includes(IBAN_COMPACT));
  assert.ok(!stdout.includes("1904"));
});

test("mcp: a tool RESULT carrying an IBAN is blocked — neutralized before it reaches the client", async () => {
  const { cwd, env } = await isolatedEnv("pw-mcp-block-inbound");
  const policyPath = await writePolicy(cwd, { rules: [{ detector: "iban", action: "block" }] });
  const call = {
    jsonrpc: "2.0",
    id: "call-3",
    method: "tools/call",
    // leaky_tool ignores its arguments and always returns a canned IBAN —
    // isolates INBOUND (result) scanning from outbound (argument) scanning.
    params: { name: "leaky_tool", arguments: { note: "nothing sensitive here" } },
  };

  const { status, stdout } = runGateway({
    cwd,
    env: { ...env, PROMPTWARDEN_POLICY: policyPath },
    messages: [call],
  });
  assert.equal(status, 0);

  const outLines = parseNdjson(stdout);
  const response = outLines.find((m) => m.id === "call-3");
  assert.ok(response, "expected a (neutralized) response for call-3");
  assert.equal(response.result.isError, true);
  assert.match(response.result.content[0].text, /iban/i);
  assert.match(response.result.content[0].text, /block/i);

  assert.ok(!stdout.includes(IBAN_COMPACT), "the raw IBAN must never reach the client");
  assert.ok(!stdout.includes("1904"), "no IBAN fragment must reach the client");
});

test("mcp: a tool RESULT carrying an IBAN is redacted when the rule says redact, not block", async () => {
  const { cwd, env } = await isolatedEnv("pw-mcp-redact-inbound");
  const policyPath = await writePolicy(cwd, { rules: [{ detector: "iban", action: "redact" }] });
  const call = {
    jsonrpc: "2.0",
    id: "call-4",
    method: "tools/call",
    params: { name: "leaky_tool", arguments: {} },
  };

  const { status, stdout } = runGateway({
    cwd,
    env: { ...env, PROMPTWARDEN_POLICY: policyPath },
    messages: [call],
  });
  assert.equal(status, 0);

  const outLines = parseNdjson(stdout);
  const response = outLines.find((m) => m.id === "call-4");
  assert.ok(!response.result.isError, "a redact-only result must not be flagged as an error");
  assert.equal(response.result.content[0].text, "Wire funds to [REDACTED:IBAN] today");
  assert.ok(!stdout.includes(IBAN_COMPACT));
  assert.ok(!stdout.includes("1904"));
});

test("mcp: a JSON-RPC message split across two stdin writes reassembles into exactly one line before reaching the child", async () => {
  const { cwd, env } = await isolatedEnv("pw-mcp-framing");
  const { child, closed, stdout, stderr } = spawnGatewayAsync({ cwd, env });

  const message = {
    jsonrpc: "2.0",
    id: "split-1",
    method: "tools/call",
    params: { name: "echo_tool", arguments: { note: "hello framing world" } },
  };
  const line = JSON.stringify(message) + "\n";
  const splitAt = Math.floor(line.length / 2);

  child.stdin.write(line.slice(0, splitAt));
  await delay(50); // give the two writes a real chance to land as separate 'data' events
  child.stdin.write(line.slice(splitAt));
  child.stdin.end();

  const code = await closed;
  assert.equal(code, 0);

  const received = fakeServerReceivedLines(stderr());
  assert.equal(received.length, 1, `expected exactly one reassembled line at the child, got: ${JSON.stringify(received)}`);
  assert.deepEqual(JSON.parse(received[0]), message);

  const outLines = parseNdjson(stdout());
  const response = outLines.find((m) => m.id === "split-1");
  assert.ok(response, "expected a response for the reassembled call");
  assert.equal(response.result.content[0].text, JSON.stringify({ note: "hello framing world" }));
});

test("mcp: --help exits 0 with usage", async () => {
  const { cwd, env } = await isolatedEnv("pw-mcp-help");
  const result = spawnSync(process.execPath, [cliPath, "mcp", "--help"], { cwd, env, encoding: "utf8" });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Usage: promptwarden mcp/);
});

test("mcp: a missing \"--\" separator is a config error, exit 3", async () => {
  const { cwd, env } = await isolatedEnv("pw-mcp-nosep");
  const result = spawnSync(process.execPath, [cliPath, "mcp", "node", "server.js"], { cwd, env, encoding: "utf8" });
  assert.equal(result.status, 3);
  assert.match(result.stderr, /--/);
});

test("mcp: a server command that cannot be spawned is a config error, exit 3", async () => {
  const { cwd, env } = await isolatedEnv("pw-mcp-spawnfail");
  const result = spawnSync(process.execPath, [cliPath, "mcp", "--", "promptwarden-definitely-not-a-real-binary-xyz"], {
    cwd,
    env,
    encoding: "utf8",
  });
  assert.equal(result.status, 3);
  assert.match(result.stderr, /failed to start server/i);
});
