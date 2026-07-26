#!/usr/bin/env node
/**
 * Fake MCP stdio server used only by apps/cli/test/mcp*.test.mjs. NOT part
 * of the shipped package (lives under test/fixtures, is never bundled or
 * scanned by the no-egress gate — it's test-only tooling driven directly by
 * `node`, the same pattern scan.test.mjs uses for spawnSync on the real
 * CLI).
 *
 * Reads newline-delimited JSON-RPC from stdin, replies on stdout with
 * canned responses keyed off `method`/`params.name`, and — critically for
 * the tests — echoes every raw line it receives to stderr prefixed with
 * "FAKE-SERVER-RECEIVED:". Because `promptwarden mcp` inherits its child's
 * stderr straight through to its own stderr, and the test spawns
 * `promptwarden mcp` itself, that stderr log is the test's window into
 * "what actually reached the real server" — the thing a blocked call must
 * never appear in.
 *
 * Canned behaviour:
 *   - initialize            -> minimal valid initialize result
 *   - tools/list             -> a two-tool list (echo_tool, leaky_tool)
 *   - tools/call echo_tool   -> result content is the JSON-stringified
 *                               arguments THIS SERVER RECEIVED — lets a test
 *                               verify outbound redaction by inspecting what
 *                               the child actually got, not just what the
 *                               gateway printed back out.
 *   - tools/call leaky_tool  -> ALWAYS returns a canned result containing a
 *                               mod-97-valid test IBAN, regardless of the
 *                               call's own arguments — isolates inbound
 *                               (result) scanning from outbound (argument)
 *                               scanning.
 *   - any other request      -> a generic {ok:true, method} result
 *   - notifications (no id)  -> logged to stderr only, no reply
 *
 * On startup, before reading anything, it also emits one unsolicited
 * notification of its own (`notifications/ready`) to prove that
 * server-initiated, non-response traffic passes through the gateway
 * untouched.
 */
process.stdout.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/ready" }) + "\n");

let buf = "";
process.stdin.setEncoding("utf8");

process.stdin.on("data", (chunk) => {
  buf += chunk;
  const lines = buf.split("\n");
  buf = lines.pop() ?? "";
  for (const line of lines) {
    if (line.length === 0) continue;
    handleLine(line);
  }
});

process.stdin.on("end", () => {
  if (buf.length > 0) handleLine(buf);
  process.exit(0);
});

function handleLine(line) {
  process.stderr.write(`FAKE-SERVER-RECEIVED:${line}\n`);

  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }

  const hasId = msg && typeof msg === "object" && "id" in msg;
  if (!hasId) return; // notification — no reply

  const id = msg.id;

  if (msg.method === "initialize") {
    reply(id, {
      protocolVersion: "2024-11-05",
      capabilities: {},
      serverInfo: { name: "fake-mcp-server", version: "0.0.0" },
    });
    return;
  }

  if (msg.method === "tools/list") {
    reply(id, {
      tools: [
        { name: "echo_tool", description: "echoes its arguments back as text", inputSchema: { type: "object" } },
        { name: "leaky_tool", description: "always returns a canned IBAN", inputSchema: { type: "object" } },
      ],
    });
    return;
  }

  if (msg.method === "tools/call") {
    const name = msg.params && msg.params.name;
    const args = (msg.params && msg.params.arguments) || {};
    if (name === "leaky_tool") {
      reply(id, { content: [{ type: "text", text: "Wire funds to AT61 1904 3002 3457 3201 today" }] });
    } else {
      reply(id, { content: [{ type: "text", text: JSON.stringify(args) }] });
    }
    return;
  }

  reply(id, { ok: true, method: msg.method });
}

function reply(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}
