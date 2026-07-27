/**
 * MCP stdio gateway (`wardkeep mcp -- <real server command> [args...]`).
 *
 * Per docs/ROADMAP.md §2's interception-mechanism table, this is the best
 * adapter after the CLI's own `scan`/`hook` front doors: it reaches Claude
 * Desktop, Claude Code, Cursor, VS Code, Windsurf and JetBrains through one
 * config-file edit (point the client at `wardkeep mcp -- <old command>`
 * instead of `<old command>` directly), and it is the *only* mechanism in
 * this repo that sees tool RESULTS as well as tool arguments — the inbound
 * direction nothing else covers, and precisely what `bulk_pii` exists for.
 *
 *   MCP client (Claude Desktop, ...)          Real MCP server (child)
 *   ────────────────────────────              ────────────────────────
 *         |  stdout  ---> stdin  |            |  stdin  <--- stdout  |
 *         |         (our stdin)  |  gateway   |  (child.stdin)       |
 *         |  <---  stdin  stdout |  (this     |  ---> stdout  <---   |
 *         |       (our stdout)   |   process) |  (child.stdout)      |
 *
 * From the client's point of view we ARE the server (it talks to our
 * stdin/stdout); from the real server's point of view we ARE the client (we
 * talk to its stdin/stdout). Every message is scanned exactly once, in the
 * direction it's travelling:
 *
 *   - OUTBOUND (client -> server, i.e. our stdin -> child.stdin): only
 *     `tools/call` requests are inspected, and only their
 *     `params.arguments` string values (recursively — an argument can be a
 *     nested object/array). `block` -> the call never reaches the child; we
 *     synthesize a JSON-RPC error response (toUserMessage only — see below)
 *     using the request's own `id` and write it directly to our stdout.
 *     `redact` -> the offending string values are replaced with their
 *     redacted form and the (now-safe) request is forwarded. `warn`/
 *     `observe`/clean -> forwarded byte-identical.
 *   - INBOUND (server -> client, i.e. child.stdout -> our stdout): only
 *     responses whose `id` we recognise as a forwarded `tools/call` are
 *     inspected, and only `result.content[].text` items (the MCP tool-result
 *     text-content shape). `block` -> the whole `content` array is replaced
 *     with a single toUserMessage-only notice and `isError: true` is set, so
 *     a model reading this back cannot mistake it for real data. `redact` ->
 *     individual `text` items are substituted. `warn`/`observe`/clean ->
 *     forwarded byte-identical. Non-text content items (images, embedded
 *     resources) are never scanned — see docs/MCP_GATEWAY.md.
 *   - Everything else — `initialize`, `tools/list`, `resources/*`,
 *     notifications in either direction, and any response we have no
 *     pending `tools/call` id for — is forwarded byte-identical, unparsed
 *     beyond the JSON.parse needed to recognise it isn't one of the two
 *     cases above. This is what keeps the gateway transparent.
 *
 * Framing: MCP stdio transport is newline-delimited JSON — exactly one JSON
 * value per line, UTF-8. `LineFramer` buffers partial chunks at the byte
 * level (never decoding a line until a full `\n` has been seen) so a message
 * split across two `data` events — including mid-multibyte-character splits
 * — is never corrupted or forwarded early.
 *
 * child_process carve-out: this file owns the ONE reviewed
 * `child_process.spawn` call in this package (see .github/workflows/ci.yml's
 * no-egress gate, which excludes exactly this file from the
 * child_process/execSync/spawnSync/createRequire pattern while still
 * applying every network pattern to it). No shell is ever invoked — argv is
 * passed straight through with `shell` left at its default `false` — and the
 * child's own stderr is inherited so its diagnostics reach whoever is
 * running `wardkeep mcp`.
 *
 * Only HTTP/SSE-transport MCP servers are out of scope (stdio only); see
 * docs/MCP_GATEWAY.md.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { EvaluationResult, Finding, Policy, evaluate, toUserMessage } from "@wardkeep/policy-engine";
import { recordEvent } from "../events.js";
import { loadPolicy } from "../policy.js";

const USAGE = `Usage: wardkeep mcp -- <server command> [args...]

  Spawns <server command> as the real MCP server (stdio transport) and
  proxies newline-delimited JSON-RPC between this process's own
  stdin/stdout and the child, scanning tools/call arguments (outbound) and
  tool results (inbound) against the resolved policy. Everything else
  (initialize, tools/list, notifications, ...) passes through unchanged.

  --help, -h    Print this message.

Point an MCP client's server config at "wardkeep mcp -- <old command>"
instead of "<old command>" directly. See docs/MCP_GATEWAY.md.

Exit code: the spawned server's own exit code, or 3 if the server could not
be started, argv was malformed, or the policy could not be resolved.
`;

/** JSON-RPC 2.0 reserved-for-implementation server-error range (-32000..-32099). */
const POLICY_BLOCK_ERROR_CODE = -32001;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Deep-clone a JSON-safe value without a runtime dependency. Safe here because every value we clone originated from JSON.parse. */
function jsonClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

// ---------------------------------------------------------------------------
// Line framing: buffer raw bytes, emit only complete lines. Byte 0x0A (LF)
// never appears as part of a multi-byte UTF-8 continuation/lead byte (those
// are always >= 0x80), so scanning for it at the byte level before decoding
// is safe even when a multi-byte character straddles two `data` events.
// ---------------------------------------------------------------------------
class LineFramer {
  private pending: Buffer[] = [];

  /** Feed a chunk; returns any complete lines (decoded, without the trailing \n) it completed. */
  push(chunk: Buffer): string[] {
    this.pending.push(chunk);
    const combined = Buffer.concat(this.pending);
    const lines: string[] = [];
    let start = 0;
    for (let i = 0; i < combined.length; i++) {
      if (combined[i] === 0x0a) {
        lines.push(combined.subarray(start, i).toString("utf8"));
        start = i + 1;
      }
    }
    this.pending = start < combined.length ? [combined.subarray(start)] : [];
    return lines;
  }

  /** Called on stream end: whatever remains without a trailing newline is treated as one final line. */
  flush(): string[] {
    if (this.pending.length === 0) return [];
    const combined = Buffer.concat(this.pending);
    this.pending = [];
    return combined.length > 0 ? [combined.toString("utf8")] : [];
  }
}

// ---------------------------------------------------------------------------
// Recursive string collection/substitution for tools/call arguments.
// ---------------------------------------------------------------------------
interface StringHit {
  path: (string | number)[];
  original: string;
}

/**
 * Depth ceiling for the walk below. These payloads come from whatever client
 * is on the other end of the pipe, so a deeply nested one must not blow the
 * stack mid-message and drop the connection. Anything past this depth is left
 * unscanned rather than crashing the proxy.
 */
const MAX_WALK_DEPTH = 64;

function collectStrings(
  node: unknown,
  path: (string | number)[],
  out: StringHit[],
  depth = 0,
): void {
  if (depth > MAX_WALK_DEPTH) return;
  if (typeof node === "string") {
    out.push({ path: [...path], original: node });
  } else if (Array.isArray(node)) {
    node.forEach((v, i) => collectStrings(v, [...path, i], out, depth + 1));
  } else if (isRecord(node)) {
    for (const [k, v] of Object.entries(node)) collectStrings(v, [...path, k], out, depth + 1);
  }
}

function setAtPath(root: unknown, path: (string | number)[], value: unknown): void {
  let cur: unknown = root;
  for (let i = 0; i < path.length - 1; i++) {
    cur = (cur as Record<string | number, unknown>)[path[i]];
  }
  (cur as Record<string | number, unknown>)[path[path.length - 1]] = value;
}

/** Text-bearing content items in an MCP tool result's `content` array. */
interface TextHit {
  index: number;
  original: string;
}

function collectResultTextHits(content: unknown[]): TextHit[] {
  const hits: TextHit[] = [];
  content.forEach((item, i) => {
    if (isRecord(item) && item.type === "text" && typeof item.text === "string") {
      hits.push({ index: i, original: item.text });
    }
  });
  return hits;
}

interface EvaluatedHit<H> {
  hit: H;
  result: EvaluationResult;
}

/**
 * `host` must be the same label the caller passes to `recordEvent` for this
 * same batch of hits ("cli:mcp:call" for outbound tool arguments,
 * "cli:mcp:result" for inbound tool results below) — otherwise a policy
 * exception scoped to one direction could never match evaluations tagged
 * under the other.
 */
function evaluateHits<H extends { original: string }>(hits: H[], policy: Policy, host: string): EvaluatedHit<H>[] {
  return hits.map((hit) => ({ hit, result: evaluate(hit.original, policy, host) }));
}

/** Merge per-string EvaluationResults into one, for recordEvent/toUserMessage — neither reads start/end/redactedText off it, only findings/blocked/needsWarning (see apps/cli/src/scan.ts's identical pattern). */
function mergeResults(evaluated: EvaluatedHit<unknown>[]): EvaluationResult {
  const findings: Finding[] = [];
  let blocked = false;
  let needsWarning = false;
  for (const { result } of evaluated) {
    findings.push(...result.findings);
    if (result.blocked) blocked = true;
    if (result.needsWarning) needsWarning = true;
  }
  return { findings, redactedText: "", blocked, needsWarning };
}

// ---------------------------------------------------------------------------
// Gateway wiring
// ---------------------------------------------------------------------------
interface GatewayContext {
  policy: Policy;
  child: ChildProcess;
  /** ids of forwarded tools/call requests we still expect a response for. */
  pendingToolCalls: Set<string | number>;
}

function writeLine(stream: NodeJS.WritableStream, line: string): void {
  try {
    stream.write(line.endsWith("\n") ? line : line + "\n");
  } catch {
    // Destination pipe already closed (child or client exited) — nothing
    // useful to do with a write failure this deep in a proxy loop.
  }
}

async function processOutboundLine(raw: string, ctx: GatewayContext): Promise<void> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    writeLine(ctx.child.stdin!, raw); // not JSON — pass through unchanged
    return;
  }

  if (!isRecord(parsed) || parsed.method !== "tools/call") {
    writeLine(ctx.child.stdin!, raw);
    return;
  }

  const hasId = "id" in parsed;
  const id = hasId ? (parsed.id as string | number | null) : null;
  if (hasId && (typeof id === "string" || typeof id === "number")) {
    ctx.pendingToolCalls.add(id);
  }

  const params = isRecord(parsed.params) ? parsed.params : undefined;
  const args = params && isRecord(params.arguments) ? params.arguments : undefined;
  if (args === undefined) {
    writeLine(ctx.child.stdin!, raw); // nothing scannable in this call
    return;
  }

  const hits: StringHit[] = [];
  collectStrings(args, [], hits);
  if (hits.length === 0) {
    writeLine(ctx.child.stdin!, raw);
    return;
  }

  const evaluated = evaluateHits(hits, ctx.policy, "cli:mcp:call");
  const merged = mergeResults(evaluated);
  await recordEvent(merged, ctx.policy, "cli:mcp:call");

  if (merged.blocked) {
    if (hasId && (typeof id === "string" || typeof id === "number")) {
      ctx.pendingToolCalls.delete(id); // no response will ever arrive for a call we never forwarded
    }
    if (hasId) {
      const errorResponse = {
        jsonrpc: "2.0",
        id,
        error: {
          code: POLICY_BLOCK_ERROR_CODE,
          message: `Wardkeep blocked this tool call (${toUserMessage(merged)})`,
        },
      };
      writeLine(process.stdout, JSON.stringify(errorResponse));
    }
    // A tools/call with no id at all is not valid MCP (a request expects a
    // reply), but if one somehow arrives we still refuse to forward it —
    // there's just nothing to reply to.
    return; // never forwarded to the child
  }

  let changed = false;
  const clonedArgs = jsonClone(args);
  for (const { hit, result } of evaluated) {
    if (result.redactedText !== hit.original) {
      setAtPath(clonedArgs, hit.path, result.redactedText);
      changed = true;
    }
  }

  if (!changed) {
    writeLine(ctx.child.stdin!, raw); // warn/observe/clean — forward byte-identical
    return;
  }

  const rewritten = { ...parsed, params: { ...params, arguments: clonedArgs } };
  writeLine(ctx.child.stdin!, JSON.stringify(rewritten));
}

async function processInboundLine(raw: string, ctx: GatewayContext): Promise<void> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    writeLine(process.stdout, raw);
    return;
  }

  if (!isRecord(parsed) || !("id" in parsed)) {
    writeLine(process.stdout, raw); // notification — nothing to correlate
    return;
  }

  const id = parsed.id;
  if ((typeof id !== "string" && typeof id !== "number") || !ctx.pendingToolCalls.has(id)) {
    writeLine(process.stdout, raw); // not a response to a tools/call we forwarded
    return;
  }
  ctx.pendingToolCalls.delete(id);

  const result = isRecord(parsed.result) ? parsed.result : undefined;
  const content = result && Array.isArray(result.content) ? result.content : undefined;
  if (!content) {
    writeLine(process.stdout, raw); // error response, or a result shape we don't scan
    return;
  }

  const hits = collectResultTextHits(content);
  if (hits.length === 0) {
    writeLine(process.stdout, raw);
    return;
  }

  const evaluated = evaluateHits(hits, ctx.policy, "cli:mcp:result");
  const merged = mergeResults(evaluated);
  await recordEvent(merged, ctx.policy, "cli:mcp:result");

  if (merged.blocked) {
    const blockedResult = {
      ...result,
      content: [{ type: "text", text: `Wardkeep blocked this tool result (${toUserMessage(merged)})` }],
      isError: true,
    };
    writeLine(process.stdout, JSON.stringify({ ...parsed, result: blockedResult }));
    return;
  }

  let changed = false;
  const newContent = content.slice();
  for (const { hit, result: hitResult } of evaluated) {
    if (hitResult.redactedText !== hit.original) {
      newContent[hit.index] = { ...(content[hit.index] as Record<string, unknown>), text: hitResult.redactedText };
      changed = true;
    }
  }

  if (!changed) {
    writeLine(process.stdout, raw); // warn/observe/clean — forward byte-identical
    return;
  }

  writeLine(process.stdout, JSON.stringify({ ...parsed, result: { ...result, content: newContent } }));
}

export async function runMcpGateway(argv: string[]): Promise<number> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    process.stdout.write(USAGE);
    return 0;
  }

  const dashIndex = argv.indexOf("--");
  if (dashIndex !== 0 || argv.length === 1) {
    process.stderr.write('wardkeep mcp: expected "-- <server command> [args...]"\n\n' + USAGE);
    return 3;
  }
  const serverCmd = argv.slice(1);

  let policy: Policy;
  try {
    ({ policy } = await loadPolicy());
  } catch (err) {
    process.stderr.write(`${(err as Error).message}\n`);
    return 3;
  }

  return new Promise<number>((resolveExitCode) => {
    // Reviewed carve-out (see file header): no shell, argv passed straight
    // through, child's own stderr inherited so its diagnostics surface to
    // whoever is running `wardkeep mcp`.
    const child = spawn(serverCmd[0], serverCmd.slice(1), {
      stdio: ["pipe", "pipe", "inherit"],
      shell: false,
    });

    const ctx: GatewayContext = { policy, child, pendingToolCalls: new Set() };
    const outboundFramer = new LineFramer();
    const inboundFramer = new LineFramer();
    let outboundChain: Promise<void> = Promise.resolve();
    let inboundChain: Promise<void> = Promise.resolve();
    let settled = false;

    const enqueueOutbound = (line: string) => {
      outboundChain = outboundChain
        .then(() => processOutboundLine(line, ctx))
        .catch((err: unknown) => {
          process.stderr.write(`wardkeep mcp: error scanning outbound message: ${(err as Error).message}\n`);
        });
    };
    const enqueueInbound = (line: string) => {
      inboundChain = inboundChain
        .then(() => processInboundLine(line, ctx))
        .catch((err: unknown) => {
          process.stderr.write(`wardkeep mcp: error scanning inbound message: ${(err as Error).message}\n`);
        });
    };

    // process.stdin/child.stdout, and their writable counterparts, all get a
    // no-op 'error' listener so a peer closing its end early (EPIPE) doesn't
    // crash this process — the proxy loop already handles a closed
    // destination via writeLine's own try/catch; these just stop Node from
    // treating an unhandled stream error as fatal.
    process.stdin.on("error", () => {});
    process.stdout.on("error", () => {});
    child.stdin?.on("error", () => {});
    child.stdout?.on("error", () => {});

    process.stdin.on("data", (chunk: Buffer) => {
      for (const line of outboundFramer.push(chunk)) enqueueOutbound(line);
    });
    process.stdin.on("end", () => {
      for (const line of outboundFramer.flush()) enqueueOutbound(line);
      outboundChain.then(() => {
        try {
          child.stdin?.end();
        } catch {
          // already closed
        }
      });
    });

    child.stdout?.on("data", (chunk: Buffer) => {
      for (const line of inboundFramer.push(chunk)) enqueueInbound(line);
    });
    child.stdout?.on("end", () => {
      for (const line of inboundFramer.flush()) enqueueInbound(line);
    });

    const finish = (code: number) => {
      if (settled) return;
      settled = true;
      Promise.all([outboundChain, inboundChain]).finally(() => resolveExitCode(code));
    };

    child.on("error", (err) => {
      process.stderr.write(`wardkeep mcp: failed to start server: ${err.message}\n`);
      finish(3);
    });
    child.on("close", (code, signal) => {
      finish(code ?? (signal ? 1 : 0));
    });

    const forwardSignal = (signal: NodeJS.Signals) => {
      if (!child.killed) child.kill(signal);
    };
    process.on("SIGINT", forwardSignal);
    process.on("SIGTERM", forwardSignal);
  });
}
