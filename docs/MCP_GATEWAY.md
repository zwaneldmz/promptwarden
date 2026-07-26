# MCP stdio gateway (`promptwarden mcp -- <server command>`)

Wraps a real MCP server's stdio transport with PromptWarden's policy engine so both directions
of MCP traffic get scanned: the arguments a client sends into `tools/call`, and the text content
a tool result sends back. Implemented in
[`apps/cli/src/mcp/gateway.ts`](../apps/cli/src/mcp/gateway.ts); see that file's module doc for
the line-by-line design. This document covers the operational contract: what it covers, what it
deliberately does not, and copy-pasteable config for the clients that speak MCP over stdio.

## What it covers

Per `docs/ROADMAP.md` §2's interception-mechanism table, the gateway is positioned as **the best
adapter after the CLI's own `scan`/`hook` front doors** specifically because it is the *only*
mechanism in this repo that sees tool **results**, not just arguments:

| Direction | What's scanned | Block | Redact | Warn / observe |
|---|---|---|---|---|
| Outbound — client → real server | `tools/call` `params.arguments`, every string value, at any nesting depth | The call never reaches the child. A JSON-RPC error is synthesized and sent back to the client instead, using the original request's `id` and a `toUserMessage`-only reason. | The offending string values are replaced with their redacted form (`[REDACTED:IBAN]`, etc.) and the rewritten call is forwarded. | Forwarded unchanged; the finding is still recorded. |
| Inbound — real server → client | Each tool result's `content[]` items where `type === "text"`, i.e. `content[i].text` | The whole `content` array is replaced with a single `{type: "text", text: "..."}` notice (built from `toUserMessage` only) and `isError: true` is set, so a model reading the result back can't mistake it for real data. | Individual `text` items are substituted in place; other content items in the same result are untouched. | Forwarded unchanged; the finding is still recorded. |

Every event is recorded through the same `recordEvent`/`toLogRecord` path the rest of the CLI
uses (`cli:mcp:call` / `cli:mcp:result` as the surface label), governed by the same policy
document and discovery precedence as `promptwarden scan` — see
[`apps/cli/src/policy.ts`](../apps/cli/src/policy.ts).

Everything that is **not** a `tools/call` request or a response the gateway is tracking —
`initialize`, `tools/list`, `resources/*`, notifications in either direction, and any response
whose `id` doesn't correspond to a forwarded `tools/call` — passes through byte-identical. The
gateway never re-serializes a message it isn't modifying, so it stays transparent to protocol
features it doesn't need to understand.

Because it reaches the MCP client through nothing more than a config-file edit (point the
client's server `command` at `promptwarden mcp -- <old command>` instead of `<old command>`
directly), it covers **every MCP-speaking client that can start a stdio server** — Claude Code,
Claude Desktop, Cursor, VS Code, Windsurf, JetBrains, and anything else that follows the same
"spawn a command, talk NDJSON over its stdin/stdout" contract.

## What it does NOT cover

Stated plainly, because installing the gateway is easy to over-read:

- **Only the MCP channel.** It has no visibility into anything outside the wrapped server's own
  stdin/stdout — not the rest of the client's process, not other MCP servers you haven't also
  wrapped, not the model's own reasoning.
- **Not a prompt gate.** Per `docs/ROADMAP.md` §2's boundary statement: "MCP cannot gate a prompt
  the model never routes to it." The gateway only ever sees what the model *chooses* to send
  through a `tools/call`. It says nothing about — and must never be documented as covering — the
  human's own typed prompt. That's the Claude Code `UserPromptSubmit` hook's job (see
  [`docs/CLAUDE_CODE_HOOK.md`](CLAUDE_CODE_HOOK.md)), not this gateway's.
- **HTTP/SSE-transport MCP servers are out of scope by design.** This is a stdio-framing proxy
  only — it spawns a child process and speaks newline-delimited JSON-RPC over pipes. A server
  reachable only over HTTP or SSE (no local `command` to wrap) is not something this gateway can
  sit in front of. If the client you're configuring only offers a URL-based MCP connection, the
  gateway has nothing to attach to.
- **Non-text content is never scanned.** Only `content[]` items with `type: "text"` are
  inspected on the inbound side. Images, embedded resources, and any other content type pass
  through untouched — including if that content happens to encode sensitive text (a screenshot
  of a spreadsheet, a base64-embedded document). This is the same "structured formats only, no
  content-sniffing a binary blob" posture the rest of the engine takes.
- **A blocked/redacted `tools/call` is still visible to the model as "a tool call happened."**
  The model sees a JSON-RPC error (for a block) or a normal-looking result carrying the redacted
  text (for a redact) — it does not see the original text it tried to send. This is the intended
  behavior, not a gap, but worth stating: the gateway changes what the model receives back, it
  does not silently pretend the call never happened.
- **Malformed-but-non-JSON lines pass through unscanned.** A line that isn't valid JSON on either
  side of the pipe is forwarded verbatim rather than blocked — the gateway can only evaluate JSON
  it can parse. Framing itself (reassembling a message split across multiple `data` events) is
  handled correctly regardless of content.

## Configuration

In every example, `promptwarden mcp -- <original command...>` replaces whatever the client used
to invoke the real MCP server directly. Everything after the literal `--` is passed straight
through to `child_process.spawn` with no shell involved — quote/escape it exactly as you would
the original command's argv, not as a shell string.

### Claude Code (`.mcp.json`)

Project-scoped config, checked into the repo at `.mcp.json`:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "promptwarden",
      "args": ["mcp", "--", "npx", "-y", "@some/mcp-server"]
    }
  }
}
```

### Claude Desktop

`claude_desktop_config.json` (macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`; Windows:
`%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "my-server": {
      "command": "promptwarden",
      "args": ["mcp", "--", "node", "/absolute/path/to/server/index.js"]
    }
  }
}
```

### Cursor

`.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global):

```json
{
  "mcpServers": {
    "my-server": {
      "command": "promptwarden",
      "args": ["mcp", "--", "npx", "-y", "@some/mcp-server"]
    }
  }
}
```

### VS Code

`.vscode/mcp.json`:

```json
{
  "servers": {
    "my-server": {
      "type": "stdio",
      "command": "promptwarden",
      "args": ["mcp", "--", "node", "/absolute/path/to/server/index.js"]
    }
  }
}
```

In every case, if the original server config carried its own `env` block, keep it — the gateway
spawns the child with the same environment `promptwarden mcp` itself runs under, so any
credentials the real server needs still reach it unchanged; only the arguments and results the
server exchanges with the client are inspected.

### Policy

The gateway resolves its policy the same way `promptwarden scan` does — see the precedence chain
in [`apps/cli/src/policy.ts`](../apps/cli/src/policy.ts)'s module doc
(`/etc/promptwarden/policy.json` > `$PROMPTWARDEN_POLICY` > `$XDG_CONFIG_HOME` > repo-local
`.promptwarden.json` (strictness-monotonic only) > built-in default). There is no gateway-specific
policy flag; set `$PROMPTWARDEN_POLICY` in the client's `env` block for that server entry if you
want a policy other than whatever the ambient environment resolves to.

## Verify it's live

1. Configure a real (or the test fixture) MCP server through the gateway as above and restart
   the client.
2. Ask the assistant to call a tool with a synthetic, Luhn-valid test card number in one of its
   arguments — for example `4532 0151 1283 0366` (the same fixture the CLI's own tests use). Under
   the built-in default policy (`credit_card: warn`) the call still goes through; switch the
   policy's `credit_card` rule to `block` to see it refused with a PromptWarden error instead —
   never the digits themselves.
3. For the inbound direction, the canary needs to come back *in a tool result* rather than in
   what you send — point the server at data that includes the same test card number (or a
   mod-97-valid test IBAN such as `AT61 1904 3002 3457 3201`) and confirm the returned result
   carries `[REDACTED:CARD]`/`[REDACTED:IBAN]` (under a `redact` rule) or a block notice with
   `isError: true` (under `block`) instead of the raw value.
4. Negative control: repeat both probes with ordinary, non-sensitive content and confirm nothing
   is altered — the gateway should be invisible on a clean call.

Do not use a real card or account number for this — a synthetic, checksum-valid test fixture is
enough to prove the gate is live, and a real one would needlessly put real payment data through
whatever the wrapped server logs.
