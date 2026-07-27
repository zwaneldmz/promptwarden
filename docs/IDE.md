# Wardkeep — IDE surfaces

What reaches an IDE, what doesn't, and why. Read this before assuming the VS Code extension or
`wardkeep emit-exclusions` covers more than they do — the honest boundary matters more here
than anywhere else in this project, because the gap is architectural, not a missing feature.

## The boundary, stated once, plainly

**IDE inline completions (GitHub Copilot, Cursor Tab, JetBrains AI Assistant) and any AI chat or
agent panel bundled into the editor (Copilot Chat, Cursor Chat, agent/agentic tool-use modes) are
architecturally out of reach for a local, open-source tool.** The completion or chat payload is
assembled *inside a closed process* — the vendor's own extension or background service — and sent
over its own connection. Nothing in this repository sits on that path, and nothing can be added to
sit on that path without either patching a signed vendor binary (breaks the signature, breaks
auto-update, see `docs/ROADMAP.md` §4) or running a TLS-intercepting proxy (explicitly rejected,
same section). This is unchanged from `docs/ROADMAP.md` §3's coverage map; this document exists to
put the same boundary in front of anyone looking specifically at the IDE.

What **is** reachable from inside an editor, without any of the above, is narrower and is exactly
what this repo builds for it:

1. **The files themselves**, once they're open in the editor — this extension can read and
   diagnose them locally, same as any linter.
2. **The paths a vendor's own tooling is willing to skip**, if that vendor ships an exclusion
   mechanism — `wardkeep emit-exclusions` renders the file; the vendor decides whether to
   honor it.
3. **The MCP transport**, when an agent-mode tool call goes over stdio JSON-RPC to a server this
   machine also runs — a real interception point, and the strongest lever available for anything
   IDE-adjacent. See [`docs/MCP_GATEWAY.md`](MCP_GATEWAY.md).

## Coverage table

| IDE surface | Covered by | Enforcement strength | Detail |
|---|---|---|---|
| Inline completions (Copilot, Cursor Tab, JetBrains AI Assistant) | **Nothing.** Not attempted. | — | Closed-process payload, no interception point exists. Path exclusions (below) are the only indirect lever — they act on what the vendor reads, not on what it sends. |
| AI chat / agent panel inside the editor (Copilot Chat, Cursor Chat, agent tool-use mode rendered in-editor) | **Nothing.** Not attempted. | — | Same closed-process boundary. If the panel dispatches tool calls over MCP, see the "Agent mode / MCP tool calls" row — that's a different channel than the chat UI itself. |
| Agent mode / MCP tool calls (Claude Code, Cursor agent mode, Copilot agent mode, any client that speaks MCP over stdio) | **MCP stdio gateway** — `wardkeep mcp -- <server command>` | **Local-only, deterministic** — every tool argument and every tool *result* on the wrapped server is scanned against the resolved policy before it crosses the gateway | The strongest IDE-adjacent lever this project has, because MCP is an explicit, machine-readable protocol rather than a closed payload. Config-file reach only (edit the MCP server's `command` to point at the gateway) — nothing to install inside the IDE. See [`docs/MCP_GATEWAY.md`](MCP_GATEWAY.md) for the full mechanism, and `docs/ROADMAP.md` §2's interception-mechanism table for why this is rated ahead of everything else IDE-side. |
| Files on disk (what an inline-completion/chat/agent feature might read as context, or what a developer opens directly) | **VS Code diagnostics** (`apps/vscode`) *and, independently,* **path exclusions** (`wardkeep emit-exclusions`) | Diagnostics: **local-only** (visible to the human in the Problems panel; does not touch what any AI feature reads or sends). Exclusions: **vendor-enforced, best-effort, or community-convention depending on format** — see the breakdown below. | Two different mechanisms answering two different questions: diagnostics tell *you* what's in a file; exclusions are a hint to a *vendor's tool* about which files to leave alone. Neither one scans, redacts, or blocks anything the way the browser extension or CLI do. |

## VS Code diagnostics (`apps/vscode`)

A minimal VS Code extension that runs the same engine (`@wardkeep/policy-engine`) the CLI and
browser extension use, over the text of files you open or save, and publishes
`vscode.Diagnostic` entries in the Problems panel plus a status-bar finding count.

- Triggers: opening a document, saving a document, and the two commands
  **Wardkeep: Scan Active File** and **Wardkeep: Scan Workspace Selection**.
- Severity mapping: `block` → Error, `redact`/`warn` → Warning, `observe` → Information.
  (`allow` findings never reach this point — the engine already filters them out.)
- **Diagnostic messages carry category and action only — `finding.detector` and
  `finding.action` — never `finding.match`.** A diagnostic is visible in screenshots, Live
  Share sessions, and anything pasted into a chat; putting the matched IBAN or card number in
  the message text would defeat the point of flagging it. This mirrors the engine's own
  `toUserMessage` privacy gate (`packages/policy-engine/src/engine.ts`), even though diagnostics
  don't route through that function directly.
- Policy source: the `wardkeep.policyPath` setting, or the built-in
  `vscode-standalone-default` policy if unset — there is no managed-storage or `/etc` discovery
  inside an editor; distribute a path via Settings Sync or a committed `.vscode/settings.json`
  if you need one.
- **What it explicitly does not do:** intercept, read, or gate the Copilot/Cursor chat panel,
  inline suggestions, or any agent-mode tool call. It only ever looks at documents already open
  (or explicitly selected) in the editor's own text buffers — see the doc comment at the top of
  `apps/vscode/src/extension.ts`.
- Build status: typechecks against the repo's own `tsc` (`apps/vscode/tsconfig.json`), using
  `@types/vscode` as a dev-only dependency — no new runtime dependency. **The root
  `npm run typecheck` script does not yet include `apps/vscode/tsconfig.json`, and no bundler
  entry exists for it in `npm run build:*`** — both need wiring into the root `package.json`,
  which this workstream does not own. The extension has not been launched or run inside VS
  Code as part of this work; only `tsc --noEmit` has verified it.

## Path exclusions (`wardkeep emit-exclusions`)

```
wardkeep emit-exclusions --format cursorignore|copilot-yaml|aiignore [--out <path>]
```

Renders a vendor-specific exclusion file from the same resolved policy document `wardkeep
scan` uses (see `apps/cli/src/policy.ts`'s discovery precedence) — the patterns included are
driven by which detectors that policy actually enables (any action other than `allow`), so a
policy that blocks `api_key` gets the secrets-shaped patterns below, and a policy that leaves
`email`/`phone` on `allow` gets none (there's no filename shape that says "this file holds an
email address" the way `.env` or `*.pem` says "this file holds a secret").

Default path patterns rendered, grouped by the detector that justifies them:

| Detector | Patterns |
|---|---|
| `api_key` | `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `credentials*`, `secrets*`, `*.p12`, `*.pfx`, `.aws/**`, `.kube/**`, `service-account*.json` |
| `private_key` | `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `*.p12`, `*.pfx` |
| `connection_string` | `.env`, `.env.*`, `credentials*`, `secrets*` |
| `jwt` | `.env`, `.env.*` |
| `credit_card`, `iban`, `at_svnr`, `bulk_pii` | `*.sql`, `*dump.sql`, `*.csv` (bulk exports, not single secrets) |

Every rendered file's header states the source policy's name and repeats, format-by-format, that
**enforcement is entirely on the vendor's side and this tool cannot verify or force it**:

| Format | File | What it feeds | Enforcement strength, per the vendor's own docs |
|---|---|---|---|
| `cursorignore` | `.cursorignore` | Cursor's editor | **Best-effort.** Cursor's own description does not guarantee an excluded path is never read or sent to a model. |
| `copilot-yaml` | Pasted into repo/org Settings → Copilot → Content exclusion (this file is not consumed automatically — `wardkeep` makes no network calls and cannot upload it for you) | GitHub Copilot code completions and Copilot Chat's editor context | **Vendor-enforced, server-side, for the surfaces it covers** — but per GitHub's own documentation it is **NOT applied to Copilot CLI, the Copilot coding agent, or Copilot Chat's agent mode.** A policy that assumes content exclusion covers agent mode is wrong. |
| `aiignore` | `.aiignore` | Whichever tools choose to read it | **Community convention, not a guaranteed feature** — comparable to `.copilotignore`. Some tools document honoring a file with this name; nothing here can confirm any given editor actually does. |

None of these three replace scanning. They reduce what a vendor's tool is *offered* to read, on a
best-effort or vendor-enforced-for-a-subset-of-surfaces basis; they never redact, warn, or block
anything themselves, and `wardkeep emit-exclusions` does not verify that any target editor
picked the file up.

## Agent mode / MCP — the strongest lever, documented separately

Agent-mode tool calls (Claude Code, Cursor's agent mode, Copilot's agent mode, and any other
client that speaks MCP over stdio to a locally-run server) are the one IDE-adjacent surface with a
real interception point: `wardkeep mcp -- <server command>` sits between the MCP client and
the real server, scanning both tool *arguments* and tool *results* against the resolved policy —
the inbound direction nothing else in this project covers. It reaches Claude Code, Claude Desktop,
Cursor, VS Code, Windsurf, and JetBrains through a single config-file edit (pointing the server's
`command` at the gateway), with no IDE extension install of its own required.

Full mechanism, the reviewed `child_process.spawn` carve-out, and its scope limits (MCP transport
only; HTTP/SSE-transport servers out of scope) are documented in
[`docs/MCP_GATEWAY.md`](MCP_GATEWAY.md) — that document is the one to read before assuming
"agent mode" means the same thing as "the chat panel." It doesn't: the chat panel is the closed,
unreachable payload from the section above; MCP tool calls are the one channel out of it this
project can actually see.

## What this document deliberately does not claim

- That the VS Code extension sees, gates, or even knows about a Copilot/Cursor completion or chat
  turn. It doesn't, and can't.
- That `.cursorignore`/`.copilot-yaml`/`.aiignore` are enforced. They're rendered; whether they're
  *honored* is entirely up to code this project does not own or control.
- That path exclusions cover agent mode. GitHub's own docs say content exclusion explicitly does
  not; `.cursorignore`'s and `.aiignore`'s coverage of agent/agentic modes is unverified either
  way, so treat both as no better than "maybe, for the editor's own completions" and nothing more.
- That any of the above is a substitute for the MCP gateway, the CLI, the Claude Code hook, or the
  browser extension — those are where scanning, redaction, and blocking actually happen. Everything
  in this document is either a read-only diagnostic (VS Code) or a hint a vendor may or may not
  respect (exclusions).
