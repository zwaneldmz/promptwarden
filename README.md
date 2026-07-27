# Wardkeep

*Formerly PromptWarden — renamed July 2026 to avoid collisions with
similarly-named projects.*

Local guardrails for AI tools. Wardkeep warns, redacts, or blocks
sensitive data — credit cards, IBANs, private keys, JWTs, API keys,
connection strings, social insurance numbers, and bulk PII patterns — before
it reaches ChatGPT, Claude, Gemini, Copilot, or any other AI surface. File
uploads are scanned too, including Office attachments (.xlsx, .docx). All
evaluation is local, deterministic, and dependency-free. Nothing ever leaves
the device.

## Surfaces

| Surface | What it covers | How it works |
|---|---|---|
| **Chrome extension** | Typed prompts, pastes, send-button clicks, file uploads/drops on AI chat sites | MV3 content script, capture-phase interception, no site-specific selectors |
| **CLI** (`wardkeep scan`) | Piped text, files, heredocs — `cat data.csv \| wardkeep scan --stdin` | Same policy engine, same detectors, exit codes for CI |
| **Claude Code hook** (`wardkeep hook claude-code`) | Human prompts (`UserPromptSubmit`) and every tool argument (`PreToolUse`) | Stdin/stdout hook protocol; `redact` rewrites tool args via `updatedInput` |
| **MCP gateway** (`wardkeep mcp -- <server>`) | Tool arguments *and* tool results on any stdio MCP server | Transparent JSON-RPC proxy; reaches Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, JetBrains |
| **VS Code extension** | Files open in the editor | Diagnostics in the Problems panel; does **not** intercept Copilot/Cursor completions |
| **Path exclusions** (`wardkeep emit-exclusions`) | Vendor exclusion files for Cursor, GitHub Copilot, `.aiignore` | Renders the file; enforcement is on the vendor's side |

## How it works

A dependency-free TypeScript policy engine evaluates text against a set of
detectors (Luhn-validated card numbers, mod-97 IBANs, PEM key blocks, JWT
structure checks, API key prefix patterns, and more) and a policy document
that decides **warn**, **redact**, **block**, or **observe** per data type.
A bulk PII post-pass fires when many distinct values appear in one prompt.

Each surface wraps the same engine with the appropriate I/O:

- **Browser:** content script intercepts submit actions before text is sent.
  Guardrail UI in a closed ShadowRoot.
- **CLI:** reads stdin/files, evaluates, emits a `toLogRecord` event, exits
  with a code CI can gate on.
- **Claude Code hook:** reads the hook JSON envelope, scans the prompt or
  tool arguments, returns a decision on stdout.
- **MCP gateway:** wraps a real MCP server, scanning both directions of
  newline-delimited JSON-RPC. Block on outbound = synthesized error, call
  never reaches child. Inbound block = error notice to the client.

Logging defaults to off. When enabled, all records pass through
`toLogRecord`, the single privacy gate that provably emits no prompt
content in event mode.

## Detectors

| ID | What it catches | Validation |
|---|---|---|
| `credit_card` | 13–19 digit card numbers | Luhn checksum + issuer prefix (Visa, MC, Amex, Discover, Maestro, Diners, JCB, UnionPay) |
| `iban` | International bank account numbers | Per-country length table (95 countries) + mod-97 |
| `api_key` | Structured vendor secret keys | OpenAI/Anthropic `sk-`, AWS `AKIA`/`ASIA`, GitHub `ghp_`/`github_pat_`, Slack `xox*-`, Google `AIza`, Stripe `sk_live_`/`rk_live_` |
| `private_key` | PEM-armored private key blocks | `-----BEGIN ... PRIVATE KEY-----` (RSA/EC/DSA/PKCS#8/OpenSSH/PGP) |
| `jwt` | JSON Web Tokens | Three base64url segments; decoded header contains `alg` |
| `connection_string` | Database/queue connection URIs and ODBC/ADO.NET strings | URI form with password field, or `Password=`/`AccountKey=` key-value form |
| `at_svnr` | Austrian social insurance numbers | 10-digit check-digit validation |
| `email` | Email addresses | RFC-like pattern match |
| `phone` | International phone numbers | `+`/`00` prefix, 9–15 digits |
| `bulk_pii` | Bulk data exfiltration (many distinct PII values in one prompt) | Post-pass: fires when one category hits a threshold, or 2+ categories each hit half. Requires an explicit rule. |

Custom regex detectors are supported via `pattern` in a policy rule.

## Install

### Browser extension (not yet on the Chrome Web Store)

1. `npm install` and build (see [Build](#build)).
2. Open `chrome://extensions`, enable Developer mode.
3. Click "Load unpacked" and select `apps/extension/`.
4. Type a Luhn-valid test card number into a supported chat site and press
   Enter to see the guardrail.

### CLI

```bash
npm install
npm run build:engine
npm run build:cli
# Then either:
node apps/cli/dist/cli.js scan --stdin
# Or link it:
npm link
wardkeep scan --stdin
```

### Claude Code hook

Add to your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "command": "wardkeep hook claude-code" }
    ],
    "PreToolUse": [
      { "command": "wardkeep hook claude-code" }
    ]
  }
}
```

See [docs/CLAUDE_CODE_HOOK.md](docs/CLAUDE_CODE_HOOK.md) for the full
contract.

### MCP gateway

Wrap any MCP server's command with the gateway:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "wardkeep",
      "args": ["mcp", "--", "actual-server-binary", "--flag"]
    }
  }
}
```

See [docs/MCP_GATEWAY.md](docs/MCP_GATEWAY.md) for configuration examples
covering Claude Code, Claude Desktop, Cursor, VS Code, and others.

## Repository layout

```
packages/policy-engine   Dependency-free TS library: policy schema, detectors,
                         evaluation, privacy-gated logging, Office extraction,
                         byte-level file scanning. Tested (npm test).
apps/extension           Manifest V3 Chrome extension: content-script
                         interception, guardrail UI, managed-storage policy,
                         dynamic host coverage, popup event log.
apps/cli                 CLI tool: scan, hook claude-code, mcp gateway,
                         emit-exclusions. Single binary, zero runtime deps.
apps/vscode              VS Code extension: diagnostics in the Problems panel.
apps/playground          Standalone policy editor + live preview. No backend.
profiles/                Example org policy profiles (accounting, healthcare).
docs/                    Architecture, threat model, deployment guides, roadmap.
tools/                   E2E smoke tests (Playwright).
```

## Build

```bash
npm install
npm run build:engine        # TypeScript → dist for the policy engine
npm run build:cli           # esbuild bundle for the CLI
npm run build:extension     # esbuild bundle for the Chrome extension
npm run build:playground    # standalone playground HTML + extension engine bundle
npm run typecheck           # tsc --noEmit for extension + CLI
npm test                    # engine + CLI test suites (node --test)
npm run smoke               # E2E smoke tests against real AI sites
```

## Policy

A JSON document that controls what gets detected, what action to take, and
on which hosts. Example:

```json
{
  "version": 1,
  "name": "my-org",
  "hosts": ["chatgpt.com", "claude.ai"],
  "logging": "event",
  "defaultAction": "warn",
  "rules": [
    { "detector": "credit_card", "action": "block" },
    { "detector": "api_key", "action": "redact" },
    { "detector": "email", "action": "allow" }
  ]
}
```

**Browser:** managed storage (admin-pushed) > local storage > built-in
default.

**CLI:** `/etc/wardkeep/policy.json` (root-owned) >
`$WARDKEEP_POLICY` (path) > `$XDG_CONFIG_HOME/wardkeep/policy.json`
\> repo-local `.wardkeep.json` (strictness-monotonic only — can raise
actions, never lower) > built-in default.

See the [profiles/](profiles/) directory for complete examples.

## Managed deployment

Admins can push a policy via Chrome Enterprise managed storage (Google Admin
console, Intune, Group Policy, or macOS .mobileconfig) using the `policy`
key defined in `apps/extension/managed_schema.json`. Managed policy always
overrides local settings. Additional hosts can be added via the `extraHosts`
managed storage key.

Deployment guides (all marked as unverified):

- [Google Admin](docs/DEPLOY_GOOGLE_ADMIN.md)
- [Microsoft Intune](docs/DEPLOY_INTUNE.md)
- [Windows Group Policy](docs/DEPLOY_GPO.md)
- [macOS (Jamf/Intune)](docs/DEPLOY_MACOS.md)
- [Self-hosted CRX](docs/DEPLOY_SELF_HOSTED_CRX.md)

## Supported hosts (browser)

Default: ChatGPT, Claude, Gemini, Copilot, Mistral, Perplexity. Extensible
via `extraHosts` in managed storage for admin-declared internal AI tools.
See [docs/HOST_COVERAGE.md](docs/HOST_COVERAGE.md).

## What Wardkeep does NOT cover

- Direct API calls (curl, SDKs) — no interception point exists
- IDE inline completions (Copilot, Cursor Tab) — closed-process payload
- Desktop apps (Claude Desktop, ChatGPT app) — the app is unreachable; the
  MCP gateway covers tool calls routed through it
- PDF and legacy binary Office formats (.doc, .xls)
- Files an agent reads on its own (no hook reaches this path)
- Firefox (no port yet)

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full boundary.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The "Wardkeep"
name is governed separately — see [TRADEMARKS.md](TRADEMARKS.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), including the DCO sign-off
requirement and the ground rules (no network calls on the inline path, all
logging through `toLogRecord`, no site-specific selectors, no new
dependencies).
