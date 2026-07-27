# PromptWarden — Architecture & Engineering Ground Rules

An open-source, browser-first guardrail that warns, redacts, or blocks sensitive data
(credit cards, IBANs, social-insurance numbers, API keys, bulk PII) before it leaves the
browser for AI chat sites. Everything runs locally; nothing ever leaves the device.

## Architecture

```
                       ┌─────────────────────────────────────┐
                       │  packages/policy-engine (pure TS)   │
                       │  detectors · evaluate · toLogRecord │
                       │  scanBytes · extractOfficeText      │
                       └──────────┬──────────────────────────┘
                                  │ imported by every surface
          ┌───────────┬───────────┼───────────┬──────────────┐
          ▼           ▼           ▼           ▼              ▼
   ┌────────────┐ ┌─────────┐ ┌────────┐ ┌──────────┐ ┌──────────┐
   │ MV3 ext.   │ │ CLI     │ │ Claude │ │ MCP      │ │ VS Code  │
   │ (browser)  │ │ scan    │ │ Code   │ │ gateway  │ │ ext.     │
   │            │ │         │ │ hook   │ │          │ │          │
   │ content    │ │ stdin / │ │ User   │ │ stdio    │ │ open/    │
   │ script,    │ │ files,  │ │ Prompt │ │ JSON-RPC │ │ save →   │
   │ popup,     │ │ exit    │ │ Submit │ │ proxy    │ │ Problems │
   │ options    │ │ codes   │ │ + Pre  │ │ (both    │ │ panel    │
   │            │ │         │ │ ToolUse│ │ dirs)    │ │          │
   └────────────┘ └─────────┘ └────────┘ └──────────┘ └──────────┘
   Policy:         Policy:                Policy:       Policy:
   managed >       /etc > env >           same as CLI   setting or
   local >         XDG > repo-local >                   built-in
   built-in        built-in
```

- `packages/policy-engine` — policy schema, 9 detectors (checksum-validated: Luhn + issuer
  prefixes for cards, per-country-length mod-97 for IBANs, check digit for Austrian SVNR,
  PEM structure for private keys, JWT header decode, API key prefix patterns, connection
  string URI/ODBC parsing), evaluation, `toLogRecord` and `toUserMessage` as the two
  privacy gates, `bulk_pii` post-pass, `scanBytes` for text + Office (`.xlsx`/`.docx`)
  extraction. Pure, DOM-free, dependency-free.
- `apps/extension` — MV3 Chrome extension: capture-phase interception with zero
  site-specific selectors, guardrail dialogs (closed ShadowRoot), managed-storage policy
  support, dynamic host coverage (`docs/HOST_COVERAGE.md`), popup with event log and
  day-bucketed aggregate export, options page with live policy editor.
- `apps/cli` — CLI tool: `scan`, `hook claude-code`, `mcp` gateway,
  `emit-exclusions`. Zero runtime dependencies, esbuild-bundled.
- `apps/vscode` — VS Code extension: diagnostics in the Problems panel from the same
  engine. Does not intercept Copilot/Cursor.
- `apps/playground` — Standalone policy editor + live preview. Single HTML file, no
  backend. Same policy-editor module powers the extension's options page.
- `profiles/` — example policy documents (accounting firm, healthcare).
- `tools/e2e-smoke.mjs` — live-browser regression against real AI sites.

## Engineering ground rules

- **The inline path never calls a network or an LLM. Ever.** Deterministic, <10 ms on a
  10 KB prompt (enforced by a CI bench gate; currently ~0.06 ms).
- **All privacy decisions route through `toLogRecord`; all model-visible text routes
  through `toUserMessage`** — new logging or user-facing surfaces are PR-blocked unless
  they use the appropriate gate. Event mode provably contains no content (tested).
- **Zero egress is machine-verified**: CI greps source and built bundles for every network
  API and fails the build on a hit. `permissions: ["storage"]`, `host_permissions: []`.
- **No site-specific CSS selectors in the content script** — interception is generic
  (word-predicate send buttons, capture-phase events), so AI-site redesigns don't break it.
- **No new runtime dependencies.** The extension and engine use platform APIs only.
- Signed releases + `SECURITY.md` + coordinated disclosure from the first public tag.

## Status

Engine, browser extension, CLI (scan + hook + gateway + emit-exclusions), MCP gateway,
and standalone playground are functional. The browser extension is live-verified (see
`tools/e2e-smoke.mjs`). The VS Code extension typechecks but has not been launched in
VS Code. Not yet scanned: PDF and legacy binary Office formats (documented in
`docs/THREAT_MODEL.md`). Chrome Web Store listing not yet published. See
`docs/ROADMAP.md` for what's next.
