# PromptWarden

Browser guardrails for AI chat. PromptWarden warns, redacts, or blocks
sensitive data (IBANs, card numbers, social insurance numbers, API keys,
org-specific IDs) before it leaves the browser for ChatGPT, Claude, Gemini,
Copilot, and others. File uploads are scanned too, including plain text and
Office Open XML attachments (.xlsx, .docx) — all locally, with no network
call.

## How it works

A content script intercepts submit actions (Enter, click-to-send, paste) on
supported chat sites before the text is sent. Each candidate string runs
through a dependency-free detector library (Luhn/issuer-prefix credit card
check, IBAN mod-97, API key patterns, and more) evaluated against a policy
that decides warn, redact, or block per data type. Logging defaults to off
and, where a managed policy turns it on, is privacy-gated to structured
event records (category + host + timestamp) that provably contain no prompt
text.

## Install

The extension isn't yet published to the Chrome Web Store. To run it
locally:

1. `npm install` and build (see [Build](#build) below).
2. Open `chrome://extensions`, enable Developer mode.
3. Click "Load unpacked" and select `apps/extension/`.
4. Type a Luhn-valid test card number into a supported chat site and press
   Enter to see the guardrail.

## Repository layout

```
packages/policy-engine   Dependency-free TS library: policy schema, detectors,
                         evaluation, privacy-gated logging. Tested (`npm test`).
apps/extension           Manifest V3 extension: content-script interception,
                         guardrail UI, managed-storage policy support.
profiles/                Example org policy profiles.
docs/                    Architecture notes.
```

## Build

```bash
npm install
npm run build:engine
npm run typecheck
npm run build:extension
npm test
```

## Managed deployment

Admins can push a policy via Chrome Enterprise managed storage (Google Admin
console or Group Policy) using the `policy` key defined in
`apps/extension/managed_schema.json`. Managed policy always overrides local
settings.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The "PromptWarden"
name is governed separately — see [TRADEMARKS.md](TRADEMARKS.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), including the DCO sign-off
requirement and the ground rules (no network calls on the inline path, all
logging through `toLogRecord`, no site-specific selectors, no new
dependencies).
