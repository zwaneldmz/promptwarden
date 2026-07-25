# PromptWarden

Open-source guardrails for AI chat. Warns, redacts, or blocks sensitive customer
data (IBANs, card numbers, social insurance numbers, API keys, org-specific IDs)
before it leaves the browser for ChatGPT, Claude, Gemini, Copilot, and others.

Built browser-first for SMBs and the MSPs who serve them. Privacy-preserving by
default: standalone mode logs nothing; managed mode defaults to event-level
records that provably contain no prompt content.

## Repository layout

```
packages/policy-engine   Dependency-free TS library: policy schema, detectors
                         (Luhn, IBAN mod-97, AT SVNR check digit, API keys),
                         evaluation, privacy-gated logging. 20 tests.
apps/extension           Manifest V3 extension: selector-less interception,
                         guardrail UI, managed-storage policy support.
profiles/                Example org profiles (healthcare, accounting).
docs/                    Engineering plan and architecture notes.
```

## Build & test

```bash
npm install
(cd packages/policy-engine && ../../node_modules/.bin/tsc && node --test 'dist/test/*.test.js')
node_modules/.bin/esbuild apps/extension/src/content.ts --bundle --format=iife \
  --outfile=apps/extension/content.bundle.js \
  --alias:@promptwarden/policy-engine=./packages/policy-engine/src/index.ts
node_modules/.bin/esbuild apps/extension/src/background.ts --bundle --format=iife \
  --outfile=apps/extension/background.js
```

Load `apps/extension/` as an unpacked extension in Chrome (chrome://extensions,
Developer mode). Type a Luhn-valid test card number into ChatGPT and press Enter
to see the guardrail.

## Managed deployment

Admins push a policy via Chrome Enterprise managed storage (Google Admin console
or Group Policy) using the `policy` key defined in
`apps/extension/managed_schema.json`. Managed policy always wins over local.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The "PromptWarden"
name is governed separately — see [TRADEMARKS.md](TRADEMARKS.md). Console and
audit tier (not yet built) are planned as separate, commercial components.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), including the DCO sign-off
requirement and the ground rules (no network calls on the inline path, all
logging through `toLogRecord`, no site-specific selectors, no new
dependencies).
