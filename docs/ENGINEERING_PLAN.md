# PromptWarden — Architecture & Engineering Ground Rules

An open-source, browser-first guardrail that warns, redacts, or blocks sensitive data
(credit cards, IBANs, social-insurance numbers, API keys, bulk PII) before it leaves the
browser for AI chat sites. Everything runs locally; nothing ever leaves the device.

## Architecture

```
┌──────────────────────────────────────┐
│  Browser (user's device)             │
│  ┌────────────────────────────────┐  │
│  │ MV3 extension                  │  │
│  │  content script (selector-less │  │
│  │   interception: enter, click,  │  │
│  │   paste, file upload, drop)    │  │
│  │  policy engine (pure TS)       │  │
│  │  guardrail UI                  │  │
│  │  popup: event log + aggregate  │  │
│  │   export (day-bucketed counts) │  │
│  └────────────────────────────────┘  │
│  Policy: managed storage (admin) >   │
│  local storage > built-in default    │
│  Events: chrome.storage.local only — │
│  no ingest endpoint exists           │
└──────────────────────────────────────┘
```

- `packages/policy-engine` — policy schema, detectors (checksum-validated: Luhn + issuer
  prefixes for cards, mod-97 for IBANs, check digit for Austrian SVNR), evaluation,
  `toLogRecord` as the single privacy gate, `bulk_pii` post-pass, Office (`.xlsx`/`.docx`)
  text extraction. Pure, DOM-free, dependency-free.
- `apps/extension` — MV3 extension: capture-phase interception with zero site-specific
  selectors, guardrail dialogs, managed-storage policy support, dynamic host coverage
  (`docs/HOST_COVERAGE.md`), popup with event log and k-anonymity-friendly aggregate export.
- `profiles/` — example policy documents.
- `tools/e2e-smoke.mjs` — live-browser regression against real AI sites.

## Engineering ground rules

- **The inline path never calls a network or an LLM. Ever.** Deterministic, <10 ms on a
  10 KB prompt (enforced by a CI bench gate; currently ~0.06 ms).
- **All privacy decisions route through `toLogRecord`** — new logging surfaces are
  PR-blocked unless they use it. Event mode provably contains no content (tested).
- **Zero egress is machine-verified**: CI greps source and built bundles for every network
  API and fails the build on a hit. `permissions: ["storage"]`, `host_permissions: []`.
- **No site-specific CSS selectors in the content script** — interception is generic
  (word-predicate send buttons, capture-phase events), so AI-site redesigns don't break it.
- **No new runtime dependencies.** The extension and engine use platform APIs only.
- Signed releases + `SECURITY.md` + coordinated disclosure from the first public tag.

## Status

Engine and extension are functional and live-verified (see `tools/e2e-smoke.mjs`). Not yet
scanned: PDF and legacy binary Office formats (documented in `docs/THREAT_MODEL.md`).
Store listings not yet published. See open issues for the roadmap.
