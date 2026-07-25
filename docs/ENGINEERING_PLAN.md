# PromptWarden — Engineering Plan

Plan authored by Claude Fable 5, incorporating the panel review of 2026-07-25. Model roles for the product's AI tier are assigned to Claude Sonnet 4.6 and Claude Opus 4.8 (there is no "Sonnet 5"/"Opus 5"; these are the current API models).

## Product thesis

An open-source, browser-first AI data guardrail for SMBs handling sensitive customer data, sold through MSPs, with EU-native privacy defaults. The inline path is deterministic and local; LLMs appear only in the opt-in, batch audit tier.

## Revised architecture (post-panel)

```
┌────────────────────────────┐        ┌──────────────────────────────┐
│  Browser (employee device) │        │  Console (paid, multi-tenant)│
│  ┌──────────────────────┐  │  HTTPS │  MSP → Org → Profile → Device│
│  │ MV3 extension        │◄─┼────────┤  Policy CRUD + signing       │
│  │  content script      │  │ policy │  Event ingest (pseudonymous) │
│  │  policy engine (OSS) │──┼───────►│  Compliance exports          │
│  │  guardrail UI        │  │ events │  AI audit tier (opt-in)      │
│  └──────────────────────┘  │        │   Sonnet 4.6: classification │
│  Managed storage ◄─ GPO/   │        │   Opus 4.8: weekly synthesis │
│  Google Admin force-install│        └──────────────────────────────┘
└────────────────────────────┘
```

Explicitly cut from v1 (panel decision): device-level TLS-intercepting agent (cert pinning + 3-OS maintenance economics), self-hosted console at launch (becomes paid enterprise tier in phase 4+), direct-to-SMB sales motion as primary.

## Open/paid boundary

Free (Apache-2.0 or MPL-2.0 — decide before first release):
- `packages/policy-engine` — schema, detectors, evaluation, privacy-aware logging
- `apps/extension` — full interception + guardrail UX, local policy file, managed-storage support
- Example profiles

Paid:
- Multi-tenant console (MSP roles, SSO/SCIM, policy signing + distribution)
- Central event ingest, dashboards, compliance evidence exports (GDPR/HIPAA-adjacent)
- AI audit tier (below)
- DPIA template + Austrian works-council (ArbVG §96) agreement template
- Self-hosted console (enterprise tier, later)

Boundary rule: anything a single privacy-conscious individual needs is free; anything that only makes sense when managing other people is paid.

## Phases

### Phase 0 — Policy engine (weeks 1–2) ✅ built in this session
- Policy schema v1: hosts, rules, actions (allow/warn/redact/block), logging modes (off/event/content)
- Detectors with checksum validation: credit card (Luhn), IBAN (mod-97), Austrian SVNR (check digit), structured API keys, email, phone
- Custom regex rules for org-specific identifiers
- `toLogRecord` as the single privacy gate — event mode provably contains no content (tested)
- 20 passing tests; CI (`.github/workflows/ci.yml`): `npm test` (builds the engine, runs
  `node --test`, includes the <10ms benchmark gate), `npm run build:extension` (esbuild), and a
  no-egress gate that greps the extension/engine source and the built bundles for
  `fetch`/`XMLHttpRequest`/`sendBeacon`/`WebSocket`/`EventSource`/dynamic `import()` and fails
  the build if any are found

### Phase 1 — Extension (weeks 3–6) ✅ skeleton built in this session
- MV3, selector-less interception (capture-phase Enter + generic submit-button click)
- Policy precedence: managed storage > local; managed schema for Google Admin / GPO
- Guardrail UI: redact-and-continue / send-anyway / cancel; block state for hard stops
- Remaining for GA: paste-event scanning, file-upload interception, Firefox port,
  breakage telemetry dashboarding, signed policy verification (Ed25519), Web Store listing,
  force-install deployment docs for Google Admin and Intune
- Latency budget: < 10 ms evaluation on 10 KB prompts (measure in CI with a benchmark)

### Phase 2 — Console (weeks 5–10)
- Stack: Next.js + Postgres (row-level security for tenancy), hosted in EU region
- Tenancy model from migration 001: `msp → organization → profile → enrollment`
- Policy editor with live preview against sample prompts; versioned, signed policy documents
- Event ingest: batched, pseudonymous device ids, retention configurable per org (default 90 days)
- SSO (OIDC) for admins; SCIM deferred to phase 4

### Phase 3 — AI audit tier + pilot (weeks 9–12)
- Opt-in per org, off by default, requires `logging: "content"` legal basis acknowledgment
- Claude Sonnet 4.6 (batch): classify events into risk categories (customer PII, financial,
  credentials, contract text), estimate severity — high volume, low unit cost, prompt-cached
- Claude Opus 4.8 (weekly): synthesize the compliance narrative per org, propose policy
  tightening ("3 users repeatedly warn-bypassed IBAN sends → suggest redact"), draft the
  MSP-facing monthly report — low volume, high judgment
- Design-partner pilot: 2 MSPs or 3 direct orgs, 50+ seats

### Kill criterion
If by **2026-10-31** no two MSPs or three design-partner orgs have committed to a 50+ seat
pilot, stop building and re-validate the go-to-market before writing more code.

## Engineering ground rules
- The inline path never calls a network or an LLM. Ever.
- All privacy decisions route through `toLogRecord`; new logging surfaces are PR-blocked
  unless they use it.
- No site-specific CSS selectors in the content script; breakage telemetry is category-level only.
- Signed releases + SECURITY.md + disclosure policy from the first public tag.
