# PromptWarden — Next 90 Days (2026-07-27 → 2026-10-31)

Synthesized from a three-lens panel (pilot-first GTM, product/engineering GA, EU compliance) run 2026-07-25.
Decision date: **Thu 2026-10-29** (Mon 10-26 is the Austrian Nationalfeiertag).

## Thesis

The kill criterion (2 MSPs or 3 design-partner orgs, 50+ seats, by 2026-10-31) is a sales
outcome, so the plan is a sales plan that engineering serves. Three facts shape everything:
(1) DACH August is dead — the real selling window is Sep 1 → Oct 31, so weeks 1–5 build
assets and book September; (2) the works-council clock (4–12 weeks) is longer than the code
clock, so the Betriebsvereinbarung template is handed over at the **first** discovery call,
not at signing; (3) the repo's zero-egress property — no network API anywhere, `permissions:
["storage"]`, `host_permissions: []` — is the entire moat, so nothing in this window may add
server-side egress. The funnel runs on one asset: a free 7-day **Shadow-AI Exposure Check**
(event-mode logging, local export, founder-compiled 1-page report) that quantifies the
prospect's own pain in their own numbers. No console, no ingest backend, no AI tier until a
signature forces them.

**Conflict resolutions (material):** the Exposure Check is delivered via *local* event
export, not an ingest endpoint — merges plan 1's funnel with plan 3's zero-processing
posture and deletes plan 2's W5 ingest/Neon/Worker week. Console Lite exists only behind a
signed-pilot gate (W10 GO/NO-GO). Ed25519 = offline signature *verification* of admin-pasted
policy, decision-gated at W7; the phantom `policyUrl` key is deleted from
`managed_schema.json` before the first public tag (documented capability with no code behind
it — a DPO reads the schema and the store declaration turns murky).

## Pre-registered kill bar (write `docs/DECISION_2026-10-31.md` on day 1, never edit)

A commitment counts only as: signed pilot agreement + org legal entity + seat count ≥ 50 +
start date before 2026-12-15 + named exec sponsor and IT owner + deployment method +
documented works-council status, and **either** a paid pilot fee (€1,500, credited to year 1)
**or** a written convert-or-decline date. An MSP counts only with a named ≥50-seat end-client
and a scheduled deployment date. Enthusiasm scores zero.

## Workstreams

| # | Workstream | Owner | Time/wk |
|---|---|---|---|
| A | Outbound & pipeline (MSP + direct-org) | **Founder only** | ~18h from W3 |
| B | Sales assets (Exposure Check, demo, playground) | Founder + agents | ~6h |
| C | Repo credibility & correctness (license, CI, fixes) | **Agent-delegable** | W1–2 burst |
| D | Distribution (Web Store, Edge, force-install docs) | Agent-delegable, founder verifies | ~5h |
| E | Trust pack (DPIA, Betriebsvereinbarung, data sheet) | Founder + lawyer (5h, ~€1,200–2,500) | ~4h |
| F | Pilot delivery | Founder | 0 → 10h from W8 |

Cadence from W3: Mon–Wed = selling, no code before 15:00. Thu–Fri = building.
Friday: update `docs/SCOREBOARD.md`, committed.

## Week-by-week

| Wk | Dates | Deliverables (owner) | Demoable artifact |
|---|---|---|---|
| **W1** | 07-27→08-02 | Kill bar committed. Apache-2.0 `LICENSE`+`NOTICE`+`TRADEMARKS.md`, `SECURITY.md`, DCO. Fix false doc claims (no CI exists; "14 tests" → 20). Fix 3 correctness holes: click-path `activeEditable(null)` no-op (track last-focused editable via `focusin`), stale `bypassNextSubmit` gate (expire on timer + input), missing `submit` listener — one regression test each (C). Real CI: tsc → tests → bench gate → **no-egress gate** (fails on any network API outside dist/). Delete `policyUrl` from managed_schema. Icons 16–128. **Repo public.** Chrome Web Store account + submit **unlisted** (locks extension ID, starts the longest clock). Sending domain + SPF/DKIM/DMARC warmup. **Book the Austrian Arbeitsrecht+Datenschutz lawyer for W5 now** — AT firms close in August. Warm-network sweep: 20 intro paths, 8 asks. | Public repo, green CI, threat model |
| **W2** | 08-03→08-09 | `docs/THREAT_MODEL.md` (what we honestly don't stop). Event export (JSON from popup) + `tools/pwreport` → 1-page HTML/PDF — **the Exposure Check pipeline**. Landing page (zero cookies, self-hosted fonts, Impressum, `/trust` page). 3-min demo video. 40 MSP + 40 direct-org named prospects (WKO, MS Partner directory, RMM partner finders; 5–50-employee MSPs). Signed release v0.2.0 (cosign keyless + provenance). **Gate G1.** | Exposure Check report from own devices |
| **W3** | 08-10→08-16 | Cold sequence live (12 MSPs/wk, 6 touches, German, AI-Act hook — verify the 08-02 applicability scope before using it in copy). Force-install docs: Google Admin + Intune, copy-pasteable, **verified on a real managed profile** — incl. self-hosted CRX fallback so pilots never depend on store review. Weekly Playwright smoke across 7 hosts (local CI, no egress). Popup "Problem melden" → prefilled GitHub issue. Detector precision: BIN gating on credit_card, false-positive corpus test (invoice/order/tracking numbers must not fire), `bulk_pii` detector (N+ distinct PII in one payload — maps to "someone pasted our customer list"). | "50 seats in 10 minutes" screen recording |
| **W4** | 08-17→08-23 | **Options page = local-first policy builder** (rules table, live preview on the real engine, import/export, "Copy for Google Admin" button; read-only under managed policy) — same code shipped as public **/playground** URL (zero-install cold-email asset). Edge Add-ons submitted (same package; DACH = Microsoft/Intune shops). Trust pack core: TP-01 data-flow, TP-08a zero-processing statement, DSFA threshold + template, ROPA block, TOM. Pilot profiles: observe/warn/enforce JSON. **Gate G2.** | Playground URL |
| **W5** | 08-24→08-30 | **Lawyer review** (booked W1): DSFA, Betriebsvereinbarung AT (below ArbVG §96(1)Z3: event-only, no content, no individual attribution, MIN_COHORT 5, no-disciplinary-use) + DE variant (BetrVG §87(1) Nr. 6 assumed to apply), employee Art. 13 one-pager, pilot agreement. German UI strings (`chrome.i18n`, de-AT). `retentionDays` age-based pruning + user-clear in standalone (both are DPIA line items). `PRIVACY_DATA_SHEET.md` **generated from the `toLogRecord` field list with a test asserting doc matches code**. Book September hard. | Lawyer-reviewed trust pack v1.0 |
| **W6** | 08-31→09-06 | Trust pack published at `/trust` (DE+EN). Show HN + r/msp methodology post (1 day, credibility not pilots). Pitch 2 speaking slots (Steuerberater/UBIT events). First Exposure Checks at friendly orgs. 2 pilot proposals out. **Gate G3.** | Live trust page + install count |
| **W7** | 09-07→09-13 | **Selling window opens.** Outbound blitz. Ed25519 **decision gate**: build offline verify only if an evaluating MSP asked; else ship `docs/POLICY_INTEGRITY.md`. Pilot playbook (observe 2wk → warn 4wk → enforce). Pre-book it-sa Nürnberg meetings (visitor, no booth — verify dates). **Gate G4-channel.** | Pilot playbook |
| **W8** | 09-14→09-20 | 8 Exposure Checks delivered; aggregate hit rates. Ship whatever the first evaluator is blocked on, same week. v0.3.0. **Gate G5 — the product-truth + dogfood gate (most important in the plan).** | "Asked Monday, shipped Friday" |
| **W9** | 09-21→09-27 | Referral ask on every delivered Check. Proposals #3–4. One distributor conversation (2h cap, 2027 option). Report v2 with fields evaluators asked for. | Two orgs' reports side by side |
| **W10** | 09-28→10-04 | First pilot onboarding: force-install push, tuned profile, employee one-pager distributed, **works-council process formally started**. Console GO/NO-GO — GO only if a signed pilot explicitly needs central visibility; otherwise local export carries it. `pw-doctor` self-diagnosis page (policy applied? hosts enforced?). **Gate G6.** | Live pilot, seats enrolled |
| **W11** | 10-05→10-11 | it-sa week: 15+ pre-booked meetings, 24h follow-up discipline. Pilot support. | — |
| **W12** | 10-12→10-18 | Feature freeze. Decision packet: funnel numbers, installs, pilot status, honest W14 call. **Gate G7.** | Decision packet |
| **W13** | 10-19→10-25 | Zero new code. Close: e-signature, walk their DPO through the DSFA, month-to-month. Written email confirming seats + date satisfies the bar. | — |
| **W14** | 10-26→10-31 | **Thu 10-29: score `docs/DECISION_2026-10-31.md` against the pre-registered bar. Publish the verdict. No relitigating.** | The decision |

## Gates (all before the kill date; each with a named action on miss)

| Gate | Date | Must be true | On miss |
|---|---|---|---|
| G1 | 08-09 | Repo public, CI+no-egress green, store submission ID, domain warming, 80 named prospects | Bottleneck is founder execution — freeze engineering 2 weeks |
| G2 | 08-23 | 8 discovery calls, 3 Checks agreed, **≥10 September meetings booked**, store live or escalated | Thin September calendar is the real failure — phone-first + warm-intro-only for 2 weeks |
| G3 | 09-06 | 20 cumulative calls, 5 Checks in flight, 150 installs or 25 stars, 2 proposals | Change ICP (MSP↔direct, AT↔DE), not the product |
| G4-channel | 09-13 | ≥8 calls held, ≥4 prospects name their real blocker, ≥1 unprompted trust-pack request | Channel is wrong — pivot to direct-to-vertical NOW, 7 weeks left to act |
| **G5** | 09-20 | **8 Checks delivered AND median exposure ≥5 sensitive hits per 10 users/week AND ≥2 MSPs running it on their own machines**; ≥1 signed | **Exposure near zero → the pain doesn't exist; selling harder can't fix it — this is the kill signal 6 weeks early.** No dogfood → freeze features, 100% GTM W9–14 |
| G6 | 10-04 | 2 signed (any mix), 6 proposals, 15 it-sa meetings booked | Draft the stop memo in parallel while still selling |
| G7 | 10-18 | Criterion met or 3 signed-in-principle | Two weeks pure closing — no new pipeline, no code |
| KILL | 10-29 | 2 MSPs (named end-clients) or 3 orgs ≥50 seats | Stop. Publish post-mortem. Hand repo to maintainers rather than let it rot. |

## Deliberately NOT building

- **Phase-2 console** (RLS, msp→org→profile→enrollment, OIDC, SCIM, hosted editor) — local export + founder-run reports carry pilots; real console gets built in November from actual pilot complaints, behind signature #2.
- **Phase-3 AI audit tier** — requires `logging:"content"`, i.e. the exact thing that turns a pilot into a legal review. Founder writes monthly reports with Claude manually; that teaches the eventual prompt. Future gate: EU-region model endpoint, verified not assumed.
- **Any server-side telemetry/ingest** — one endpoint converts a zero-processing product into a data-processing one and destroys the moat. Local export + GitHub issue instead.
- **Firefox port** — Edge Add-ons instead (same MV3 package, Intune-native, the actual DACH fleet).
- **Ed25519 policy signing as scheduled work** — managed storage is already the trust anchor; decision-gated W7, offline-verify only, never fetching.
- **Billing/Stripe** — pilots are paid by invoice or free-for-reference; no payment code.
- **Error-tracking/analytics SDKs in the extension** — contradicts the claim that is the product.
- **UI frameworks, i18n frameworks, email pipelines, new detectors beyond named-prospect requests** (DACH-specific ones ship in 2h when asked), **pen test** (€2k independent code review letter instead), **certifications** (readiness statement + pre-answered questionnaire), **pricing page** (design-partner framing).
- Stays cut from the panel: TLS-intercepting agent, self-hosted console, direct-to-SMB as primary motion.

## Next 5 actions (week of Mon 2026-07-27)

1. **Mon AM — lock the bar, fix the lies, go public.** `docs/DECISION_2026-10-31.md`; Apache-2.0 + NOTICE + TRADEMARKS.md + SECURITY.md; correct README ("14 tests"→20) and ENGINEERING_PLAN (phantom CI); delete `policyUrl` from managed_schema; push public with real CI incl. the no-egress gate. ~4h, mostly agent-delegable.
2. **Mon PM — start the two uncontrollable clocks.** Chrome Web Store: account, icons, DE+EN copy, permission justification, upload **unlisted**. Sending domain live, SPF/DKIM/DMARC, warmup started. ~4h.
3. **Tue — book the lawyer and the entity check.** Austrian Arbeitsrecht+Datenschutz lawyer, 5h slot week of Aug 24; confirm contracting entity + 3 IT-Haftpflicht quotes. Both are August-blocked and procurement-fatal if discovered in W12. ~2h.
4. **Tue–Wed — fix the 3 correctness holes + warm sweep.** Click-path fallback via `focusin` tracking, `bypassNextSubmit` expiry, `submit` listener, regression tests (agents). In parallel: 20 warm intro paths written down, 8 asks sent, 80-name prospect list started (agents research, founder judges). ~8h.
5. **Thu–Fri — build the funnel asset.** Event export + `pwreport` 1-page report; 3-min demo video; landing page with `/trust` skeleton. First 12 warm sends go out Friday. Cold waits for warmup (W3). ~10h.

## Risks

| Risk | Mitigation |
|---|---|
| Store review stalls past W6 | Unlisted upload W1 (ID assigned immediately), Edge parallel, self-hosted CRX force-install verified W3 — store off the pilot critical path |
| False positives kill a live pilot | BIN gating + FP corpus test W3, observe-first rollout, per-pilot regex within 24h, `bulk_pii` for the real fear |
| Works council blocks deployment | Below-§96(1)Z3 default config, lawyer-reviewed BV template handed over at call #1, target low-density sectors (Steuerberater, Lohnverrechnung, Personaldienstleister, Makler) |
| August eats the window | W1–5 = assets + booking September; G2 measures the September calendar, not August calls |
| Founder builds instead of sells | Mon–Wed no code before 15:00; W8 dogfood gate forces the freeze decision while there's time to act |
| Wrong regulatory claim in outbound | Verify AI-Act 08-02 scope, it-sa dates, NISG status before use; landing-page claim matrix (no "DSGVO-konform", no unheld marks) — UWG-actionable and conversation-ending |
| MSP demands the console before signing | Static clickable prototype + "roadmap gated on your signature"; founder-delivered monthly reports free in the interim |

**Budget:** lawyer €1,200–2,500 · store fees ~$25 · domain/email €80 · it-sa ticket+hotel €600 · Sales Navigator €300 · code-review letter ~€2,000 (W6, optional until an MSP asks) ≈ **€4,500 ceiling**.
