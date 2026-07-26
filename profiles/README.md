# Pilot profiles: Observe → Warn → Enforce

`pilot-observe.json`, `pilot-warn.json`, `pilot-enforce.json` implement the rollout the pilot
playbook (`docs/NEXT_PLAN.md` W7) sells: 2 weeks observe, 4 weeks warn, then enforce. All three
scope to the 7 default hosts (`content_scripts[0].matches` in `apps/extension/manifest.json`),
`logging: "event"`, `retentionDays: 90`. `onError` is `"open"` for observe/warn (availability
first while trust is being built) and `"closed"` for enforce (strictness first, once the org has
committed). All three validate against `parsePolicy` — see "Validation" below.

## The `observe` action

`pilot-observe.json` uses the engine's `"observe"` action on every detector: the finding is
recorded (it reaches `toLogRecord` and the event buffer like any other) but the user is never
interrupted — no dialog, no `preventDefault`, the send/paste/upload proceeds untouched
(`apps/extension/src/content.ts` short-circuits observe-only results after logging). This is
what makes the two-week baseline genuinely silent, which the Exposure Check's credibility
depends on.

History note: an earlier revision of this profile used `"warn"` everywhere because a true
log-only action didn't exist yet (`"allow"`-actioned matches never become findings, so an
all-allow policy logs nothing). The `"observe"` action closed that gap; if you are diffing old
exports against new ones, week-1 event counts are comparable but old deployments showed dialogs
where new ones don't.

## `bulk_pii`

All three profiles carry `bulkPiiThreshold: 5` and a `bulk_pii` rule. The detector is a
post-pass in `packages/policy-engine/src/engine.ts`: distinct matched strings across
`email`/`iban`/`credit_card`/`phone`/`at_svnr` are counted **before** the allow-filter (so
individually-allowed emails still count toward the threshold), and at the threshold a
synthetic `bulk_pii` finding fires with the profile's configured action. Covered by the
`bulk_pii` tests in `packages/policy-engine/test/fp-corpus.test.ts` (threshold boundary,
distinct-vs-repeated matches, allow interaction, redact semantics, log-record categories).

## Validation

All three files are validated against the built engine's `parsePolicy()` (profiles are data,
not code — validation is a `node -e` run against `packages/policy-engine/dist`, reproducible
with `npm run build:engine`):

```
pilot-observe.json  -> parsePolicy OK (name: "Pilot — Observe (weeks 1–2)", 7 rules)
pilot-warn.json     -> parsePolicy OK (name: "Pilot — Warn (weeks 3–6)", 7 rules)
pilot-enforce.json  -> parsePolicy OK (name: "Pilot — Enforce (week 7+)", 7 rules)
```

`parsePolicy` validates schema (types, required fields, action enums — including `"observe"`),
not that every listed detector does something at runtime.
