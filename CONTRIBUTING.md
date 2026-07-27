# Contributing to Wardkeep

Thanks for considering a contribution. This project is small, the
maintainer is one person plus AI agents, and the priorities below exist to
keep the codebase trustworthy for something that touches sensitive customer
data — please read the ground rules before sending a PR.

## Sign off your commits (DCO, not a CLA)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a contributor license agreement. It's a statement, added to your
commit message, that you wrote the contribution or otherwise have the right
to submit it under the project's license.

Sign off every commit with `git commit -s`, which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use your real name and a working email — anonymous or pseudonymous
sign-offs aren't accepted. PRs with unsigned commits will be asked to
amend (`git commit --amend -s`, then force-push the branch) before merge.

## Ground rules

These are non-negotiable because they're the load-bearing claims the whole
product makes to customers about privacy:

1. **The inline path never calls a network API.** No `fetch`, `XMLHttpRequest`,
   `WebSocket`, `sendBeacon`, or similar in the content-script/policy-engine
   evaluation path. CI enforces this with a no-egress gate; a PR that trips
   it needs a documented exception, not a workaround.
2. **All logging goes through `toLogRecord`; all model-visible text goes
   through `toUserMessage`.** If you add a new place that might log
   something, it must construct that record via `toLogRecord`, not an ad hoc
   object. If you add text that a model or user sees (hook stderr, MCP error
   messages), it must go through `toUserMessage`. These are the two privacy
   gates that guarantee no matched content leaks.
3. **No site-specific CSS selectors** in the content script. Interception is
   selector-less (capture-phase key/submit handling) on purpose — selectors
   break on every redesign and turn into an unmaintainable per-site list.
4. **No new npm dependencies** without discussing it in an issue first. The
   policy engine is dependency-free by design; the extension's dependency
   surface is deliberately tiny because it runs in every employee's browser.
5. **TypeScript for all extension and engine code.** No plain JS additions.

## Test fixtures for a DLP tool

This project's test corpus is inherently made of credential-shaped strings —
that's the point, we're testing a detector for them. That collides with
GitHub's scanners, which can't tell a fixture from a leak:

- **Push protection** blocks the push outright when a commit contains a
  string shaped like a live API key (Stripe `sk_live_...`, etc.).
- **Secret scanning** fires a post-push alert for connection strings and
  similar shapes it doesn't push-protect on, indistinguishable in the alert
  inbox from a real leaked credential.

A blocked push is a bad day; a false alert is worse, because it trains
whoever triages alerts to expect noise and skim past the next one.

**The rule:** a test fixture that is shaped like an API key, token,
connection string, or private key must be **assembled at runtime from
parts** — never written as a scanner-matchable literal in source — with a
brief comment explaining why it's built that way. For example, build a
Stripe-shaped key as `` `sk_${"live"}_${body}` `` rather than the literal
`sk_live_...` string, or assemble a connection string's `user:pass@host`
segment from separate variables instead of writing the full URI inline.

**Card numbers and IBANs are exempt** — write them as plain literals. They
have to be checksum-valid (Luhn for cards, mod-97 for IBANs) for the
detector tests to be meaningful, and neither push protection nor secret
scanning flags them, so there's no scanner to appease and no benefit to
obscuring them. The de-literalization rule targets API keys, auth tokens,
connection strings, and private key blocks specifically — the shapes GitHub
actually scans for.

CI enforces this with a fixture-hygiene grep over the test directories; see
`.github/workflows/ci.yml`.

## Running tests locally

```bash
npm install
npm run typecheck            # tsc --noEmit for extension + CLI
npm run build:extension
npm test                     # builds engine + CLI, runs both test suites
```

`npm test` builds `packages/policy-engine` and `apps/cli`, then runs
`node --test` for both (includes the benchmark gate on evaluation latency).
Please run all three before opening a PR — CI runs the same commands plus a
no-egress check on the built bundles.

## Pull requests

- Keep PRs scoped to one change; explain the "why" in the description.
- Add or update a test for behavior changes, especially detector logic or
  anything touching `toLogRecord`.
- If your change touches the extension's declared permissions or
  `managed_schema.json`, call that out explicitly — it changes what admins
  and the Chrome Web Store review see.

## Reporting security issues

Do not open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) for the private reporting process.
