# Contributing to PromptWarden

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
2. **All logging goes through `toLogRecord`.** If you add a new place that
   might log something, it must construct that record via `toLogRecord`, not
   an ad hoc object. This is the single privacy gate that guarantees
   event-mode logs provably contain no prompt content.
3. **No site-specific CSS selectors** in the content script. Interception is
   selector-less (capture-phase key/submit handling) on purpose — selectors
   break on every redesign and turn into an unmaintainable per-site list.
4. **No new npm dependencies** without discussing it in an issue first. The
   policy engine is dependency-free by design; the extension's dependency
   surface is deliberately tiny because it runs in every employee's browser.
5. **TypeScript for all extension and engine code.** No plain JS additions.

## Running tests locally

```bash
npm install
npx tsc -p apps/extension/tsconfig.json --noEmit
npm run build:extension
npm test
```

`npm test` builds `packages/policy-engine` and runs its `node --test` suite
(includes the benchmark gate on evaluation latency). Please run all three
before opening a PR — CI runs the same commands plus a no-egress check on
the built extension bundle.

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
