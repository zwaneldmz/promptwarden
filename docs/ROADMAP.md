# Roadmap

Scope: what to fix before anyone deploys this to a fleet, and how PromptWarden's policy engine
reaches surfaces outside the browser. Ground rules in
[ENGINEERING_PLAN.md](ENGINEERING_PLAN.md) are binding; where an item here would bend one, it
says so explicitly instead of quietly taking an exception.

Ordering in "Now" is risk reduction per unit of effort, not severity alone. Line numbers are
omitted deliberately — they rot; the named symbol is the anchor.

---

## 1. Now (security + ops fixes)

### 1.1 Fleet-silent failures — enforcement looks green and does nothing

1. **`hosts:["*"]` in the deploy docs matches no host, so a fleet that pastes the documented
   policy enforces nothing while the popup still says "Managed by your organization".**
   `hostMatches` has no bare-wildcard branch (`*` neither starts with `*.` nor equals a
   hostname), so `enforcing()` is false everywhere: no interception, no logging, no signal.
   Fix the JSON in all three docs to the explicit host list, and in `parsePolicy` either
   reject a bare `"*"` with a readable error or support it as "all hosts" — pick one.
   `docs/DEPLOY_GPO.md`, `docs/DEPLOY_INTUNE.md`, `docs/DEPLOY_GOOGLE_ADMIN.md`,
   `packages/policy-engine/src/policy.ts` — **2–3h**

2. **A malformed managed policy fails open to the user-writable local policy with no
   diagnostic anywhere.** `resolvePolicy`'s empty `catch` swallows the `JSON.parse` throw and
   falls through to `chrome.storage.local` (privilege inversion: a broken admin push hands
   control to the area the user can write). The `policy-parse-error` report is unreachable by
   construction — at that instant `policy` is still `FALLBACK_POLICY`, whose `logging` is
   `"off"`, and `report()` returns early. Fail to the built-in default instead of local, mark
   the state errored, record the diagnostic, and gate diagnostic suppression on the *managed*
   policy's logging mode rather than on whichever fallback happens to be loaded — otherwise
   every policy-load failure is self-silencing. `apps/extension/src/background.ts`,
   `apps/extension/src/content.ts` — **0.5–1d**

3. **Make both of the above visible in five seconds on a helpdesk call.** Red "Policy error —
   contact IT" row in the popup plus `chrome.action.setBadgeText("!")`. The popup currently
   sets `managed = true` from the mere presence of the string while `policy` stays null, so it
   renders the managed badge over `standalone-default`, Rules 0, Hosts 0. Also note in
   `managed_schema.json` that Chrome validates only the string *type*, never the contents — a
   garbage policy passes `chrome://policy` with no error badge.
   `apps/extension/popup.js`, `apps/extension/popup.html`,
   `apps/extension/managed_schema.json` — **0.5d**

### 1.2 Bypasses and fail-open paths

4. **The guardrail UI lives in the page's own DOM under a fixed, well-known id, and the page
   controls it.** Three consequences from one root cause: `document.body.id =
   "promptwarden-guardrail"` makes the capture-phase click listener's self-exemption
   (`target.closest("#" + UI_ID)`) match every click, disabling the whole send-button path
   with no user action; a page `MutationObserver` can find the dialog by id and `.click()`
   "Send anyway"/"Upload anyway" (button handlers have no `isTrusted` gate) to self-approve
   the exact bypass the dialog exists to gate; and `#promptwarden-guardrail{display:none
   !important}` hides it. Fix: closed `ShadowRoot` on a host whose id is a per-load
   `crypto.randomUUID()`, keep a module-level reference, replace the id lookup with an
   identity check over `event.composedPath()`, gate `onPick` on `e.isTrusted`, and add a smoke
   case that sets `document.body.id` to the old constant and asserts interception still fires.
   `apps/extension/src/content.ts`, `tools/e2e-smoke.mjs` — **0.5–1d**

5. **Unscannable or oversized `.xlsx`/`.docx` uploads are released silently.** `scanFiles`
   returns `null` whenever `findings.length === 0`, discarding the `unreadable` count, so an
   all-unreadable scan is indistinguishable from a clean one: no dialog, no `log()`, no
   `report()`. `onError:"closed"` cannot help — it only catches a *rejected* promise and this
   path resolves. Trigger paths need no attacker: a >20 MB workbook (`MAX_OFFICE_FILE_BYTES`),
   Zip64, or any OOXML whose parts are not at the hardcoded `^xl/worksheets/sheet\d+\.xml$` /
   `^word/document\.xml$` names — part names are declared in `[Content_Types].xml`/`_rels`,
   not fixed by spec, so a renamed sheet part opens fine in Excel and is never scanned. Return
   a distinct `{ unscanned: n }` result, route it through `failClosed()`, always surface the
   "could not be scanned" dialog + diagnostic. Then resolve parts through the OPC manifest.
   The header comment's claim of "fail-open, but visibly so" is false today and must go.
   `apps/extension/src/file-scan.ts`, `apps/extension/src/content.ts`,
   `packages/policy-engine/src/extract-office.ts` — **1d** plumbing, **+1d** OPC resolution

6. **`bypassNextSubmit` is a 2-second global free-fire window, and the threat model claims the
   opposite.** For 2s after any "Send anyway", *any* submission passes unscanned — different
   text, different editable, the site's own queued-draft resend or network retry, or page
   script writing the textarea and dispatching an untrusted `input` (the disarm listener
   requires `isTrusted`, so synthetic input deliberately does not disarm). Replace the boolean
   with a single-use token bound to the trigger identity, the editable element, and a hash of
   the approved text, consumed on first match; keep the timer as an outer expiry. Correct
   `THREAT_MODEL.md`'s "only lets through the literal resumed submission" sentence to match
   whatever the code then guarantees. `apps/extension/src/content.ts`,
   `docs/THREAT_MODEL.md` — **2–4h**

7. **No `externally_connectable` and no sender check: any other installed extension can forge
   and evict DLP records.** With the key absent, all extensions may `sendMessage`. The
   `onMessage` listener ignores `sender`, stores `msg.record` verbatim ("already passed through
   `toLogRecord`" is only true of our own content script), and passes `msg.kind` straight to
   `recordDiagnostic` with no check against the declared union. 500 forged records evict every
   genuine event (`buf.slice(-max)`), erasing evidence and poisoning the aggregate a customer
   hands their DPO. Declare `"externally_connectable": { "ids": [], "matches": [] }`, reject
   `sender.id !== chrome.runtime.id` as the first line, validate `record` against the exact
   field set `toLogRecord` emits and `kind` against the literal union, drop the unused
   `"event"` alias. `apps/extension/manifest.json`,
   `apps/extension/src/background.ts` — **2–3h**

### 1.3 The privacy gate has two holes

8. **`logging:"content"` persists the entire prompt, not the matched text.** The `bulk_pii`
   post-pass synthesizes `{ start: 0, end: text.length, match: text }` and `toLogRecord`
   copies `f.match` verbatim, so one record holds the whole prompt — or, via `scanFiles`, the
   whole extracted text of a 20 MB spreadsheet. Both shipped profiles reach this state
   (`defaultAction:"warn"`, no `bulk_pii` rule). The redact branch already avoids the
   whole-text span; do the same for logging (store span length, not text) and cap per-finding
   `match` (≈64 chars, centred). `MAX_BUFFERED` caps entry *count*, never bytes, against a
   ~10 MB quota, and the resulting `set()` rejection is swallowed into `console.warn` — so a
   content-mode deployment stops recording at an unpredictable point. Add a byte budget to
   `appendCapped` and a `storage-write-failed` diagnostic. Render the effective logging mode as
   a first-class popup row with an explicit warning when it is `"content"`.
   `packages/policy-engine/src/engine.ts`, `apps/extension/src/background.ts`,
   `apps/extension/popup.html` — **1d**

9. **`pw-diagnostics` is a second persistence path that bypasses `toLogRecord`, ignores
   `retentionDays`, and the user cannot see or clear it.** It stores `{ kind, host, ts }` —
   a per-second record of which AI host the employee was on when a scan failed — written
   directly by `report()`/`recordDiagnostic`; `pruneExpired` and the startup prune only touch
   `EVENT_BUFFER_KEY`, and "Clear events" only clears `pw-events`. `extra-hosts-error` is
   recorded with no logging-mode check at all, so `logging:"off"` still produces writes.
   Add `toDiagnosticRecord(kind, policy)` next to `toLogRecord`, returning null when logging is
   off, and drop `host` — the reason codes are a closed set and none need a hostname to be
   actionable. Include the diagnostics key in both prune paths and in "Clear events". Update
   `THREAT_MODEL.md` to name both surfaces instead of claiming one.
   `packages/policy-engine/src/engine.ts`, `apps/extension/src/content.ts`,
   `apps/extension/src/background.ts`, `apps/extension/popup.js`,
   `docs/THREAT_MODEL.md` — **3–4h**

10. **Drop the k-anonymity claim; it is a per-device day-bucketed count table with cells of
    size 1.** `buildAggregate` applies no `k` and no small-cell suppression, so
    `{"2026-07-14":{"claude.ai":{"credit_card":{"block":1}}}}` is a per-event disclosure, and
    the file also carries `policyName`/`hosts`/`extensionVersion`. Rename it "day-level counts
    from this device" in code, popup hint and plan, and say in the hint that the export names
    sites and dates. Optional `k` suppression and week/month buckets can follow, default off.
    `apps/extension/popup.js`, `apps/extension/popup.html`,
    `docs/ENGINEERING_PLAN.md` — **2–4h**

11. **The "report a problem" link prefills `navigator.userAgent` into a public GitHub issue and
    builds the URL on every popup open.** The diagnostics half is well minimized; the UA is the
    one field that identifies the person rather than the bug, in a body whose realistic user
    action is "Submit". Replace with coarse platform + browser major version, build the URL
    lazily in the click handler, and prefer "copy diagnostics to clipboard" + a plain link.
    `apps/extension/popup.js` — **1–2h**

12. **Clamp `retentionDays`.** `parsePolicy` accepts `36500`, which turns a 90-day local buffer
    into an indefinite one from managed storage. Clamp to a documented maximum (365).
    `packages/policy-engine/src/policy.ts` — **30m**

### 1.4 Detection quality

13. **Secrets detection covers the harmless half.** `API_KEY_PATTERNS` is five regexes. Misses,
    measured: PEM private keys, JWTs, `sk_live_` (the `sk-` pattern requires a hyphen),
    `github_pat_`, `glpat-`, `ASIA` temp keys, Azure `AccountKey=…`, GCP service-account JSON,
    Slack webhooks, MSSQL `Server=…;Password=…`, bare `PASSWORD=`. `AKIA…` catches the AWS key
    *id* while the 40-char secret next to it is unmatched. `postgres://user:pass@host/db`
    registers only as `email` — mislabelled in the log, and `email` is `allow` in the shipped
    standalone default, so it passes. Add three detectors with their own ids (so an admin can
    set `private_key: block` without touching `email`): `private_key`
    (`-----BEGIN [A-Z ]*PRIVATE KEY-----`, zero plausible FP), `connection_string` (URI form
    with a populated password field, plus `(AccountKey|Password|Pwd)\s*=\s*\S{8,}`), and `jwt`
    (three base64url segments, then decode the header and require parseable JSON containing
    `alg` — a real checksum-equivalent gate). Extend `API_KEY_PATTERNS` with `sk_(live|test)_`,
    `rk_live_`, `github_pat_`, `glpat-`, `ASIA…`, `npm_`, `hf_`, `dop_v1_`,
    `"type":\s*"service_account"`. All anchored literals, so the 10 ms bench gate is safe —
    re-run it. Ship a companion FP corpus of pasted source, JSON logs, docs and base64 image
    data, or a `KEY=value` rule will regress. `packages/policy-engine/src/detectors.ts`,
    `packages/policy-engine/test/fp-corpus.test.ts` — **1.5–2d**

14. **IBAN's mod-97 gate is defeated by its own right-trim loop; the card BIN list is too
    narrow and a green test locks the gap in.** The trim loop gives one candidate ~20
    independent 1-in-97 checksum trials: measured FP rate on random `[A-Z]{2}\d{2}` + tail
    tokens is 1.9% at length 16, 10.1% at 24, **18.6% at 34** — real ops identifiers like
    `VM03WINSRV2019DCPRODBACKUP07` flag as IBANs. Replace the loop with a per-country
    length table (match the country code, take exactly that many chars, one mod-97 trial;
    unknown prefixes get zero trials), keeping a bounded trim only for trailing punctuation.
    Conversely `ISSUER_PREFIX` omits Maestro, Diners, JCB, UnionPay and Discover 65/644–649 —
    verified misses on `5641820000000005`, `36700102000000`, `6250947000000014`,
    `3530111333300000`, `6500000000000002`. Replace the prefix regex with numeric BIN ranges
    paired with valid PAN lengths (Amex 15, Diners 14, Visa 13/16/19). `fp-corpus.test.ts`
    currently *asserts* that a Maestro-prefixed and a Diners-prefixed number must not be
    flagged — rewrite those to genuinely out-of-range numbers and add the five above as
    required positives. `packages/policy-engine/src/detectors.ts`,
    `packages/policy-engine/test/fp-corpus.test.ts` — **1d**

15. ~~**`CARD_CANDIDATE` eats one trailing separator.**~~ **Done.** The last repetition of
    `/\b(?:\d[ -]?){13,19}\b/g` could consume a space or hyphen, extending the match span one
    char past the number, so a `redact` action produced `[REDACTED:CARD]and email`. Cosmetic in
    the browser, but in a `PreToolUse` `updatedInput` rewrite of a shell command an eaten space
    changes meaning. The pattern now ends on a digit; regression test in
    `packages/policy-engine/test/fp-corpus.test.ts`.

16. **`bulk_pii` fires on an ordinary email signature under both shipped profiles, and inherits
    `defaultAction` when unconfigured.** Distinctness is over raw match *strings*, so
    `AT61 1904 3002 3457 3201` and `AT611904300234573201` count as two. A German business
    signature (2 addresses + Tel + Mobil + Fax) trips the default threshold of 5. Normalise
    (strip separators, lowercase) before the `Set`; require structural repetition — matches on
    ≥N distinct lines, or ≥N distinct matches from a single detector — since a signature has
    one of each category and a CSV dump has 200 emails; and default `bulk_pii` to `observe`
    when no rule declares it rather than silently inheriting `defaultAction` (a
    `defaultAction:"block"` profile currently blocks signatures). Re-tune the threshold against
    a corpus; the current 5 was not derived from anything measurable.
    `packages/policy-engine/src/engine.ts`, `packages/policy-engine/src/policy.ts`,
    `profiles/*.json` — **1d**

17. **No exception mechanism at any granularity, so the only lever for a known-good pattern is
    disabling the detector.** `4111 1111 1111 1111`, `4242 4242 4242 4242` and
    `5555 5555 5555 4444` all block — engineers paste those daily and the only escape is
    `credit_card: allow`, which also allows real cards. Add `except?: string[]` to
    `DetectorRule` (compiled regexes tested against each candidate match, dropping the
    finding), with built-in defaults for the reserved test BINs, `example.com`/`.invalid`/
    `.test` domains and RFC 5737 addresses. Add per-rule `hosts?: string[]` defaulting to the
    policy's, so one document can be strict externally and permissive on an internal tool.
    Both are pure additions to `parsePolicy` and the finding filter.
    `packages/policy-engine/src/policy.ts`, `packages/policy-engine/src/engine.ts` — **1–1.5d**

18. **Observe mode cannot be used to tune.** `toLogRecord` emits `categories` and `actions` as
    two independent deduped sets, so nothing says which action belonged to which detector — the
    popup then attributes one `primaryAction` to *every* category, reporting e.g.
    `bulk_pii: redact` for an event where `bulk_pii` only warned. Deduping also destroys
    volume: 40 emails in one prompt is one entry. And the user's override choice — "Send
    anyway" / "Redact and continue" / "Cancel" — is recorded nowhere, though override rate per
    rule is the standard FP proxy and the choice is already in front of the user. Change the
    record to `findings: [{ detector, action, count }]`, fix `buildAggregate` to key off it,
    log the guardrail outcome as its own record type from the `onPick` handlers, and surface
    per-rule override rate in the popup. Add a `fingerprint` logging tier between `event` and
    `content`: per finding, detector + match length + character-class shape + truncated hash of
    the normalised match — enough to diagnose the IBAN FP above without storing an IBAN.
    `packages/policy-engine/src/engine.ts`, `apps/extension/src/content.ts`,
    `apps/extension/popup.js` — **1.5–2d**

### 1.5 Operability and release

19. **Policy changes never reach already-open tabs.** `content.ts` fetches the policy once at
    `document_start` and registers no `storage.onChanged` listener (the only listener is in
    `background.ts`, filtered to `areaName === "managed" && "extraHosts" in changes`; the
    sibling `policy` key is unhandled), so a corrected or rolled-back policy needs a browser
    restart. Content scripts get `onChanged` with the existing `storage` permission — listen on
    the managed area, re-run `parsePolicy` in place, with a cheap re-fetch on `visibilitychange`
    as a backstop. Then write the rollback runbook: what a corrected push affects and when, and
    that force-install rollback means republishing the previous code under a *higher* version.
    `apps/extension/src/content.ts`, `docs/DEPLOY_*.md` — **1d**

20. **No health or identity signal an admin can collect.** `pw-diagnostics` is write-only and
    its only exit is a prefilled public GitHub issue — nobody can be told to file an internal
    DLP malfunction on a public tracker. There is no policy revision at all (`Policy.version`
    is pinned to the schema version; `name` is the sole identity, so two different documents
    are indistinguishable). Add an admin-set opaque `policyRevision` to the schema; render a
    Diagnostics block in the popup (extension version, policy name + revision, resolved source
    managed/local/built-in, last successful resolve timestamp, per-kind counts); add an "Export
    diagnostics" button producing one self-contained JSON file with no GitHub and no UA. All
    inside the zero-egress invariant. `packages/policy-engine/src/policy.ts`,
    `apps/extension/popup.js`, `apps/extension/popup.html` — **1–2d**

21. **Nothing to pin, verify or roll back to.** `.github/workflows/` has only `ci.yml` and
    `smoke.yml`; `.gitignore` excludes the built bundles, so what ships is whatever the
    packager's laptop produced, never hashed or published. Build inputs float
    (`"@types/chrome": "*"`, `esbuild: "^0.28.1"`, `typescript: "^7.0.2"`), so the CI-verified
    build is not reproducible, and `ENGINEERING_PLAN.md` already promises signed releases from
    the first public tag. Add a tag-triggered release workflow that builds in CI and publishes
    a deterministic zip + CRX with SHA-256 sums and the source commit, pin devDependencies to
    exact versions, add `minimum_chrome_version`. `.github/workflows/`, `package.json`,
    `apps/extension/manifest.json` — **1–2d**

22. **The no-egress gate is aliasable, scans a hardcoded path list, and never audits the
    bundles that actually ship.** `const f = globalThis.fetch; f(url)` matches nothing (the
    pattern needs the literal `fetch(`), and the pattern omits `chrome.runtime.connect`,
    cross-extension `sendMessage` (a real channel this codebase has the permissions for),
    `RTCPeerConnection`, `WebTransport`, `navigator.serviceWorker`, `chrome.downloads`,
    `window.open`, `top.location=`, `el.src=`, `<link rel=prefetch>`. The six-path `TARGETS`
    list means a future `options.js` or new `packages/*/src` is silently unscanned. And
    `npm run build:extension` *overwrites* the committed bundles before the grep runs, so the
    committed artifact — what a CRX pack or "load unpacked" ships — is never audited (rebuilt
    byte-identical today, so this is latent, not live). Fix: drive the scan off
    `git ls-files '*.ts' '*.js' '*.html'`, extend the pattern, and add
    `git diff --exit-code` on the bundles after the build step as a reproducibility proof. Add
    `"content_security_policy": { "extension_pages": "script-src 'self'; object-src 'self';
    connect-src 'none'" }` so popup/service-worker egress is blocked by the platform rather
    than by grep — note in the plan that content-script fetches are outside `extension_pages`
    CSP, so grep still carries that half; smoke-test the popup's blob download (a navigation,
    should be unaffected). `.github/workflows/ci.yml`,
    `apps/extension/manifest.json` — **0.5d**

23. **No macOS deploy path.** The Windows registry paths for Chrome and Edge are thorough; macOS
    appears only as a binary path. Add `DEPLOY_MACOS.md` covering the per-extension managed
    preference domain (`com.google.Chrome.extensions.<id>` /
    `com.microsoft.Edge.extensions.<id>`) delivered as a `.mobileconfig` via Intune or Jamf, and
    mark every unverified deploy doc as such at the top — only `DEPLOY_GOOGLE_ADMIN.md` carries
    that caveat today. `docs/` — **0.5–1d**

24. **The npm workspace does not exist.** The root `package.json` declares
    `workspaces: ["packages/*", "apps/*"]` but neither `packages/policy-engine` nor
    `apps/extension` has a `package.json`; `npm ls --workspaces` reports "No workspaces
    found!" and the lockfile has zero link entries. `@promptwarden/policy-engine` resolves only
    through esbuild `--alias` (runtime) and tsconfig `paths` (typecheck) — no Node process can
    import it. Consequence: with no `package.json`, `module: NodeNext` makes `tsc` emit
    **CommonJS** while `dist/src/index.d.ts` declares ESM. Fix before any CLI code exists: add
    the member manifests with `"type": "module"`, and rename the root to
    `promptwarden-monorepo` so `promptwarden` is free for the published CLI. Test imports are
    all extensionful relative paths, so the flip to ESM is safe for `node --test`.
    `package.json`, `packages/policy-engine/package.json` — **30m**

---

## 2. CLI and agentic-tool coverage

### The reuse fact

The engine needs **no changes** to serve non-browser adapters. Verified per file:
`policy.ts`, `detectors.ts`, `engine.ts` and `index.ts` are 100% environment-agnostic
(RegExp, `Map`/`Set`, `Date`). `extract-office.ts` touches exactly two platform globals,
`TextDecoder` and `DecompressionStream("deflate-raw")`, and is byteOffset-correct throughout,
so a pooled `Buffer.subarray` from `fs` works. `evaluate()`, `toLogRecord()` and
`extractOfficeText()` all run unmodified under Node against real files. Adapters are thin:
argument parsing, an I/O shim, and an exit-code contract.

Three consequences follow, and they are the whole design:

- **Node floor is `>=22.0.0`, and the reason is a silent failure.** `deflate-raw` only landed
  in Node 20.12/21.2; on 18 the constructor throws, `inflateCapped`'s own `try/catch` swallows
  it, and every `.xlsx`/`.docx` quietly becomes "unreadable" with no diagnostic. Add a CI
  matrix job on the floor version so a regression is loud.
- **`file-scan.ts` is web-only by signature** (`File`, `arrayBuffer()`, `blob.text()`). Lift
  its pure core into the engine as `scanBytes(name, bytes, policy)` plus the size caps and
  extension/MIME lists **before** the CLI forks those constants — otherwise
  `THREAT_MODEL.md`'s file-cited coverage claims stop being true for one adapter.
- **A second privacy gate is required.** A blocking hook's stderr is fed back to the model as
  an error, and `permissionDecisionReason` goes into its context — so a block reason quoting
  the matched IBAN exfiltrates exactly what the block prevented. Add
  `toUserMessage(result)` beside `toLogRecord`: categories and actions only, never a match,
  regardless of logging mode, with a test asserting no match string appears even under
  `logging:"content"`. Widen the ground rule from "all logging routes through `toLogRecord`"
  to **"all logging and all model-visible text"**.

### Package shape

One publishable, zero-dependency package `promptwarden` (`"type": "module"`,
`bin: { promptwarden: "dist/cli.js" }`), engine pre-bundled by the same esbuild `--alias`
trick the extension already uses. Three **subcommands**, not three bins — `npx` only
auto-resolves the bin matching the package name:

```
promptwarden scan  [--stdin|--file <p>…|--json]   exit 0 clean / 1 blocked / 2 warn+--strict / 3 config
promptwarden hook  claude-code                    hook JSON envelope on stdin, decision on stdout
promptwarden mcp   -- <real server cmd>           stdio JSON-RPC gateway (later)
```

Publishing `@promptwarden/policy-engine` separately is deferred until someone asks for the
library; dual-publish lockstep is real cost for no current consumer.

Policy discovery **inverts** the naive "nearest file wins": a `.promptwarden.json` inside an
untrusted `git clone` must not be able to downgrade `credit_card: block` to `allow`.
Precedence: `/etc/promptwarden/policy.json` (root-owned, the managed-storage analogue, and
what makes the existing GPO/Intune/Jamf docs extend to the CLI) > `$PROMPTWARDEN_POLICY` as a
*path*, never inline JSON (env vars leak via `ps -E` and CI logs) > `$XDG_CONFIG_HOME` >
repo-local, applied **strictness-monotonic only** (may raise a rule's action using the
existing `{allow:0 … block:4}` severity map, never lower it, never set `logging:"content"`,
rejected if a symlink or not owned by the invoking uid) > built-in default. All five go
through the existing `parsePolicy`.

`hosts` is browser-only — `hostMatches` returns false for `hosts: []`, so the CLI evaluates
unconditionally and passes a surface label as `toLogRecord`'s host (`cli:scan`,
`cli:claude-code`). Document that in `policy.ts` and in `profiles/*.json`. Events append one
`toLogRecord` line to `${XDG_STATE_HOME:-~/.local/state}/promptwarden/events.jsonl`, mode
0600, reusing `MAX_BUFFERED = 500` / `DEFAULT_RETENTION_DAYS = 90` and the same
`isExpired`/`retentionDaysOf` semantics; a single `O_APPEND` write below `PIPE_BUF` is atomic,
so no lockfile (the extension's `writeQueue` exists only because `chrome.storage` is
read-modify-write). Prune via temp file + `rename()`.

Extend `ci.yml`'s pattern for Node before the first adapter lands:
`node:http|node:https|node:net|node:tls|node:dgram|node:dns|child_process|execSync|spawnSync|createRequire`.
Every import in the CLI must be **static** — the gate bans `import(`. Add any new adapter path
to the scan in the same commit that creates it.

### Interception mechanisms

| Mechanism | Catches | Misses | Effort | Verdict |
|---|---|---|---|---|
| Agent SDK: `evaluate()` in your own code before `query()` | Everything, with **all four actions intact** — you own the prompt string, no hook contract constrains you | Nothing the caller doesn't route through it; requires being the SDK host | Low | **Build now** — only surface where `redact` and `warn` survive; best demo of the engine |
| Claude Code `PreToolUse` hook, no matcher | Every tool argument — Bash `command`, Write/Edit `content`/`new_string`, WebFetch `url`, MCP args, and the **Agent** tool's `prompt` (subagent prompts). Runs before the permission check, so `deny` holds even under `bypassPermissions` | The human's own prompt; per-matcher scoping leaves unlisted tools ungated (hence: no matcher); `mcp__memory` matches nothing — needs `mcp__memory__.*`, and plugin servers are `mcp__plugin_<p>_<s>__<tool>` | Low–med | **Build now** — the actual enforcement layer, and via `updatedInput` the **only** redaction channel in a CLI harness |
| Claude Code `UserPromptSubmit` hook | The typed/pasted prompt before the model sees it, every turn, every permission mode; enforceable from managed settings and survives a user's `disableAllHooks` | **Cannot rewrite the prompt** — no `updatedPrompt` exists, so `redact` degrades to block/warn and `warn`-then-send has no analogue. Blind to files the agent reads itself, and **fails OPEN on timeout** (30 s; output discarded, prompt still reaches the model) | Low | **Build now** — block/observe only. Keep Office extraction off this event |
| `promptwarden scan` — argv, pipes, heredocs, `--file` | `claude -p "…"`, `cat customers.csv \| claude`, heredocs (the heredoc *is* stdin), files by path | Everything typed inside an interactive TUI; files the agent reads itself; absolute-path invocation | Low | **Build now** — the CLI's own front door |
| git pre-commit / required CI check (`git diff --cached \| promptwarden scan --stdin`) | Secrets and PII entering version control under the **same policy document** as the browser | `--no-verify`; history; `--unified=0` diff syntax can split a card across a hunk boundary and defeat Luhn — strip diff markers and test that case | Very low | **Build now** — position as "one policy at commit time", never as a secret scanner |
| MCP stdio gateway (`promptwarden mcp -- <server>`) | Every MCP tool argument **and every tool result** — the inbound direction nothing else covers, and precisely what `bulk_pii` was built for. Reaches Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, JetBrains through one config-file edit | Only the MCP channel. HTTP/SSE-transport servers out of v1 scope by design | Med (~300 lines) | **Build later — best next adapter after the CLI.** Needs one reviewed `child_process.spawn` carve-out in the no-egress gate |
| Cowork plugin (repackage the hook as `hooks/hooks.json`) | Org-**required** plugin install that users cannot remove — the real analogue of managed storage, aimed at the non-developer users likeliest to paste a customer list | Which events fire and whether the stdin/exit-code contract matches the CLI is **unverified** — there is no Cowork hooks reference page | Low incremental | **Later** — do not claim support until a canary prompt with a synthetic Luhn-valid card proves the gate is live |
| Codex CLI hooks (`UserPromptSubmit`, `PreToolUse` + `updatedInput`) | Same two gates as Claude Code, including redaction via `updatedInput` | Hosted/server-side tools (e.g. WebSearch) are invisible. Sources disagree on whether hooks are on by default and whether `PreToolUse` covers only Bash or also `apply_patch`/MCP — if the Bash-only variant is installed, file writes sail past | Med | **Later, provisional** — gate behind a version check plus a canary |
| PATH shim wrapper binary | argv + non-TTY stdin for any CLI, no hook API needed | Interactive TUI input entirely (once the child owns the tty, bytes never enter the wrapper's address space); absolute-path/alias/`env -i` invocation | Low (~80 lines) | **Later** — needs an `isTTY` check plus a read deadline (a shim draining an inherited never-closed pipe hangs) and an absolute interpreter shebang |
| zsh ZLE `accept-line` widget | The full command line at submission, pre-execution, with in-place rewrite via `$BUFFER` | Same TUI blind spot; non-interactive shells; any other shell the user opens | Low (~15 lines) | **Later** — cheap and genuinely blocking |
| bash DEBUG trap + `shopt -s extdebug` | Blocks a simple command by returning non-zero | Skips only that command, not a compound line; `extdebug` changes unrelated bash behaviour | Low | **Later** — fragile. Prefer this over `bind -x`, which forces you to re-implement submission and breaks job control and multi-line input |
| zsh `preexec`, `fish_preexec`, `PROMPT_COMMAND` | The command line, for logging only | **Blocking.** A preexec hook returning 1 does not stop the command; fish closed the block request as will-not-implement; `PROMPT_COMMAND` runs after the fact | Very low | **Rejected as a gate** — shipping these as "blocking" would be false assurance |
| PTY proxy, bracketed-paste gate (`ESC[200~ … ESC[201~`) | Pastes inside a raw-mode TUI — atomic, application-agnostic boundary; the shipped `claude` binary handles bracketed paste | Typed-input submission boundaries inside a TUI are not recoverable from the byte stream (a bare CR may mean submit, accept-completion, newline, or dismiss) | High | **Rejected for now** — Node has no stdlib pty (`tty.openpty` undefined), so it needs `node-pty`, a **runtime dependency**. Revisit only as paste-only, never as a line scanner |
| Plain MCP server as the DLP gate | Nothing enforceable | **The model decides whether to call it**, so it sits downstream of the decision you want to gate and never sees a prompt the model doesn't route to it. "Check with the DLP server first" is prompt adherence, not a control | — | **Rejected** — would be a materially misleading claim for a tool with a published threat model. MCP's legitimate roles are as a harness-invoked `"type": "mcp_tool"` hook handler and as the surface being gated |
| Local LLM-endpoint proxy (`ANTHROPIC_BASE_URL` / `HTTPS_PROXY` / `NODE_EXTRA_CA_CERTS`) | Highest fidelity of anything: the final assembled prompt, including **files the agent read itself** and prior turns | Cert-pinned or proxy-blind clients; local models; unset env vars | Med–high | **Rejected in-tree** — collides head-on with "the inline path never calls a network" and with the no-egress gate, and a TLS-MITM CA is a hard sell to the buyer who likes `host_permissions: []`. If ever built, a separate repo and a deliberate documented amendment, not an exception |

**Two boundaries stated plainly, because they are the two most likely misreadings:**

- **A Claude Code hook can gate a prompt; a shell hook cannot see inside an interactive TUI.**
  `UserPromptSubmit` is invoked by the harness with the prompt in hand, so it can block it. A
  PATH shim, ZLE widget or preexec hook sits *outside* the running process: once `claude` owns
  the tty, keystrokes go kernel tty → child and never traverse the wrapper. Verified: a shim
  logs `scanned argv: []`, sees `stdin is a TTY`, and the card typed afterwards reaches the
  child unscanned. Only a PTY proxy sees those bytes, and only pastes have a recoverable
  boundary.
- **MCP cannot gate a prompt the model never routes to it.** It is model-invoked and
  downstream. The gateway is valuable for tool arguments and tool *results*; it is not a prompt
  gate, and must never be documented as one.

---

## 3. Coverage map

| Leak path | Covered today | Plan |
|---|---|---|
| Typed Enter / send-button click on the 7 default hosts | Yes — capture-phase, no site selectors | Harden the guardrail UI (§1.4), propagate policy changes (§1.19) |
| Paste into a browser chat box | Yes | — |
| File upload / drag-drop, `.txt`-class and `.xlsx`/`.docx` | Yes | Fix the silent unreadable release (§1.5); resolve OOXML parts via the OPC manifest |
| PDF, legacy `.doc`/`.xls` uploads | **No** — documented gap | Unscheduled |
| Internal AI tools beyond the 7 hosts | Managed `extraHosts` + optional permission grant, no retroactive injection into open tabs | §1.19 |
| Firefox | **No port** | Unscheduled |
| `claude -p "…"`, pipes, heredocs | No | `promptwarden scan` |
| Typed prompt in Claude Code / Codex CLI | No | `UserPromptSubmit` hook — block/observe only, no redaction, fails open on timeout |
| Tool arguments: Bash, Write/Edit, WebFetch, MCP calls | No | `PreToolUse` hook with `updatedInput` — the only redaction channel |
| Subagent prompts | No | `PreToolUse` on the Agent tool (hooks also fire inside subagents) |
| MCP tool arguments **and results** | No | MCP stdio gateway |
| Files the agent reads on its own (`Read`/`Grep`, `CLAUDE.md`, auto-loaded context, skills) | No, and **no hook reaches this** | `PreToolUse` on `Read` sees the path, not the bytes; `PostToolUse` is non-blocking. Installing a prompt hook does **not** make "no IBANs leave this machine" true — say so in `THREAT_MODEL.md` |
| Data typed inside an interactive TUI | No | Structurally out of reach for shell-layer mechanisms; pastes only, via a PTY proxy we are not building |
| Secrets entering git | No | pre-commit + required CI check on the diff |
| Direct API calls from scripts (`curl`, Python/Node SDKs) | No — `THREAT_MODEL.md` already says visibility is zero | Opt-in SDK wrapper at best. Mandatory coverage needs a MITM proxy or root-level TLS hooking; both are rejected |
| IDE inline completions (Copilot, Cursor Tab, JetBrains AI) | No | **Architecturally out of reach** for a local OSS tool — the payload is assembled inside a closed process and sent over its own connection. The only levers are vendor-side and *path*-based: GitHub content exclusions (server-enforced, and per GitHub's own docs **not** applied to Copilot CLI, the cloud agent, or Chat Agent mode) and `.cursorignore` (best-effort by Cursor's own description). `.copilotignore` is a community convention, not an enforced feature. At most, a `promptwarden emit-exclusions` renderer |
| Desktop apps (Claude Desktop, ChatGPT app) | No | Out of reach — patching an app bundle breaks signature, notarization and every auto-update. The app is unreachable; **its MCP config file is not**, which is the gateway's seam |
| Hosted/server-side tools (e.g. Codex WebSearch) | No | Out of reach — executed on the provider's side, no hook fires |

Everything outside the browser is client-side and locally editable. The only enforcement floors
are managed storage (browser) and a root-owned `/etc/promptwarden/policy.json` plus managed
settings (CLI); a user can still call a binary by absolute path, pass `--no-verify`, or open a
different shell. The existing threat-model framing — catch the default, unthinking path, not
survive a user actively trying to exfiltrate — transfers verbatim and should be restated in
any CLI or terminal-layer doc.

---

## 4. Deliberately not doing

- **Local TLS-MITM / base-URL proxy in this repo** — breaks "the inline path never calls a
  network" and the CI no-egress gate; a developer-machine CA is a new attack surface. Separate
  repo and an explicit ground-rule amendment, or not at all.
- **eBPF syscall tracing** — needs root/`CAP_BPF`, and is observe-only in practice
  (`bpf_override_return` needs `CONFIG_BPF_KPROBE_OVERRIDE`, off in mainstream kernels, plus an
  `ALLOW_ERROR_INJECTION` tag `write()` lacks). A root daemon reading every process's buffers
  inverts the whole posture.
- **`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` interposition** — verifiably dead on the target:
  `claude` ships hardened runtime without `com.apple.security.cs.allow-dyld-environment-variables`,
  so dyld prunes `DYLD_*`; re-signing destroys the vendor signature. Also reads as malware to EDR.
- **Clipboard polling** — ingests every password-manager copy and 2FA code: a strict superset of
  what the extension deliberately never touches, and it cannot block anyway.
- **`script -k` / `tmux pipe-pane` session capture** — produces full plaintext transcripts
  outside `toLogRecord`, which is exactly what the single-gate rule exists to prevent.
- **`node-pty` for a PTY keystroke scanner** — a native runtime dependency for a mechanism that
  cannot recover typed-submission boundaries anyway. Paste-only, if ever.
- **VS Code terminal-data extension** — `onDidWriteTerminalData` is a proposed API and cannot be
  published to the Marketplace.
- **Per-terminal-emulator plugins (iTerm2 et al.)** — a third runtime and a per-emulator port
  (Ghostty, WezTerm, Kitty, Alacritty, Windows Terminal all differ) with no enforcement floor.
- **`bind -x` on bash Enter** — forces re-implementing submission (`eval` the line yourself),
  which breaks job control, multi-line continuation and `$?`.
- **Entropy-based secret heuristics in the inline path** — too many false positives for a
  blocking guardrail; structured formats only. An entropy tier belongs in an opt-in audit mode.
- **`--staged` (shelling out to git) inside the CLI binary** — would introduce `child_process`
  into a binary whose trust story is "reads stdin, writes stdout, opens no handles". Pipe the
  diff in instead.
- **Positioning the pre-commit hook as a secret scanner** — five structured patterns against
  gitleaks' hundreds, bypassable with `--no-verify`, and blind to history. The differentiated
  claim is *one policy applied at commit time*.
- **Publishing `@promptwarden/policy-engine` as a separate package** — dual-publish version
  lockstep for no current consumer. Revisit on the first real library request.
- **Patching desktop app bundles** — breaks code signing and notarization, and would make this
  project something EDR flags.