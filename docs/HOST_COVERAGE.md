# Host Coverage: default 7, admin-extensible without a store re-review

Status: **default coverage, the permission plumbing, the background-side dynamic
registration, and the popup grant flow are all shipped.** Declaring `extraHosts` and
granting the permission now makes the content script actually inject on the named
origin. That is not the same as the policy engine actually *enforcing* anything there —
see "The other half: `hostMatches()` and `policy.hosts`" below for the one remaining
manual step (mirroring the same origins into the policy document's `hosts` array), which
this doc's scope does not automate.

## Council finding this answers

G5 (`docs/NEXT_PLAN.md`) measures exposure — sensitive-data hits per user per week — as
evidence the pain PromptWarden addresses is real. As shipped, that measurement runs against
exactly 7 hardcoded hosts (`content_scripts[0].matches` in `apps/extension/manifest.json`).
That is a 7-host allowlist's exposure rate, not the market's: any org whose staff use an
internal chat gateway, a self-hosted LLM UI, or a vendor tool outside the 7 contributes zero
measured exposure regardless of actual risk. A pilot evaluator who asks "what about our
internal tool?" cannot be answered with "wait for the next Chrome Web Store review cycle" —
that's a multi-day-to-multi-week delay against a sales conversation happening this week.

## Why the default is 7 hosts, not `https://*/*`, by default

`host_permissions: []` plus a 7-origin `content_scripts.matches` list is a deliberate,
narrow **required** permission grant:

- The Chrome Web Store install prompt and the enterprise admin's permission-review screen
  both read the required permission surface, not the optional one. A required `https://*/*`
  reads, to a reviewer or a DPO, as "this extension can inject into every page you visit" —
  it invites exactly the store-review friction and the works-council/DPO hesitation the rest
  of this plan is designed to avoid (`docs/NEXT_PLAN.md` thesis: zero-egress and a narrow
  permission footprint are the moat).
- A named, auditable host list is also what the trust pack and the exposure reports lean on:
  "PromptWarden scanned these 7 named AI chat sites" is a sentence a DPO can verify by
  reading the manifest. "PromptWarden can run anywhere" is not.

So the 7-host list stays the **required, install-time** default. Coverage beyond it is
**optional and runtime-granted**, per host, with the admin (or, in standalone mode, the
individual user) making an explicit, revocable grant — never a store re-submission.

## What works today

- `apps/extension/manifest.json` declares:
  - `optional_permissions: ["scripting"]`
  - `optional_host_permissions: ["https://*/*"]`
  - Required `permissions` (`["storage"]`) and required `host_permissions` (`[]`) are
    **unchanged**. Adding an optional-permissions block does not add anything to the
    install-time prompt; Chrome only prompts for optional permissions when the extension
    calls `chrome.permissions.request(...)` in response to a user gesture, at whatever later
    moment that happens.
  - Manifest JSON validity was checked directly (`python3 -m json.tool`) as part of this
    change; there is no existing manifest-schema test in the repo to extend.
- `apps/extension/managed_schema.json` declares `extraHosts` as an array-of-strings managed
  policy field: the list of additional origin match patterns (e.g.
  `"https://internal-chat.example.com/*"`) an admin wants scanned, distributed the same way
  `policy` already is — via Chrome Enterprise policy / Google Admin console managed storage.
  Setting `extraHosts` **does not by itself grant the permission** to access those origins;
  it only declares intent. See "How an admin extends coverage" below for the grant step.
- `apps/extension/src/background.ts` reads `extraHosts` from managed storage, validates each
  entry as a well-formed **https-only** match pattern (`<all_urls>`, `http:`, and every other
  scheme are rejected — malformed entries are silently dropped, not fatal, matching the
  fail-closed-to-default posture the rest of this file already uses for `policy`), filters to
  the subset Chrome's `chrome.permissions.contains` confirms is actually granted, and
  reconciles a single dynamically registered content script (id `pw-extra`, same
  `content.bundle.js`, `run_at: document_start`, `all_frames: true`,
  `persistAcrossSessions: true` as the manifest's static 7-host entry) against that granted
  subset. Runs on service-worker startup, on `chrome.storage.onChanged` for managed
  `extraHosts`, and on `chrome.permissions.onAdded` / `onRemoved` (so a fleet-wide
  `ExtensionSettings` grant or revocation is picked up without any popup interaction). Never
  throws — any failure lands in the `pw-diagnostics` buffer under the closed-set reason code
  `extra-hosts-error`. See "How it's implemented" below for the detail.
- `apps/extension/popup.js` / `popup.html`: when managed `extraHosts` are declared but the
  `scripting` + origins permission grant is missing, the popup shows a one-line notice and an
  **"Enable extended coverage"** button that calls `chrome.permissions.request(...)` from the
  click handler (the required user gesture), then messages the background service worker to
  re-sync immediately rather than waiting for the `onAdded` listener. The popup also has a
  **"Problem melden"** link that opens a prefilled GitHub issue (placeholder repo path — the
  real one isn't public yet, see the comment at the top of `popup.js`) carrying only the
  extension version, the browser UA, and a category-level count summary from `pw-diagnostics`
  — never event data, never a hostname from `pw-events` or `pw-diagnostics`.

## How an admin extends coverage (2 steps, no store re-review)

**Step 1 — declare which hosts.** Set `extraHosts` in the managed policy pushed via Chrome
Enterprise policy / Google Admin console, e.g.:

```json
{
  "policy": "{...existing PromptWarden policy JSON...}",
  "extraHosts": ["https://internal-chat.example.com/*", "https://llm.example.org/*"]
}
```

**Step 2 — grant the optional host permission.** `extraHosts` names the origins; the
extension still needs Chrome's permission to inject into them. Two ways to grant it, both
already-standard Chrome Enterprise / MV3 mechanics (no PromptWarden code required for the
grant itself):

- **Fleet-wide, no user click (preferred for a pilot):** the admin adds the extension's
  `optional_host_permissions` origins to
  [`ExtensionSettings`](https://chromeenterprise.google/policies/#ExtensionSettings)'s
  `runtime_allowed_hosts` for the PromptWarden extension ID, via Google Admin console or
  Group Policy. This pre-grants the optional host permission fleet-wide — end users never
  see a permission prompt.
- **Per-user, one-click (standalone / self-serve pilots):** the popup's **"Enable extended
  coverage"** button calls `chrome.permissions.request({ permissions: ["scripting"],
  origins: extraHosts })` from the click handler (a user gesture is required — this cannot be
  requested from a background script or on load, and never is). Chrome shows its native
  permission-grant prompt scoped to exactly the declared `extraHosts` origins (not a blanket
  `https://*/*`); accepting it grants those origins, plus the `scripting` API permission, for
  that browser profile only. **Shipped.**

Either path is revocable the normal Chrome way (`chrome://extensions` → Details →
Permissions, or the admin removing the `ExtensionSettings` entry) — nothing here is a
one-way grant. Revocation is picked up automatically: `background.ts` listens on
`chrome.permissions.onRemoved` and tears down the matching registered content script.

**Step 3 (easy to miss) — mirror the same origins into the policy's `hosts` array.** See
"The other half: `hostMatches()` and `policy.hosts`" immediately below — granting the
permission makes the content script *run* there; it does not by itself make any policy rule
*apply* there.

## The other half: `hostMatches()` and `policy.hosts`

Steps 1–2 above (declare + grant) are the whole story for *whether the content script
injects* on an extraHosts origin. They are **not** the whole story for whether it does
anything once injected. `apps/extension/src/content.ts` gates all enforcement behind
`hostMatches(policy, location.hostname)` (`packages/policy-engine/src/policy.ts`), which
checks the *policy document's own* `hosts` array — a field that has nothing to do with
`extraHosts` and is not touched by anything in this file's scope.

Concretely: if an admin declares `extraHosts: ["https://internal-chat.example.com/*"]`,
grants the permission, and background.ts registers the content script there, the script
**will load** on `internal-chat.example.com` — but if that host is not also listed in
`policy.hosts` (the distributed `policy` JSON, a separate managed-storage field), every
`hostMatches()` check on that page returns `false` and the content script does nothing:
no detection, no warn/redact/block, no event logged. It fails safe (nothing happens) rather
than unsafe (silent bypass of a rule the admin thought was active), but it is a trap for an
admin who did Steps 1–2 and reasonably assumed coverage was complete.

**So: every origin added to `extraHosts` must also be added to `policy.hosts`, by hand, in
the same policy update.** Nothing in this round automates that mirroring — `extraHosts` and
`policy` are independent managed-storage fields read by different code paths
(`background.ts`'s `syncExtraHostCoverage` vs. `content.ts`'s policy application), and
keeping them in sync is currently a manual admin responsibility. A future round could fold
`extraHosts` into `hostMatches()` directly (so injection and enforcement share one source of
truth) — out of scope here; flagged, not fixed.

## How it's implemented

The piece that turns a granted permission + a declared `extraHosts` list into an actual
running content script is dynamic content-script registration in the background service
worker, via `chrome.scripting.registerContentScripts`. **Shipped in `apps/extension/src/background.ts`.**

### Function signature

```ts
// apps/extension/src/background.ts

/**
 * Reconciles the single "pw-extra" dynamically-registered content script
 * against the admin's `extraHosts` managed-storage field and the host
 * permissions Chrome has actually granted. Safe to call repeatedly (service
 * -worker startup, managed-storage change, chrome.permissions.onAdded/
 * onRemoved, or a popup "sync-extra-hosts" message) — it diffs against
 * what's currently registered rather than blindly re-registering.
 *
 * Never calls chrome.permissions.request itself (that requires a user
 * gesture and lives in the popup click handler) — this only registers
 * scripts for origins Chrome confirms are already granted. Never throws —
 * every failure is caught and recorded to pw-diagnostics as the closed-set
 * reason code "extra-hosts-error" instead of propagating.
 */
async function syncExtraHostCoverage(): Promise<void>;
```

(Unlike the original spec's signature, the shipped version takes no `extraHosts` parameter —
it reads managed storage itself via `chrome.storage.managed.get(["extraHosts"])`, the same
way `resolvePolicy()` reads `policy`. Callers just call it with no arguments.)

### Registration flow (as shipped)

1. **Trigger points** — `syncExtraHostCoverage()` runs:
   - Directly at module top level, mirroring the existing `enqueueStartupPrune()` call —
     covers service-worker startup even when neither `onInstalled` nor `onStartup` fires (a
     worker can wake for other reasons, e.g. an incoming message).
   - `chrome.storage.onChanged`, filtered to `areaName === "managed"` and a changeset that
     includes the `extraHosts` key.
   - `chrome.permissions.onAdded` and `chrome.permissions.onRemoved` — covers both a
     fleet-wide `ExtensionSettings` grant/revocation and the popup's user-gesture path (the
     popup's own message, below, is belt-and-suspenders on top of `onAdded` for latency, not
     a replacement for it).
   - A `{ type: "sync-extra-hosts" }` runtime message sent by `popup.js` immediately after
     `chrome.permissions.request(...)` resolves truthy.
2. **Read declared hosts** — `chrome.storage.managed.get(["extraHosts"])`, validated to
   well-formed **https-only** match patterns (`<all_urls>` and every non-https scheme,
   including bare `http:`, are rejected) and de-duplicated. Missing/malformed/absent managed
   storage all resolve to "no extra hosts," matching `resolvePolicy()`'s existing
   fail-closed-to-default posture for the sibling `policy` field.
3. **Check the `scripting` permission itself first** — `chrome.permissions.contains({
   permissions: ["scripting"] })`. `scripting` is `optional_permissions` and hosts are
   `optional_host_permissions`; both are checked, not just the origin. If `scripting` isn't
   granted, nothing could have been registered through this API in the first place
   (registration itself requires it), so the function returns early with nothing to
   reconcile — no `chrome.scripting.*` call is even attempted.
4. **Filter to granted origins only** — for each declared pattern, `chrome.permissions
   .contains({ origins: [pattern] })` (checked one at a time — a single batched call only
   answers "are all of these granted?", not which ones). This is what makes declare (step 2
   above) and grant independently safe: a policy naming 40 hosts before anyone has granted
   any of them registers zero scripts and injects nowhere, silently, until a grant lands.
5. **Diff and register** — `chrome.scripting.getRegisteredContentScripts({ ids: ["pw-extra"] })`
   first. Empty granted set + an existing registration → `unregisterContentScripts`. Non-empty
   granted set that matches the existing registration's `matches` (order-independent) → no-op.
   Otherwise → `updateContentScripts` if a registration already exists, `registerContentScripts`
   if not — both with `{ id: "pw-extra", matches: grantedOrigins, js: ["content.bundle.js"],
   runAt: "document_start", allFrames: true, persistAcrossSessions: true }`, mirroring the
   static manifest entry's `run_at`/`all_frames` exactly. The stable `id` is what makes this
   idempotent across calls.
6. **No change to `content.ts`** — the content script itself is host-agnostic already (see
   its own header: "Deliberately selector-less"); it doesn't need to know whether it's
   running on a default host or an `extraHosts` one. `hostMatches()` in
   `packages/policy-engine/src/policy.ts` governs which *policy rules* apply per host — see
   "The other half" above for why that's a separate step admins must not skip.

### What's still deliberately out of scope

- No per-host toggle list in the popup, no origin validation/preview beyond what
  `chrome.permissions.request` already shows natively and the https-match-pattern validator
  above.
- No retroactive scan of tabs already open on a newly-covered host — `document_start`
  injection only takes effect on the next navigation, same limitation the 7 default hosts
  already have on extension install/update.
- No change to `toLogRecord` or any logging surface. `extraHosts` changes *where* the
  content script runs; it does not change what it's allowed to log. An event from an extra
  host goes through the exact same `toLogRecord` gate as one from `claude.ai` today.
- No automated mirroring of `extraHosts` into `policy.hosts` — see "The other half" above.

## Reporting requirement

**Any G5 exposure report (or any exposure number quoted in a sales or trust-pack context)
must name the host coverage it ran with** — "7 default hosts" vs "7 default + N admin-added
hosts, granted on [date] and mirrored into policy.hosts." Coverage is not fixed across the
pilot's lifetime now that `extraHosts` registration is live: a number from before a coverage
grant and a number from after are not comparable, and presenting them as if they were
overstates either the improvement or the baseline. A granted-but-not-policy-mirrored host
(see "The other half" above) contributes **zero** measured exposure even though the content
script is running there — a report must not claim coverage for a host that was only
declared+granted without confirming it also appears in `policy.hosts`.

## Honest summary

| Piece | Status |
|---|---|
| `optional_permissions` / `optional_host_permissions` in manifest | Shipped |
| `extraHosts` field in managed schema | Shipped (declaration only) |
| Fleet-wide grant via `ExtensionSettings.runtime_allowed_hosts` | Standard Chrome Enterprise mechanic, no PromptWarden code needed, usable today once an admin has the extension ID |
| Popup "Enable extended coverage" one-click grant button | **Shipped this change** (`apps/extension/popup.js` / `popup.html`) |
| Popup "Problem melden" prefilled GitHub issue link | **Shipped this change** — placeholder repo path, see comment in `popup.js` |
| Background-side `chrome.scripting.registerContentScripts` sync | **Shipped this change** (`apps/extension/src/background.ts`, `syncExtraHostCoverage`) |
| Scanning (content script *injects*) on a granted `extraHosts` origin outside the default 7 | **Possible now** — declare + grant, nothing else required for injection |
| Enforcement (policy rules actually *apply*) on that same origin | **Requires one more manual step** — the origin must also be added to `policy.hosts`, by hand, or `hostMatches()` silently no-ops there. See "The other half" above |
| Automated mirroring of `extraHosts` into `policy.hosts` | Not built — out of scope this round, flagged above |
