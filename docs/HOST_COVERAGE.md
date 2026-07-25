# Host Coverage: default 7, admin-extensible without a store re-review

Status: **default coverage and the permission plumbing are shipped. The background-side
dynamic registration that makes `extraHosts` actually scan a new site is spec, not code —
see "What's spec" below.** Do not read this doc as a description of shipped behavior; the
"What works today" section is the only part that is.

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
  it only declares intent. See "How an admin extends coverage" below for the grant step, and
  "What's spec" for what currently *reads* `extraHosts` (nothing yet — see caveat).

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
- **Per-user, one-click (standalone / self-serve pilots):** the popup gets a "Scan additional
  sites" button that calls `chrome.permissions.request({ origins: ["https://*/*"] })` from
  the click handler (a user gesture is required — this cannot be requested from a background
  script or on load). Chrome shows its native permission-grant prompt; accepting it grants
  `https://*/*` for that browser profile only. This button is **not yet built** — it's
  specced under "What's spec" below, owned by whoever picks up `background.ts` /
  `popup.js` next round.

Either path is revocable the normal Chrome way (`chrome://extensions` → Details →
Permissions, or the admin removing the `ExtensionSettings` entry) — nothing here is a
one-way grant.

## What's spec (not yet implemented — background.ts is owned by another agent this round)

The piece that turns a granted permission + a declared `extraHosts` list into an actual
running content script is dynamic content-script registration in the background service
worker, via `chrome.scripting.registerContentScripts`. This section specs it precisely
enough to be a ~2-hour implementation task.

### Function signature

```ts
// apps/extension/src/background.ts (or a new apps/extension/src/host-coverage.ts
// imported by it, at the implementer's discretion)

/**
 * Reconciles dynamically-registered content scripts against the admin's
 * `extraHosts` policy field and the host permissions Chrome has actually
 * granted. Safe to call repeatedly (e.g. on install, on managed-policy
 * change, on chrome.permissions.onAdded/onRemoved) — it diffs against what's
 * currently registered rather than blindly re-registering.
 *
 * Never calls chrome.permissions.request itself (that requires a user
 * gesture and belongs in the popup click handler) — this only registers
 * scripts for origins Chrome confirms are already granted.
 */
async function syncExtraHostCoverage(extraHosts: string[]): Promise<void>;
```

### Registration flow

1. **Trigger points** — call `syncExtraHostCoverage` from:
   - `chrome.runtime.onInstalled` / `onStartup` (pick up policy already in place).
   - The existing managed-storage change listener path (today `resolvePolicy()` is
     pull-based, called per `get-policy` message; this needs a
     `chrome.storage.onChanged` listener on the `managed` area watching the `policy` key,
     since `extraHosts` rides in the same managed object — or a dedicated watch on
     `extraHosts` if it's easier to reason about separately).
   - `chrome.permissions.onAdded` (a fleet-wide `ExtensionSettings` grant lands here too,
     not just the popup's user-gesture path).
2. **Read declared hosts** — pull `extraHosts` out of the same managed-storage object
   `resolvePolicy()` already reads (`chrome.storage.managed.get(["policy", "extraHosts"])`).
   Treat missing/malformed entries as "no extra hosts," matching the existing
   fail-closed-to-default posture of `resolvePolicy()`'s try/catch.
3. **Filter to granted origins only** — for each pattern in `extraHosts`, call
   `chrome.permissions.contains({ origins: [pattern] })`. Drop anything not (yet) granted.
   This is what makes step 1 (declare) and step 2 (grant) independently safe: a policy that
   names 40 hosts before anyone has granted `https://*/*` registers zero scripts and injects
   nowhere, silently, until the grant lands.
4. **Diff and register** — compare the granted, declared hosts against
   `chrome.scripting.getRegisteredContentScripts({ ids: ["pw-extra-hosts"] })`. If the match
   set changed, `unregisterContentScripts({ ids: ["pw-extra-hosts"] })` then
   `registerContentScripts([{ id: "pw-extra-hosts", matches: grantedExtraHosts, js:
   ["content.bundle.js"], runAt: "document_start", allFrames: true }])` — mirroring the
   static entry's `run_at`/`all_frames` so behavior on an extra host matches behavior on a
   default host exactly. Re-registering under the same script `id` is what makes this
   idempotent to call repeatedly.
5. **No change to `content.ts`** — the content script itself is host-agnostic already (see
   its own header: "Deliberately selector-less"); it doesn't need to know whether it's
   running on a default host or an `extraHosts` one. `hostMatches()` in
   `packages/policy-engine/src/policy.ts` governs which *policy rules* apply per host, which
   is a separate, already-working concern from *whether the script runs there at all*.
6. **Un-grant handling** — `chrome.permissions.onRemoved` should re-run
   `syncExtraHostCoverage` too, so a revoked grant tears down the matching registered
   scripts rather than leaving a dangling registration Chrome will refuse to honor anyway.

### Explicitly out of scope for that 2-hour task

- No UI beyond the single popup "Scan additional sites" button described above — no
  per-host toggle list, no origin validation/preview beyond what `chrome.permissions.request`
  already shows natively.
- No retroactive scan of tabs already open on a newly-covered host — `document_start`
  injection only takes effect on the next navigation, same limitation the 7 default hosts
  already have on extension install/update.
- No change to `toLogRecord` or any logging surface. `extraHosts` changes *where* the
  content script runs; it does not change what it's allowed to log. An event from an extra
  host goes through the exact same `toLogRecord` gate as one from `claude.ai` today.

## Reporting requirement

**Any G5 exposure report (or any exposure number quoted in a sales or trust-pack context)
must name the host coverage it ran with** — "7 default hosts" vs "7 default + N admin-added
hosts, granted on [date]." Coverage is not fixed across the pilot's lifetime once
`extraHosts` ships: a number from before a coverage grant and a number from after are not
comparable, and presenting them as if they were overstates either the improvement or the
baseline. Until the background-side registration above is implemented, every exposure
number this repo can currently produce is, by construction, a 7-host number — say so.

## Honest summary

| Piece | Status |
|---|---|
| `optional_permissions` / `optional_host_permissions` in manifest | Shipped this change |
| `extraHosts` field in managed schema | Shipped this change (declaration only) |
| Fleet-wide grant via `ExtensionSettings.runtime_allowed_hosts` | Standard Chrome Enterprise mechanic, no PromptWarden code needed, usable today once an admin has the extension ID |
| Popup "Scan additional sites" one-click grant button | Spec only, not built |
| Background-side `chrome.scripting.registerContentScripts` sync | Spec only, not built — background.ts is owned by another agent this round |
| Any live scanning of a host outside the default 7 | **Not possible yet** — permission plumbing exists, nothing consumes it |
