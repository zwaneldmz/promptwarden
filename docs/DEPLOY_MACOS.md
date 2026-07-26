# Deploying PromptWarden on macOS (Chrome and Edge)

**Note:** not yet verified against a real managed tenant; treat the steps below as unconfirmed until tested end-to-end. The macOS managed-preference domain names and structure below are drawn from Chromium's and Microsoft's own documentation (cited inline) and cross-checked against the Windows registry paths `DEPLOY_GPO.md`/`DEPLOY_INTUNE.md` already document for the same two policies — but nothing here has been run against a real Jamf/Intune tenant or a real Chrome/Edge install on macOS. If something in this doc doesn't match what you see on a live machine, trust the machine and file an issue.

Covers macOS fleets running Chrome and/or Edge — the target audience most of this project's existing deploy docs (`DEPLOY_GPO.md`, `DEPLOY_INTUNE.md`, `DEPLOY_GOOGLE_ADMIN.md`) don't address; all three are Windows-registry-shaped, and macOS appears nowhere in them except as a binary path. The two things to configure are the same as every other deploy doc: (1) force the install, (2) push the managed policy JSON. Do both, for either browser you target.

## Prerequisites

- A macOS fleet enrolled in an MDM that can push configuration profiles (Jamf Pro or Intune for macOS, covered below — the underlying mechanism, a `.mobileconfig` configuration profile, works the same regardless of which MDM pushes it, so this doc's profile content applies to any MDM, not just these two).
- The PromptWarden **Chrome Web Store extension ID** (`<PROMPTWARDEN_EXTENSION_ID>`) and, separately, the **Edge Add-ons extension ID** (`<PROMPTWARDEN_EDGE_EXTENSION_ID>`) — placeholders until either store listing ships, same caveat as `DEPLOY_GOOGLE_ADMIN.md`/`DEPLOY_INTUNE.md`/`DEPLOY_GPO.md`. If you're deploying a self-hosted CRX instead (`DEPLOY_SELF_HOSTED_CRX.md`), use that build's own extension ID here, not the (unissued) store ID — see that doc's warning section for why mixing them breaks policy delivery silently.
- Chrome and/or Edge already installed on the target Macs (this doc covers policy delivery, not browser installation/updates).

## The two macOS-specific pieces this doc adds

Everything else in this doc (what `ExtensionInstallForcelist` does, what the `policy`/`extraHosts` schema means, the `hosts: ["*"]` footgun, the `extraHosts` caveat) is identical in substance to `DEPLOY_GPO.md`/`DEPLOY_INTUNE.md`/`DEPLOY_GOOGLE_ADMIN.md` — only the delivery mechanism differs. The two things that are genuinely macOS-specific:

1. **The managed-preference domain names**, which replace the Windows registry paths:

   | Purpose | Windows registry path (for reference) | macOS managed-preference domain |
   |---|---|---|
   | Force-install list (Chrome) | `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist` | `com.google.Chrome`, key `ExtensionInstallForcelist` |
   | Force-install list (Edge) | `HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist` | `com.microsoft.Edge`, key `ExtensionInstallForcelist` |
   | PromptWarden's own policy (Chrome) | `...\3rdparty\extensions\<id>\policy\{policy,extraHosts}` | `com.google.Chrome.extensions.<PROMPTWARDEN_EXTENSION_ID>`, keys `policy` and `extraHosts` |
   | PromptWarden's own policy (Edge) | `...\3rdparty\extensions\<id>\policy\{policy,extraHosts}` | `com.microsoft.Edge.extensions.<PROMPTWARDEN_EDGE_EXTENSION_ID>`, keys `policy` and `extraHosts` |

   The per-extension domain (row 3/4) is documented directly by Chromium for the third-party-extension-policy mechanism this project's `managed_schema.json` uses — see ["Configuring Apps and Extensions by
   Policy"](https://www.chromium.org/administrators/configuring-policy-for-extensions/), Mac section. Edge inherits the identical Chromium mechanism; substitute `com.microsoft.Edge` for `com.google.Chrome` per [Microsoft's own Edge policy documentation](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/extensioninstallforcelist), which confirms `com.microsoft.Edge` as Edge's macOS domain for the standard (non-3rdparty) policies — the per-extension `.extensions.<id>` suffix for Edge is inferred by the same Chromium mechanism Edge otherwise mirrors exactly, not independently confirmed against a real Edge-on-Mac install.

2. **How that domain's keys actually get onto disk**, which is where macOS diverges structurally from a flat registry value or a JSON policy file. There are two real formats, and mixing them up is the most likely way to ship a policy that Chrome silently ignores:

   - **A `.mobileconfig` configuration profile** (what Jamf/Intune actually push) wraps each domain in a `com.apple.ManagedClient.preferences` payload, with the domain's keys living inside an `mcx_preference_settings` dict, flat and matching the schema directly — no extra wrapper around `policy`/`extraHosts` themselves. **This is the format to use** — it's what "Step 1" and "Step 2" below produce.
   - **A hand-authored legacy `.plist` imported via `dscl -mcximport`** (an old Open Directory / MCX mechanism, essentially obsolete, not what any modern MDM does) wraps every key in `{state = Always; value = ...;}`. Chromium's own docs call this out explicitly: that wrapper means "this configuration does NOT directly match the schema provided in your `managed_schema.json`." If you ever see a plist shaped like that, it's the legacy format, not what Jamf/Intune's configuration-profile UI produces — don't hand-adapt `mcx_preference_settings` content into that shape or vice versa.

## Step 1 — Force-install, via a `.mobileconfig` profile

The `.mobileconfig` payload below force-installs PromptWarden for Chrome. Duplicate the same payload with `com.microsoft.Edge` and the Edge extension ID/update URL for Edge; you can ship both in one profile as two separate `PayloadContent` entries.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.ManagedClient.preferences</string>
      <key>PayloadIdentifier</key>
      <string>tech.abantu.promptwarden.chrome-forcelist</string>
      <key>PayloadUUID</key>
      <string>REPLACE-WITH-A-FRESH-UUID</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadDisplayName</key>
      <string>PromptWarden — Chrome force-install</string>
      <key>PayloadContent</key>
      <dict>
        <key>com.google.Chrome</key>
        <dict>
          <key>Forced</key>
          <array>
            <dict>
              <key>mcx_preference_settings</key>
              <dict>
                <key>ExtensionInstallForcelist</key>
                <array>
                  <string>&lt;PROMPTWARDEN_EXTENSION_ID&gt;;https://clients2.google.com/service/update2/crx</string>
                </array>
              </dict>
            </dict>
          </array>
        </dict>
      </dict>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>PromptWarden macOS policy</string>
  <key>PayloadIdentifier</key>
  <string>tech.abantu.promptwarden.macos-policy</string>
  <key>PayloadRemovalDisallowed</key>
  <true/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>REPLACE-WITH-ANOTHER-FRESH-UUID</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
```

Generate real UUIDs for both `PayloadUUID` fields (`uuidgen` on any Mac, or let Jamf/Intune generate them for you if their profile editor does so automatically). This is the MDM-agnostic profile shape — see "Delivery via Jamf Pro" and "Delivery via Intune for macOS" below for how each MDM actually gets this XML onto a device.

## Step 2 — Push the managed policy JSON (per-extension "3rd-party" policy)

Same principle as Step 1, targeting the per-extension domain instead of the browser-wide one. Add a second `PayloadContent` entry to the profile above (or a second top-level profile — either works):

```xml
<dict>
  <key>PayloadType</key>
  <string>com.apple.ManagedClient.preferences</string>
  <key>PayloadIdentifier</key>
  <string>tech.abantu.promptwarden.chrome-extension-policy</string>
  <key>PayloadUUID</key>
  <string>REPLACE-WITH-A-FRESH-UUID</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadDisplayName</key>
  <string>PromptWarden — Chrome extension policy</string>
  <key>PayloadContent</key>
  <dict>
    <key>com.google.Chrome.extensions.&lt;PROMPTWARDEN_EXTENSION_ID&gt;</key>
    <dict>
      <key>Forced</key>
      <array>
        <dict>
          <key>mcx_preference_settings</key>
          <dict>
            <key>policy</key>
            <string>{"version":1,"name":"Default","hosts":["chatgpt.com","chat.openai.com","claude.ai","gemini.google.com","copilot.microsoft.com","chat.mistral.ai","www.perplexity.ai"],"rules":[{"detector":"credit_card","action":"redact"},{"detector":"iban","action":"redact"},{"detector":"at_svnr","action":"block"}],"logging":"event","defaultAction":"warn","retentionDays":90}</string>
            <key>extraHosts</key>
            <array>
              <string>https://internal-chat.example.com/*</string>
              <string>https://llm.example.org/*</string>
            </array>
          </dict>
        </dict>
      </array>
    </dict>
  </dict>
</dict>
```

Note the domain name (`com.google.Chrome.extensions.<PROMPTWARDEN_EXTENSION_ID>`) is literally `<extension-id>` appended to the browser's own domain with a `.` — the extension ID is part of the *domain name itself*, not a key inside it, matching how the Windows registry path embeds the ID as a path segment rather than a value.

**`hosts` must list explicit hostnames — never `["*"]`.** The example above lists the same 7 hosts as `apps/extension/manifest.json`'s `content_scripts[0].matches`, identically to every other deploy doc's example policy. `hostMatches()` (`packages/policy-engine/src/policy.ts`) only understands an exact hostname or a leading `*.` subdomain wildcard; a bare `"*"` matches **zero** hosts, so a policy that pastes `"hosts":["*"]` enforces nothing anywhere while the popup still shows "Managed by your organization" — `parsePolicy` rejects a bare `"*"` entry outright rather than accepting it silently.

**`extraHosts` caveat — read before promising it to a pilot evaluator.** Same as every other deploy doc: declaring `extraHosts` here states intent, but scanning those hosts only starts once the matching optional host permission (`https://*/*`) is actually granted — via `ExtensionSettings.runtime_allowed_hosts` (itself a plain Chrome/Edge policy, delivered the same way as Step 1's `ExtensionInstallForcelist` — i.e. under the `com.google.Chrome`/`com.microsoft.Edge` domain, not the per-extension one) or the popup's "Enable extended coverage" button. See [`docs/HOST_COVERAGE.md`](HOST_COVERAGE.md) for the full mechanism and the "current implementation status" caveat that applies everywhere this is mentioned.

Edge: duplicate this whole payload with `com.microsoft.Edge.extensions.<PROMPTWARDEN_EDGE_EXTENSION_ID>` and the Edge extension ID.

## Delivery via Jamf Pro

Jamf Pro's native UI has no built-in schema for either `com.google.Chrome` (beyond a handful of common keys) or any per-extension domain — same gap `DEPLOY_INTUNE.md` describes for Windows Settings Catalog, for the same reason (a per-extension managed-storage schema is defined by the extension itself, and Jamf/Microsoft/Google don't ship one for every third-party extension). Two options:

### Option A — Upload a custom preference manifest (more "native," out of scope to hand you pre-built)

Jamf Pro's **Application & Custom Settings** payload supports uploading a `.plist`-based **preference manifest** that describes a domain's keys and generates a form UI for them, instead of requiring raw XML. Authoring that manifest for `com.google.Chrome.extensions.<id>` is extension-ID-specific (the ID isn't issued yet — see Prerequisites) and out of scope for this doc to hand you pre-built, same reasoning `DEPLOY_INTUNE.md`'s equivalent "Option A" gives for a custom ADMX.

### Option B — Upload the raw `.mobileconfig` directly (copy-pasteable now)

Simpler to stand up immediately: build the `.mobileconfig` from Step 1 + Step 2 above (fill in real extension IDs and fresh UUIDs), then in Jamf Pro:

**Computers** → **Configuration Profiles** → **New** → give it a name and scope → **Application & Custom Settings** payload → **External Applications** → **Upload manually** (or your Jamf version's equivalent "edit the plist directly" option) → paste the two `PayloadContent` dicts (Step 1's `com.google.Chrome` block and Step 2's `com.google.Chrome.extensions.<id>` block) into the domain-scoped editor Jamf presents, one domain per "Preference Domain" entry. Alternatively, some Jamf Pro versions let you skip the domain-by-domain UI entirely and instead upload the complete `.mobileconfig` file as-is under **General** → import — check which your tenant's Jamf Pro version offers before assuming either path.

Scope the profile to the target computers/smart group and push. Jamf's normal check-in interval (or **Recon** / **Enrollment Complete** triggers, or a forced `sudo jamf policy` on a test machine) applies the profile.

## Delivery via Intune for macOS

Intune's **Settings Catalog** for macOS mirrors its Windows counterpart's gap: it has built-in entries for a handful of well-known Chrome/Edge policies, but nothing for PromptWarden's own per-extension schema. Two options, same shape as `DEPLOY_INTUNE.md`'s Windows guidance:

### Option A — Settings Catalog, if your tenant's catalog happens to list it

**Devices** → **macOS** → **Configuration** → **Create** → **Settings catalog**, search for **Chrome** / **Edge** → **Extension install forcelist**. Confirm your tenant's catalog actually surfaces this before relying on it — catalog contents are Microsoft/Google-maintained and can change. This only covers Step 1 (force-install); the catalog has no entry for PromptWarden's own `policy`/`extraHosts` schema, so Step 2 always needs Option B below regardless.

### Option B — Custom configuration profile, uploading the `.mobileconfig` directly (covers both steps, copy-pasteable now)

**Devices** → **macOS** → **Configuration** → **Create** → **Templates** → **Preference file** (or **Custom** on older Intune UIs — naming has shifted across Intune releases; look for the option that lets you upload an arbitrary `.mobileconfig`/preference file rather than picking from a catalog). Upload the `.mobileconfig` built from Step 1 + Step 2 above as a single file, or split it into two separate profiles (one per domain) if you'd rather manage force-install and the extension policy as independently assignable profiles. Assign to the target device group.

## `defaults write` recipe for testing on one machine

**Caveat before you use this:** this is a widely used sysadmin technique for locally testing macOS managed preferences without an MDM, not something Google or Microsoft officially documents as a supported testing path, and it has not been independently verified against a real Chrome/Edge install by this doc's author. It works by placing the exact file an MDM profile install ultimately produces on disk — `/Library/Managed Preferences/<domain>.plist` — directly, via `sudo defaults write` targeting that literal path, rather than going through an actual profile install:

```bash
sudo mkdir -p "/Library/Managed Preferences"

# Step 1 — force-install (Chrome)
sudo defaults write "/Library/Managed Preferences/com.google.Chrome" \
  ExtensionInstallForcelist -array \
  "<PROMPTWARDEN_EXTENSION_ID>;https://clients2.google.com/service/update2/crx"

# Step 2 — PromptWarden's own policy (Chrome)
sudo defaults write "/Library/Managed Preferences/com.google.Chrome.extensions.<PROMPTWARDEN_EXTENSION_ID>" \
  policy -string '{"version":1,"name":"Default","hosts":["chatgpt.com","chat.openai.com","claude.ai","gemini.google.com","copilot.microsoft.com","chat.mistral.ai","www.perplexity.ai"],"rules":[{"detector":"credit_card","action":"redact"},{"detector":"iban","action":"redact"},{"detector":"at_svnr","action":"block"}],"logging":"event","defaultAction":"warn","retentionDays":90}'

sudo defaults write "/Library/Managed Preferences/com.google.Chrome.extensions.<PROMPTWARDEN_EXTENSION_ID>" \
  extraHosts -array \
  "https://internal-chat.example.com/*" \
  "https://llm.example.org/*"
```

(Swap `com.google.Chrome`/`com.google.Chrome.extensions.<id>` for `com.microsoft.Edge`/`com.microsoft.Edge.extensions.<id>` to test Edge instead.)

Fully quit and relaunch the browser afterward (managed preferences are read at startup and on an explicit policy reload, not continuously) — then verify with the same `chrome://policy`/`edge://policy` check as every other deploy doc, below. If nothing shows up, the most likely causes, in rough order of likelihood: a typo in the domain name (it must be exact, including case), the browser not fully quit and relaunched, or (per Microsoft's own documentation) Edge specifically refusing to force-install a non-Add-ons-store extension unless the Mac is recognized as MDM-managed — a manually-placed file may not satisfy that check the same way a real MDM enrollment does. If Edge silently ignores Step 1 on an unenrolled test Mac even with the file correctly in place, that's the likely reason; Chrome has not been reported to have the equivalent restriction, but this hasn't been independently confirmed here either.

## Verification via `chrome://policy` / `edge://policy`

Same check as every other deploy doc, run locally:

1. Open `chrome://extensions` (or `edge://extensions`). Confirm PromptWarden is listed, enabled, with removal/disable controls unavailable (the force-install indicator).
2. Open `chrome://policy` (or `edge://policy`) → **Reload policies**. Confirm there's a card for the PromptWarden extension (Chrome/Edge render one per extension shipping a `managed_schema.json`) showing the `policy`/`extraHosts` values you pushed, with **no red "Error" badge**. A schema error most commonly means the `policy` value wasn't valid JSON *text* (the schema types it as `"string"`; `apps/extension/src/background.ts::resolvePolicy` calls `JSON.parse(managed.policy)` on whatever's there) — re-check for a stray escaping issue introduced by whichever tool you used to author the `.mobileconfig`.
3. Type a Luhn-valid test card number into a covered site's chat box and confirm the guardrail dialog fires per the pushed policy's `credit_card` action.
4. If nothing appears within a few minutes, use `chrome://policy`/`edge://policy` → **Reload policies** rather than waiting for the normal profile re-check interval, and confirm the profile actually installed: **System Settings** → **Privacy & Security** → **Profiles** (or **Profiles** pane on older macOS) should list it.

## Cross-linking from the other deploy docs

`DEPLOY_GPO.md`, `DEPLOY_INTUNE.md`, and `DEPLOY_GOOGLE_ADMIN.md` don't yet link to this document — adding "if your fleet is macOS, see `DEPLOY_MACOS.md`" pointers to each would improve discoverability, but editing those files is out of scope for the change that introduced this doc. Tracked as a follow-up.
