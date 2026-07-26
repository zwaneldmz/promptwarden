# Deploying PromptWarden via Microsoft Intune (Chrome and Edge)

**Note:** not yet verified against a real managed tenant; treat the steps below as unconfirmed until tested end-to-end.

Covers Intune-managed Windows fleets, both browsers a DACH device fleet is likely to run:
Google Chrome and Microsoft Edge. If the fleet is instead managed via on-prem Active
Directory Group Policy, see `DEPLOY_GPO.md` — the underlying registry paths are the same,
only the delivery mechanism differs. There are two separate things to configure: (1) force
the install, (2) push the managed policy JSON. Do both for either browser you target.

## Prerequisites

- Intune with the Chrome and/or Edge Settings Catalog policies available (both ship built
  into Intune's Settings Catalog; no manual ADMX import is required for the *install*
  policies in Step 1). Confirm your tenant's catalog actually lists them before relying on
  this doc — catalog contents are Microsoft/Google-maintained and can shift between when this
  was written and when you read it.
- The PromptWarden **Chrome Web Store extension ID** (`<PROMPTWARDEN_EXTENSION_ID>` — not yet
  issued, see the same caveat as `DEPLOY_GOOGLE_ADMIN.md`) and, separately, the **Edge
  Add-ons extension ID** (`<PROMPTWARDEN_EDGE_EXTENSION_ID>` — Edge and Chrome Web Store
  listings get different extension IDs even for identical code, because the ID is derived
  from the store's own signing key, not the extension's). Neither store listing has shipped
  yet — check actual status before deploying.

## Step 1 — Force-install (Settings Catalog)

**Chrome:** Intune → **Devices** → **Configuration** → **Create** → **New policy** →
Platform **Windows 10 and later**, Profile type **Settings catalog**. Add the setting
**Google Chrome / Extensions / Extension install forcelist**. Add one entry:

```
<PROMPTWARDEN_EXTENSION_ID>;https://clients2.google.com/service/update2/crx
```

**Edge:** same flow, setting **Microsoft Edge / Extensions / Extension Installation
Forcelist**. Add one entry:

```
<PROMPTWARDEN_EDGE_EXTENSION_ID>;https://edge.microsoft.com/extensionwebstorebase/v1/crx
```

Assign each profile to the target device or user group. This is the Intune-native
equivalent of the registry values documented in `DEPLOY_GPO.md`
(`ExtensionInstallForcelist` under `Software\Policies\Google\Chrome\` /
`Software\Policies\Microsoft\Edge\`) — Settings Catalog writes the same underlying policy,
just without you touching the registry directly.

## Step 2 — Push the managed policy JSON (extension-specific "3rd-party" policy)

This is the part Intune's Settings Catalog **cannot** expose as a native toggle: `policy` and
`extraHosts` are PromptWarden's own schema
([`apps/extension/managed_schema.json`](../apps/extension/managed_schema.json)), not a
Chrome/Edge-shipped setting, so there is no pre-built catalog entry for it. Chrome and Edge
both read this class of setting from the registry path
`Software\Policies\<Google\Chrome|Microsoft\Edge>\3rdparty\extensions\<extension-id>\policy`
(the same path `DEPLOY_GPO.md` uses for on-prem AD). Intune has no first-class UI for
arbitrary per-extension registry trees, so use one of the two options below.

### Option A — Import as a custom ADMX (no script, Settings Catalog UI afterward)

Intune's Settings Catalog supports importing a custom ADMX/ADML pair
(**Devices** → **Configuration** → **Import ADMX**). Author a small ADMX that declares the
`policy` (string) and `extraHosts` (list) elements under the
`Software\Policies\Google\Chrome\3rdparty\extensions\<PROMPTWARDEN_EXTENSION_ID>\policy`
key (Edge: swap in `Software\Policies\Microsoft\Edge\...` and the Edge extension ID), then
configure the resulting policy like any built-in Settings Catalog setting. This is the more
"supported" long-term path but requires authoring and validating a custom ADMX, which is out
of scope for this doc to hand you pre-built (it is extension-ID-specific, and the ID isn't
issued yet — see Prerequisites).

### Option B — PowerShell platform script (copy-pasteable now)

Simpler to stand up immediately, at the cost of being a script instead of a native policy.
**Intune** → **Devices** → **Scripts and remediations** → **Platform scripts** → **Add**,
Windows, run in **System** context:

```powershell
$ids = @{
  "Google\Chrome" = "<PROMPTWARDEN_EXTENSION_ID>"
  "Microsoft\Edge" = "<PROMPTWARDEN_EDGE_EXTENSION_ID>"
}

$policyJson = '{"version":1,"name":"Default","hosts":["*"],"rules":[{"detector":"credit_card","action":"redact"},{"detector":"iban","action":"redact"},{"detector":"at_svnr","action":"block"}],"logging":"event","defaultAction":"warn","retentionDays":90}'
$extraHosts = @("https://internal-chat.example.com/*", "https://llm.example.org/*")

foreach ($browser in $ids.Keys) {
  $extId = $ids[$browser]
  if (-not $extId -or $extId -like "<*>") { continue }  # skip unset placeholders
  $base = "HKLM:\SOFTWARE\Policies\$browser\3rdparty\extensions\$extId\policy"
  New-Item -Path $base -Force | Out-Null
  New-ItemProperty -Path $base -Name "policy" -Value $policyJson -PropertyType String -Force | Out-Null

  $hostsKey = "$base\extraHosts"
  New-Item -Path $hostsKey -Force | Out-Null
  for ($i = 0; $i -lt $extraHosts.Count; $i++) {
    New-ItemProperty -Path $hostsKey -Name ($i + 1) -Value $extraHosts[$i] -PropertyType String -Force | Out-Null
  }
}
```

This mirrors the registry shape `DEPLOY_GPO.md` documents: `policy` is a single `REG_SZ`
holding the JSON-encoded policy string (same double-encoding note as
`DEPLOY_GOOGLE_ADMIN.md` — the value itself must be valid JSON *text*); `extraHosts` is a
subkey with numbered `REG_SZ` values, one per array entry (Chrome/Edge's registry
representation of a schema `array` field). Re-run the script (or let Intune's periodic
re-application do it) whenever the policy content changes — it's idempotent, not
incremental.

**`extraHosts` caveat:** same as `DEPLOY_GOOGLE_ADMIN.md` — declaring it here starts scanning
only once the matching optional host permission is also granted (via
`ExtensionSettings.runtime_allowed_hosts` or the popup's grant button) and the origins are
mirrored in the policy's `hosts` array; see [`docs/HOST_COVERAGE.md`](HOST_COVERAGE.md).

## Verification

1. On an enrolled test device, run `gpupdate` is not applicable (Intune, not GPO) — instead
   force an Intune sync: **Settings app** → **Accounts** → **Access work or school** →
   your account → **Info** → **Sync**. Or wait for the normal check-in interval.
2. `chrome://policy` (or `edge://policy`) → **Reload policies**. Confirm PromptWarden is
   installed (Step 1) and its extension policy card shows the `policy`/`extraHosts` values
   from Step 2 with no schema error (same red-badge check as `DEPLOY_GOOGLE_ADMIN.md`
   Verification step 2).
3. Confirm the registry values landed as expected:
   `reg query "HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<PROMPTWARDEN_EXTENSION_ID>\policy"`
   (adjust the hive path for Edge).
4. Type a Luhn-valid test card number into a covered site's chat box and confirm the
   guardrail dialog fires per the pushed policy.
