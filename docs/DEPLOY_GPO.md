# Deploying PromptWarden via Windows Group Policy (on-prem AD)

**Note:** not yet verified against a real managed tenant; treat the steps below as unconfirmed until tested end-to-end.

For on-prem Active Directory fleets. If the fleet is Intune-managed instead, use
`DEPLOY_INTUNE.md` — the underlying registry paths below are identical, only the delivery
mechanism (GPO vs. MDM CSP) differs. Covers both Chrome and Edge.

## Prerequisites

- Group Policy Management Console (GPMC) with the Chrome and/or Edge ADMX templates loaded
  into the Central Store (`chrome.admx`/`chrome.adml` from Google, `msedge.admx`/`msedgeadml`
  and `msedgeupdate.admx`/`msedgeupdateadml` from Microsoft). These templates provide the
  standard, enumerated policies used in Step 1 (`ExtensionInstallForcelist`). They do **not**
  provide an entry for PromptWarden's own `policy`/`extraHosts` schema — that's set via raw
  registry values in Step 2, same as `DEPLOY_INTUNE.md`'s Option B, because a per-extension
  managed-storage schema is defined by the extension itself and Google/Microsoft don't (and
  can't, generically) ship an ADMX entry for every third-party extension's fields.
- The PromptWarden Chrome Web Store extension ID (`<PROMPTWARDEN_EXTENSION_ID>`) and Edge
  Add-ons extension ID (`<PROMPTWARDEN_EDGE_EXTENSION_ID>`) — placeholders until the store
  listings ship (see `DEPLOY_GOOGLE_ADMIN.md` / `DEPLOY_INTUNE.md` prerequisites).

## Step 1 — Force-install (ADMX-backed policy)

In the GPO editor, under **Computer Configuration** → **Policies** → **Administrative
Templates**:

- **Chrome**: **Google** → **Google Chrome** → **Extensions** → **Configure the list of
  force-installed apps and extensions**. Enable, then add one entry:
  ```
  <PROMPTWARDEN_EXTENSION_ID>;https://clients2.google.com/service/update2/crx
  ```
- **Edge**: **Microsoft Edge** → **Extensions** → **Extension Installation Forcelist**.
  Enable, then add one entry:
  ```
  <PROMPTWARDEN_EDGE_EXTENSION_ID>;https://edge.microsoft.com/extensionwebstorebase/v1/crx
  ```

These write to (for reference, if you'd rather set them via a raw registry GPP item instead
of the ADMX UI):

```
HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist
  1  (REG_SZ) = <PROMPTWARDEN_EXTENSION_ID>;https://clients2.google.com/service/update2/crx

HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist
  1  (REG_SZ) = <PROMPTWARDEN_EDGE_EXTENSION_ID>;https://edge.microsoft.com/extensionwebstorebase/v1/crx
```

(Value name `1` because `ExtensionInstallForcelist` is a policy **list** — Chrome/Edge read
each numbered `REG_SZ` under the key as one list entry; add `2`, `3`, … for additional
force-installed extensions, not for multiple values of this one.)

## Step 2 — Push the managed policy JSON (raw registry, no ADMX entry exists for this)

Set these values directly — via **Group Policy Preferences** → **Windows Settings** →
**Registry**, or a startup script run once via GPO, whichever your environment prefers.
The shape is defined by
[`apps/extension/managed_schema.json`](../apps/extension/managed_schema.json): a `policy`
string field and an `extraHosts` array-of-strings field.

```
HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<PROMPTWARDEN_EXTENSION_ID>\policy
  policy  (REG_SZ) = {"version":1,"name":"Default","hosts":["*"],"rules":[{"detector":"credit_card","action":"redact"},{"detector":"iban","action":"redact"},{"detector":"at_svnr","action":"block"}],"logging":"event","defaultAction":"warn","retentionDays":90}

HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<PROMPTWARDEN_EXTENSION_ID>\policy\extraHosts
  1  (REG_SZ) = https://internal-chat.example.com/*
  2  (REG_SZ) = https://llm.example.org/*
```

For Edge, mirror the same two keys under
`HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<PROMPTWARDEN_EDGE_EXTENSION_ID>\policy`.

Notes, same as the other two deploy docs:

- **`policy`'s value must itself be valid JSON text.** The schema types it as `"string"`, and
  `apps/extension/src/background.ts::resolvePolicy` calls `JSON.parse(managed.policy)` on
  whatever's there. Unlike the Google Admin console's JSON editor (`DEPLOY_GOOGLE_ADMIN.md`),
  a registry `REG_SZ` has no escaping step to get wrong here — type the JSON text directly as
  the value data, with no outer quoting beyond what `regedit`/GPP itself requires.
- **`extraHosts` is a list, so it's a subkey**, not a single value — this mirrors how
  `ExtensionInstallForcelist` (a Chrome/Edge-native list policy) is represented, and is the
  standard registry convention Chrome/Edge use for any schema `array` field pushed through
  the `3rdparty\extensions` path: one `REG_SZ` per array entry, named by numeric position.
- **Declaring `extraHosts` here does not yet make PromptWarden scan those hosts.** The
  background-side code that would act on a declared, permission-granted extra host
  (`chrome.scripting.registerContentScripts`) is specced, not implemented — see
  [`docs/HOST_COVERAGE.md`](HOST_COVERAGE.md). Don't promise it as live coverage to a pilot
  evaluator.

## Verification

1. On a domain-joined test machine already receiving the GPO, run `gpupdate /force`, then
   confirm the registry values landed:
   ```
   reg query "HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
   reg query "HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<PROMPTWARDEN_EXTENSION_ID>\policy"
   reg query "HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<PROMPTWARDEN_EXTENSION_ID>\policy\extraHosts"
   ```
2. Open `chrome://extensions` (or `edge://extensions`). Confirm PromptWarden appears,
   enabled, with removal/disable controls unavailable (force-install indicator).
3. Open `chrome://policy` (or `edge://policy`) → **Reload policies**. Confirm the
   PromptWarden extension card shows the pushed `policy`/`extraHosts` values with no schema
   error — same check as `DEPLOY_GOOGLE_ADMIN.md` Verification step 2.
4. Type a Luhn-valid test card number into a covered site's chat box and confirm the
   guardrail dialog fires per the pushed policy's `credit_card` action.
