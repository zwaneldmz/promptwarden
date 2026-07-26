# Self-Hosted CRX Deployment (no store dependency)

**Verified: pending — needs a real managed tenant (founder action W3).**

Force-installs Chrome/Edge only accept a store URL or an update URL you host — Chrome and
Edge do not allow force-installing an arbitrary local `.crx` file directly. This doc packs
PromptWarden with your own signing key and serves the update manifest a self-hosted deploy
needs, so an install never depends on Chrome Web Store or Edge Add-ons review timing.

**Read the warning at the bottom before you start** — a self-hosted build and a store build
of the same source are two different extension IDs, and mixing them in one tenant breaks
policy delivery silently.

## Step 1 — Pack the extension with your own key

```bash
cd "/path/to/promptwarden"
npm install
npm run build:extension   # produces apps/extension/content.bundle.js and background.js
```

Then, using a Chrome binary (any Chrome-family browser works for packing):

```bash
# First time: no --pack-extension-key yet. This both packs apps/extension/
# AND generates apps/extension.pem next to it — a private key.
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --pack-extension="/path/to/promptwarden/apps/extension"

# Produces:
#   apps/extension.crx   (the packed, signed extension)
#   apps/extension.pem   (the private key — BACK THIS UP, see warning below)
```

For every subsequent build (after code changes), reuse the same key so the extension ID
stays stable:

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --pack-extension="/path/to/promptwarden/apps/extension" \
  --pack-extension-key="/path/to/promptwarden/apps/extension.pem"
```

**The extension ID is derived from the public half of this key**, not assigned by any store.
You can compute it ahead of packing if needed (Chrome derives it as a hash of the DER-encoded
public key), but the simplest path is: pack once, then read the ID Chrome reports in the
terminal output, or open `chrome://extensions` in Developer Mode and drag the `.crx` in to
see it (drag-install only works for local testing — see the warning below on why that's not
how you'll actually deploy this to a fleet).

## Step 2 — Host the CRX and an update manifest

Upload `extension.crx` to HTTPS-reachable storage you control (e.g.
`https://updates.example.com/promptwarden.crx`). Then write and host an update manifest XML
at a second URL (e.g. `https://updates.example.com/update.xml`) — this is the file Chrome
polls to learn there's a version to fetch:

```xml
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='YOUR_CRX_EXTENSION_ID'>
    <updatecheck codebase='https://updates.example.com/promptwarden.crx' version='0.1.0' />
  </app>
</gupdate>
```

Replace `YOUR_CRX_EXTENSION_ID` with the ID from Step 1 and `version` with the version in
`apps/extension/manifest.json`. Bump `version` in both the manifest (before re-packing) and
this XML every time you ship an update — Chrome compares this value against the installed
version to decide whether to fetch the new `.crx`.

## Step 3 — Force-install from the update URL, not the store URL

Same `ExtensionInstallForcelist` mechanism as the other three deploy docs, but the entry's
second half points at your `update.xml` instead of a store's update service:

```
<YOUR_CRX_EXTENSION_ID>;https://updates.example.com/update.xml
```

Use whichever delivery mechanism matches your fleet — Google Admin console
(`DEPLOY_GOOGLE_ADMIN.md` Step 1, same UI, this string as the entry), Intune
(`DEPLOY_INTUNE.md` Step 1), or GPO (`DEPLOY_GPO.md` Step 1). This doc doesn't repeat those
steps — only the entry value differs from the store-based versions in those docs.

You also need `ExtensionInstallSources` to allow Chrome to actually fetch a `.crx` from your
domain (some Chrome/Edge versions and policy combinations require this even for force-listed
extensions; harmless and recommended to set regardless):

- **Google Admin console**: **Devices** → **Chrome** → **Settings** → **Users & browsers** →
  find **Extension install sources**, add `https://updates.example.com/*`.
- **Intune / GPO (registry)**:
  ```
  HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallSources
    1  (REG_SZ) = https://updates.example.com/*
  ```
  (Edge: same value name/data under `HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallSources`.)

Push the same `policy`/`extraHosts` managed-storage JSON as the other deploy docs, keyed
under **this** extension ID (`YOUR_CRX_EXTENSION_ID`), not the store ID — see the warning
below for why that distinction matters here specifically.

## Verification

1. On a test device receiving the force-install policy, confirm the extension installs from
   your update URL (not the store) — `chrome://extensions` should show PromptWarden present;
   `chrome://policy` should list the `ExtensionInstallForcelist` entry pointing at
   `update.xml`, not `clients2.google.com`.
2. `chrome://policy` → **Reload policies** → confirm the PromptWarden extension policy card
   (keyed under `YOUR_CRX_EXTENSION_ID`) shows your pushed `policy`/`extraHosts` values with
   no schema error.
3. Bump the version in `manifest.json` and `update.xml`, re-pack with the same `.pem`,
   re-upload the `.crx`, and confirm a test device picks up the update within its normal
   Chrome update-check interval (or force it via `chrome://extensions` → Developer mode →
   **Update**).
4. Type a Luhn-valid test card number into a covered site's chat box and confirm the
   guardrail dialog fires.

## Warning: a self-hosted CRX has a different extension ID than the store build — never mix channels in one tenant

The Chrome Web Store and Edge Add-ons sign the extension with a key you never see, so the
extension IDs documented in `DEPLOY_GOOGLE_ADMIN.md`/`DEPLOY_INTUNE.md`/`DEPLOY_GPO.md`
(`<PROMPTWARDEN_EXTENSION_ID>` / `<PROMPTWARDEN_EDGE_EXTENSION_ID>`) are **not the same ID**
as `YOUR_CRX_EXTENSION_ID` from Step 1 of this doc, even though the source code is identical.
The ID is a hash of the packaging key's public half, not of the extension's contents or name.

Concretely, this means:

- A `chrome.storage.managed` policy pushed under the store ID does **nothing** for a device
  running the self-hosted build, and vice versa — `apps/extension/src/background.ts::resolvePolicy`
  reads managed storage scoped to whichever extension instance is actually installed on that
  device; there is no cross-ID fallback.
- A device force-installed from the store and later re-targeted at the self-hosted update URL
  (or the reverse) will **not** upgrade in place — Chrome sees two unrelated extension IDs, so
  you'd end up with both installed side by side (or, more likely, the second force-install
  failing to override the first's uninstall-protection), each with its own separate
  `chrome.storage.local` state and its own managed-policy binding.
- Never target both a store ID and a self-hosted ID at the same device or OU in the same
  policy push. Pick one channel per tenant/OU: **store** (once the Chrome Web Store / Edge
  Add-ons listing ships) **or** **self-hosted CRX**, and keep every device in that tenant on
  the same one. If you need to migrate a tenant from self-hosted to store (or back), treat it
  as an uninstall-then-reinstall of a different extension, with a fresh managed-policy push
  under the new ID — not an in-place update.
