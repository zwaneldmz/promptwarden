# Deploying PromptWarden via Google Admin Console (Chrome)

**Note:** not yet verified against a real managed tenant; treat the steps below as unconfirmed until tested end-to-end.

Force-install PromptWarden across a fleet and push a managed policy, no end-user install
step or permission prompt required. This doc covers Chrome; see `DEPLOY_INTUNE.md` for
Windows/Intune-managed fleets and `DEPLOY_GPO.md` for on-prem Active Directory.

## Prerequisites

- A Google Workspace / Chrome Enterprise Admin console with Chrome browser management
  enabled for the target org unit.
- The PromptWarden **Chrome Web Store extension ID**. The Chrome Web Store listing has not
  shipped yet. Until then, use `<PROMPTWARDEN_EXTENSION_ID>` as a placeholder everywhere below
  and replace it once the store assigns a real ID — **do not** substitute a self-hosted CRX's
  extension ID here; those are different IDs (see `DEPLOY_SELF_HOSTED_CRX.md`) and
  force-installing the wrong one will not resolve.

## Step 1 — Force-install the extension

1. Go to **admin.google.com** → **Devices** → **Chrome** → **Apps & extensions** →
   **Users & browsers**.
2. In the org-unit tree on the left, select the OU you want covered (or the root OU for the
   whole domain).
3. Click the **+** (yellow circle) at the bottom right → **Add Chrome app or extension by ID**.
4. Paste `<PROMPTWARDEN_EXTENSION_ID>` → click **Save**.
5. On the newly added row for PromptWarden, set **Installation policy** to
   **Force install**.
6. Click **Save** at the top right of the page.

Devices in that OU will install PromptWarden on their next policy fetch (typically within a
few hours; `chrome://policy` → **Reload policies** forces an immediate check on a test
device).

## Step 2 — Push the managed policy JSON

The exact shape below is defined by
[`apps/extension/managed_schema.json`](../apps/extension/managed_schema.json) — the extension
validates against this schema, and Chrome enforces the schema's types before the JSON ever
reaches the extension. There are exactly two top-level fields:

| Field | Type | Meaning |
|---|---|---|
| `policy` | string | A PromptWarden policy document, **JSON-encoded as a string** (see the warning below) |
| `extraHosts` | array of strings | Additional origin match patterns to scan beyond the default 7 (declaration only today — see the caveat below) |

1. Still on **Apps & extensions** → **Users & browsers**, click the PromptWarden row (not the
   **+**) to open its detail panel.
2. Find **Policy for extensions** and click the pencil/edit icon.
3. Paste the JSON below into the editor, adjusted for your policy content, then **Save**.

```json
{
  "policy": "{\"version\":1,\"name\":\"Default\",\"hosts\":[\"*\"],\"rules\":[{\"detector\":\"credit_card\",\"action\":\"redact\"},{\"detector\":\"iban\",\"action\":\"redact\"},{\"detector\":\"at_svnr\",\"action\":\"block\"}],\"logging\":\"event\",\"defaultAction\":\"warn\",\"retentionDays\":90}",
  "extraHosts": ["https://internal-chat.example.com/*", "https://llm.example.org/*"]
}
```

**Why `policy` is a string inside a string, not a nested object:** `managed_schema.json`
declares `policy`'s type as `"string"`, not `"object"`. The extension reads it with
`JSON.parse(managed.policy)` (`apps/extension/src/background.ts::resolvePolicy`) — so the
value you paste for the `policy` key must itself be valid JSON *text*, with its internal
quotes escaped, exactly as shown above. Pasting an unescaped nested object there will fail
Chrome's managed-schema validation (see verification step 2 below) rather than silently doing
the wrong thing.

**`extraHosts` caveat — read before promising it to a pilot evaluator.** Setting `extraHosts`
declares intent; scanning starts only once the matching optional host permission is granted.
Per [`docs/HOST_COVERAGE.md`](HOST_COVERAGE.md), the background-side registration
(`chrome.scripting.registerContentScripts`) is shipped: it reconciles the declared
`extraHosts` against the actually-granted permissions on startup and on managed-storage
changes. Grant the permission via `ExtensionSettings.runtime_allowed_hosts` (see
`docs/HOST_COVERAGE.md` "How an admin extends coverage") or the popup's "Enable extended
coverage" button, and mirror the origins in the policy's `hosts` array. Any exposure number
you report must state which hosts it covered (`docs/HOST_COVERAGE.md` "Reporting
requirement").

Policy precedence is enforced in code, not just convention: managed storage always wins over
any locally configured policy (`apps/extension/src/background.ts::resolvePolicy` reads
`chrome.storage.managed` first and only falls back to `chrome.storage.local` if managed
storage has no `policy` key).

## Verification

1. **On a test device already in the target OU**, open `chrome://extensions`. Confirm
   PromptWarden is listed, enabled, and that its card shows it was **installed by your
   organization** (the Remove/enable-disable controls are unavailable — that's the
   force-install indicator, not a bug).
2. Open `chrome://policy`. Click **Reload policies** to force an immediate refetch. Below the
   main browser-policy table, look for a card for the PromptWarden extension (Chrome renders
   one card per extension that ships a `managed_schema.json`). Confirm:
   - The `policy` and `extraHosts` values shown match what you pushed.
   - There is **no red "Error"** badge on either field. A schema error most commonly means the
     `policy` value wasn't escaped as a JSON string (see the warning above) — re-check the
     escaping and re-save.
3. On the same test device, navigate to one of the 7 covered hosts (e.g. `https://claude.ai`)
   and type a Luhn-valid test card number into the chat box. Confirm the guardrail dialog
   appears per your pushed policy's `credit_card` action.
4. If nothing appears within a few minutes of pushing policy, use
   `chrome://policy` → **Reload policies** rather than waiting for the normal ~1–24h fetch
   interval, and confirm the device is actually in the OU you targeted in Step 1.
