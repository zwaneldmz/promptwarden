# PromptWarden — Threat Model

**Verified: pending — needs a real managed tenant (founder action W3).**

This document exists to be checked against the code, not taken on faith. Every claim below
cites the file that makes it true or false. If the cited code changes and this document
doesn't, this document is wrong — file an issue.

## What PromptWarden stops

Typed, pasted, or uploaded text-and-office content, sent from a browser in the Chrome family
(Chrome, Edge, and other Chromium-based browsers — MV3 extensions are portable across the
family; see [ENGINEERING_PLAN.md](ENGINEERING_PLAN.md) Phase 1, which explicitly defers a
Firefox port) to one of the 7 AI sites named in
`apps/extension/manifest.json`'s `content_scripts[0].matches`
(`chatgpt.com`, `chat.openai.com`, `claude.ai`, `gemini.google.com`, `copilot.microsoft.com`,
`chat.mistral.ai`, `www.perplexity.ai`), on a device where the extension is installed and
active for that origin.

Interception is selector-less and covers four submission mechanics, all in the capture phase
(`apps/extension/src/content.ts`):

- Enter keydown inside an editable element
- click on a likely send button
- a genuine `<form>` submit event
- paste of text, and change/drop of a file on a `<input type="file">`

Matched text is evaluated against the active policy
(`packages/policy-engine/src/engine.ts::evaluate`) using checksum-validated detectors —
Luhn for card numbers, mod-97 for IBANs, a check digit for Austrian SVNRs, plus email, phone,
API-key, and custom regex rules (`packages/policy-engine/src/detectors.ts`) — and the
configured action (allow/warn/redact/block) is applied before the content ever reaches the
page's own submit handler. This path never calls a network API or an LLM; the only thing
that ever leaves the content script is the output of `toLogRecord`
(`packages/policy-engine/src/engine.ts::toLogRecord`), which is the single privacy gate for
every logging surface in the codebase (enforced by ground rule, see
[ENGINEERING_PLAN.md](ENGINEERING_PLAN.md) "Engineering ground rules").

## What PromptWarden does NOT stop

Read this section before you trust the product. None of the following is a bug to be fixed
in the current architecture — each is a boundary of what a browser extension can see or is
scoped to see.

**Direct API access.** A user (or a script, or an internal tool) calling an AI provider's API
directly — `curl`, a Python script, a backend integration — never touches a browser tab, so
no content script ever runs. PromptWarden has no visibility into API traffic at all; it is a
browser-UI guardrail, not a network proxy or DLP gateway.

**Mobile apps.** The ChatGPT, Claude, Gemini, Copilot, etc. iOS/Android apps are native
applications, not browser tabs running `content_scripts`. An MV3 Chrome extension cannot run
inside them under any configuration.

**Unmanaged browsers and devices.** Coverage requires the extension to be installed and
enabled in that specific browser profile. A personal device, a non-Chrome-family browser, a
guest profile, or a managed browser where an admin hasn't force-installed the extension (see
`DEPLOY_GOOGLE_ADMIN.md`, `DEPLOY_INTUNE.md`, `DEPLOY_GPO.md`) sees no interception at all —
there is no server-side enforcement layer that reaches devices the extension isn't running on.

**Screenshots and photos.** The interception points are DOM events on an editable element, a
file input, and clipboard paste of text — a photo of a screen, a phone camera picture of a
document, or a screenshot pasted as an image is image data, not the text/office-document
channels the content script inspects. `apps/extension/src/file-scan.ts` only reads
text-like files and Office Open XML (`.xlsx`/`.docx`); nothing in the codebase does OCR or
image inspection.

**PDF and legacy Office uploads.** `apps/extension/src/file-scan.ts` (header comment) is
explicit: "NOT scanned at all in v1: PDF, and the legacy binary Office formats (.doc, .xls,
.ppt) — none of those are ZIP/XML containers, so they need a different (unbuilt) extractor.
They fall through untouched, same as any other binary." A `.pdf`, `.doc`, `.xls`, or `.ppt`
attachment uploads with zero scanning, zero logging, and no dialog — it is indistinguishable
from any other binary the extension deliberately leaves alone.

**Non-matched AI sites.** Coverage is exactly the 7 hosts in `manifest.json` today. An
internal chat gateway, a self-hosted LLM UI, or any AI vendor not on that list is invisible to
PromptWarden unless an admin extends coverage: [`docs/HOST_COVERAGE.md`](HOST_COVERAGE.md)'s
`extraHosts` mechanism (managed-storage declaration + optional-permission grant +
background-side dynamic registration) is shipped. A deployment that has not declared and
granted extra hosts is, by construction, a 7-host deployment, and any exposure number
reported from it must say so ([`docs/HOST_COVERAGE.md`](HOST_COVERAGE.md) "Reporting
requirement").

**A determined insider.** PromptWarden is enforced entirely client-side, in the same browser
process the user controls. Concretely:

- A user with DevTools open, or with a userscript/console access to the page, can call a
  site's own internal send path directly (many chat SPAs expose framework state/handlers that
  don't route through the DOM events — keydown, click, submit — the content script listens
  on), bypassing interception without touching the extension at all.
- A user can disable or remove the extension from `chrome://extensions` on any device where
  it isn't force-installed by policy (force-install via managed deployment removes the
  disable/remove controls; see the three `DEPLOY_*.md` docs — this is a mitigation, not a
  guarantee against a local admin).
- `bypassNextSubmit`, the one-shot flag that lets a user's own "Send anyway" choice pass a
  second interception check without re-showing the dialog, is disarmed by any *trusted* input
  event or a 2-second timer (`apps/extension/src/content.ts`, `armBypassNextSubmit` /
  `disarmBypassNextSubmit`) — it is not a standing bypass, and a page script cannot forge a
  trusted (`isTrusted: true`) event to exploit the window, since only real user input disarms
  it and the flag only lets through the literal resumed submission, not arbitrary later ones.
  This is documented here because it is exactly the kind of narrow, time-boxed exception a
  reviewer should be able to find and check, not because it is currently exploitable.
- In standalone (non-managed) mode, policy lives in `chrome.storage.local`
  (`apps/extension/src/background.ts::resolvePolicy`), which any extension the user installs
  with the right permissions, or the user via DevTools, can read or overwrite. Managed
  storage (`chrome.storage.managed`) is read-only to the device and always wins over local
  when present — this is the enforcement floor for a managed deployment, not for standalone
  use.

No client-side control defeats a user who controls the machine and is willing to work around
it; PromptWarden's design goal is to catch the default, unthinking path (paste customer data,
hit enter), not to survive a user actively trying to exfiltrate data past it.

**Copilot inside Word/Excel.** Microsoft 365 Copilot embedded in the Word/Excel/PowerPoint
desktop applications is not a website — it doesn't run in a browser tab, so
`content_scripts.matches` can never target it regardless of host list. This is a categorically
different surface from `copilot.microsoft.com` (the one PromptWarden's manifest does cover),
which is a browser-based chat site.

## Enforcement boundary: isolated world vs. shared DOM

MV3 content scripts execute in an **isolated JavaScript world**: a separate global scope from
the page's own scripts, so `window`, variables, and function references the content script
defines are invisible to the page and vice versa. This is what makes `stopImmediatePropagation`
in `content.ts` effective at all — it stops *other event listeners registered on that DOM
node* from seeing the event, including the page's own.

It does **not** create a sealed sandbox around the DOM itself: the isolated world still shares
the live DOM with the page. Concretely, in the file-upload path
(`apps/extension/src/content.ts::onFileInputEvent`), the browser has already populated
`input.files` with the picked `FileList` by the time our capture-phase listener runs — holding
the event (`stopImmediatePropagation`) only stops the page's *event handler* from firing while
the guardrail evaluates the file; it does not hide `input.files` from a page script that reads
it independently, e.g. by polling `input.files` on a timer rather than waiting for a `change`
event. A page actively trying to observe an upload the guardrail is in the middle of
evaluating has a window — typically well under a second, bounded by `scanFiles`'s read+evaluate
time — in which it can read the held file directly. This is a structural property of how MV3
isolated worlds relate to the DOM, not a bug in this codebase, and it is the honest limit of
"held" in the file-upload dialog copy: held from the page's *submission* path, not hidden from
a page script that goes looking.

## Where these claims come from (check them yourself)

| Claim | File |
|---|---|
| The 7 matched hosts | `apps/extension/manifest.json` → `content_scripts[0].matches` |
| Inline path never networks | `apps/extension/src/content.ts` header comment; CI's no-egress gate (`docs/ENGINEERING_PLAN.md` Phase 0) |
| Single logging gate | `packages/policy-engine/src/engine.ts::toLogRecord` |
| Detectors and checksums | `packages/policy-engine/src/detectors.ts` |
| PDF / legacy Office not scanned | `apps/extension/src/file-scan.ts` header comment |
| Non-matched hosts / `extraHosts` status | `docs/HOST_COVERAGE.md` |
| Managed vs. local policy precedence | `apps/extension/src/background.ts::resolvePolicy` |
| `bypassNextSubmit` arm/disarm | `apps/extension/src/content.ts` (`armBypassNextSubmit`, `disarmBypassNextSubmit`, the `isTrusted`-gated `input` listener) |
