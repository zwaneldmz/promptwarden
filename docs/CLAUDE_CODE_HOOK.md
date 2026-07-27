# Claude Code hook (`wardkeep hook claude-code`)

Wires Wardkeep's policy engine into Claude Code as two hooks: `UserPromptSubmit` (the
human's typed/pasted prompt) and `PreToolUse` (every tool call's arguments). Implemented in
[`apps/cli/src/hooks/claude-code.ts`](../apps/cli/src/hooks/claude-code.ts); see that file's
module doc for the full per-branch reasoning. This document covers the operational contract:
what it gates, what it deliberately does not, how to wire it up, and how to verify it is
actually live.

The stdin/stdout contract below was verified against the official Claude Code hooks
documentation (`code.claude.com/docs/en/hooks` and `/hooks-guide`) on 2026-07-26, not assumed
from `docs/ROADMAP.md` alone — the roadmap's own text says to trust the docs on any
disagreement. None was found: every claim the roadmap makes about `UserPromptSubmit` (no
prompt rewrite, fails open on a 30s timeout) and `PreToolUse` (runs before the permission
check, `updatedInput` rewrites tool arguments) is confirmed by the official reference.

## What it gates

| Event | Covers | Redaction? |
|---|---|---|
| `UserPromptSubmit` | The prompt text as submitted, every turn, every permission mode (including `dontAsk`) | No — see below |
| `PreToolUse` | Every string-bearing field of `tool_input`, at any nesting depth: Bash `command`, Write/Edit `content`/`new_string`, WebFetch `url`/`prompt`, the Agent tool's subagent `prompt`, and MCP tool arguments (`mcp__<server>__<tool>`) | Yes, via `updatedInput` |

`PreToolUse` is registered with **no matcher**, deliberately: a matcher scoped to `Bash|Write|Edit`
would leave any tool not on that list — a new built-in tool, a plugin-bundled MCP server, a
tool this document was written before — silently ungated. Inside the hook itself, tool input
is walked generically (every string value in the object, not a hardcoded per-field list), for
the same reason.

## What it does NOT gate

This is the more important half. Restated from `docs/ROADMAP.md` §3's coverage map, because
installing this hook must never be read as "no sensitive data leaves this machine via Claude
Code":

- **Files the agent reads on its own** — `Read`, `Grep`, auto-loaded `CLAUDE.md`, skills, and
  any other context the model pulls in itself. `PreToolUse` on `Read` sees the *path*, not the
  file's bytes; there is no hook that sees post-read content before it enters the model's
  context. Installing this hook does not make "no IBANs leave this machine" true.
- **`UserPromptSubmit` cannot rewrite the prompt.** Confirmed against the official reference:
  there is no `updatedPrompt` field, and the only prompt-adjacent output is
  `hookSpecificOutput.additionalContext` (adds text, doesn't remove any) and a top-level
  `decision: "block"` (all-or-nothing). A `redact`-action policy rule therefore degrades to the
  same block/allow-with-warning choice as `warn` on this event — see "Configuration" below. If
  you need in-place prompt redaction, there isn't a channel for it anywhere in Claude Code
  today; only `PreToolUse`'s `updatedInput` can rewrite anything.
- **`UserPromptSubmit` fails open on a 30-second timeout.** Confirmed: "command hooks" default
  to a 30s timeout on this event specifically (other events default to 10 minutes), and on
  timeout the prompt reaches the model unscanned — the hook's output is simply discarded. This
  CLI's own evaluation is sub-millisecond, so a timeout here would mean something external is
  slow (a cold Node start on an overloaded machine, disk contention on the policy/events
  files), not the policy engine itself. There is nothing this adapter can do about this; it is
  a property of the harness.
- **Data typed inside an interactive TUI other than at the prompt-submission boundary** — not
  applicable to `UserPromptSubmit` itself (that *is* the submission boundary and is covered),
  but relevant if you're comparing this to a shell-layer mechanism: those cannot see inside a
  running TUI at all, this hook can, but only at the moment of submission.
- **Hosted/server-side tools** (e.g. a provider-executed web search) — no hook fires; the call
  never touches the local process.
- **A user who removes the hook, edits their own `settings.json`, or passes
  `--dangerously-skip-permissions`** — `PreToolUse` denies still apply under
  `bypassPermissions` (confirmed: "fire before any permission-mode check... blocks the tool
  even in `bypassPermissions` mode"), but a user with filesystem access to their own settings
  can simply delete the hook entry. The enforcement floor for a fleet is managed settings
  (organization-level hook configuration a user's own settings cannot remove), the same
  floor-vs-default distinction as the browser extension's managed storage.
- **Fixed:** `CARD_CANDIDATE` used to include a trailing space or hyphen in the match span, so
  a `redact` action rewrote `"card=4532... 0366 https://x"` to
  `"card=[REDACTED:CARD]https://x"` — a missing space, not a missing redaction. Cosmetic in the
  browser, but in a rewritten shell command it could change what actually runs, which is why it
  mattered most on this surface. The pattern now ends on a digit
  (`packages/policy-engine/src/detectors.ts`), with a regression test in
  `test/fp-corpus.test.ts`.

## Fail-open by design

Any internal error — a malformed envelope, closed/empty stdin, a policy that fails to load, an
unsupported event, an unanticipated bug — makes `runClaudeCodeHook` exit `0` with **nothing**
written to stdout. This is a deliberate trade, not an oversight: a crash or a stray non-JSON
byte on stdout can corrupt Claude Code's hook-response parsing for the whole turn, and this is
a guardrail that must never be the reason a user's session breaks. Failing open means behaving
exactly as if the hook were not installed — availability over enforcement, the same choice
`docs/ROADMAP.md` and `docs/ENGINEERING_PLAN.md` make everywhere else a guardrail failure can
otherwise take the whole harness down with it.

Concretely, this hook's own process **always exits 0** on a successful run (decisions are
communicated entirely through stdout JSON — an empty stdout on `allow`/`observe`, a JSON object
otherwise) — it never uses the `exit 2` blocking-error convention the official docs also
support, so there is exactly one channel to reason about and test, instead of two ("exit 2 +
stderr" for one event, "exit 0 + JSON" for the other).

## Configuration

One environment variable / flag pair, both equivalent:

- `WARDKEEP_HOOK_ALLOW_WARN=1` (or `true`/`yes`/`on`)
- `wardkeep hook claude-code --allow-warn`

Only affects `UserPromptSubmit`, and only `warn`/`redact`-level findings. By default those
BLOCK the prompt (see "What it does NOT gate" above for why `redact` can't do anything softer
here); setting this downgrades that to allow-with-warning — the prompt goes through, and the
user sees a `systemMessage` plus the model receives a non-sensitive `additionalContext` note
(both built exclusively from `toUserMessage`, so neither can ever quote the matched value). A
`block`-action finding always blocks, regardless of this setting — it only ever loosens
warn/redact, never a hard block.

`PreToolUse` has no equivalent flag: `warn` always allows-and-records, `redact` always rewrites
via `updatedInput`, `block` always denies. There is nothing to make configurable there — the
`updatedInput` channel exists, so `redact` behaves exactly as the policy document says.

## Install

Add to `~/.claude/settings.json` (all your projects) or `.claude/settings.json` (one project,
shareable via version control):

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "wardkeep hook claude-code" }
        ]
      }
    ],
    "PreToolUse": [
      {
        "hooks": [
          { "type": "command", "command": "wardkeep hook claude-code" }
        ]
      }
    ]
  }
}
```

No `matcher` key on either entry — omitting it (rather than setting `"matcher": ""`) is
equivalent and is what the official examples do for events/uses that mean "every occurrence."
For `PreToolUse` this is required, not cosmetic: see "What it gates" above.

If you also run other `PreToolUse` hooks that rewrite the **same** tool's input, be aware of an
official, documented limitation unrelated to this hook: "When multiple `PreToolUse` hooks
return `updatedInput`... the last one to finish takes effect... hooks run in parallel, the
order is non-deterministic." Don't stack two input-rewriting hooks on the same tool.

To downgrade `UserPromptSubmit`'s warn/redact handling fleet-wide, set the environment variable
in the command itself so it isn't relying on the invoking shell's environment:

```json
{ "type": "command", "command": "WARDKEEP_HOOK_ALLOW_WARN=1 wardkeep hook claude-code" }
```

Policy resolution follows the CLI's usual precedence (`docs/ROADMAP.md` §2): a root-owned
`/etc/wardkeep/policy.json` is the fleet floor a user's own settings can't touch; see
`apps/cli/src/policy.ts`'s module doc for the full chain.

## Verify

Confirm the hook is registered:

```
claude
> /hooks
```

Select `UserPromptSubmit` and `PreToolUse` and confirm `wardkeep hook claude-code` appears
under each.

Then run a live canary — a synthetic, Luhn-valid test card number that is not a real card (the
same fixture this repo's own tests use, safe to paste anywhere):

```
4532 0151 1283 0366
```

1. **`UserPromptSubmit` canary**: in a Claude Code session, submit a prompt containing that
   number (e.g. "here's a card on file: 4532 0151 1283 0366, can you note it down"). Under the
   built-in default policy (`credit_card: warn`), you should see the prompt blocked with a
   Wardkeep reason mentioning `credit_card` — never the digits themselves. If it goes
   through unblocked, the hook isn't wired up; check `/hooks` and the settings file location
   (project vs. user vs. managed — see "Configure hook location" in the official docs).
2. **`PreToolUse` canary**: ask Claude to run `echo "card: 4532 0151 1283 0366"` via Bash.
   Under a policy with `credit_card: redact`, the executed command should show
   `[REDACTED:CARD]` in place of the digits (check the transcript / `Ctrl+O`), never the raw
   number. Under `credit_card: block`, the tool call should be denied with a reason mentioning
   `credit_card` and no digits.
3. **Negative control**: run the same two probes with an ordinary, non-sensitive prompt/command
   and confirm nothing is blocked and no Wardkeep output appears — the point of the canary
   is to prove the gate is *live*, not to prove it blocks everything.

Do not use a real card number for this, even your own — the canary only needs to be
Luhn-valid and issuer-prefixed to be treated as a candidate; it does not need to be real, and a
real number would needlessly put real payment data through a terminal transcript and (if
`logging: "event"` or stricter) the local event log.

## Debug

If the hook doesn't seem to be firing at all: start Claude Code with `claude --debug-file
/tmp/claude.log`, reproduce, then `grep -i wardkeep /tmp/claude.log` — this shows every
hook invocation, its exit code, and its stdout/stderr, including cases where this adapter fails
open (silently) that would otherwise be invisible from the transcript.

Locally-recorded events (when `logging` is `"event"` or `"content"`) land at
`${XDG_STATE_HOME:-~/.local/state}/wardkeep/events.jsonl`, one JSON line per non-clean
outcome, tagged with `host: "claude-code:UserPromptSubmit"` or `"claude-code:PreToolUse"`.

## Verified behavior

Exercised against real `claude -p` sessions (Claude Code 2.1.215), policy loaded from
`$WARDKEEP_POLICY`:

| Scenario | Result |
|---|---|
| `UserPromptSubmit`, prompt contains a Luhn-valid card, `credit_card: block` | Prompt rejected: `UserPromptSubmit operation blocked by hook: Wardkeep blocked this prompt (block: credit_card).` The model never saw it. |
| `UserPromptSubmit`, clean prompt | Passes through untouched, no added latency visible to the user. |
| `UserPromptSubmit`, `credit_card: redact` | Blocked, with the reason naming `WARDKEEP_HOOK_ALLOW_WARN=1` as the downgrade — this event cannot rewrite a prompt. |
| `PreToolUse`, model writes a card via `Write`, `credit_card: redact` | Allowed with `updatedInput`; the file on disk contained `[REDACTED:CARD]on file`. The card never reached the filesystem. |
| `PreToolUse`, model writes an `sk-` key, `api_key: block` | Denied; no file created. |
| `PreToolUse`, connection URI with credentials in a `Bash` command | Denied. |

Two things that testing made obvious:

- **Ordering.** `UserPromptSubmit` fires first, so a prompt that itself contains sensitive data
  is rejected before any tool runs. Testing the `PreToolUse` path therefore requires input the
  *model* produces, not input you type.
- **Redaction used to eat an adjacent separator.** The rewritten input read
  `[REDACTED:CARD]on file` — the card pattern's final optional separator was inside the match
  span. Fixed in `detectors.ts` (the span can only end on a digit); rewritten input now reads
  `[REDACTED:CARD] on file`, covered by a regression test.

## Policy choice for a repo whose tests contain fixtures

Blocking `credit_card`/`iban` in a repository whose own test suite holds checksum-valid
fixtures makes that repository un-editable: a `PreToolUse` scan of an `Edit` touching
`bench.test.ts` sees a real card and denies it. This repo's `.wardkeep.json` therefore sets
those to `observe` (recorded, never interrupts) and keeps `block` for the categories that never
legitimately appear in source — `private_key`, `connection_string`, `api_key`, `jwt`. Any repo
with security fixtures needs the same split.
