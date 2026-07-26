/**
 * Claude Code hook adapter (`promptwarden hook claude-code`).
 *
 * Reads a single hook JSON envelope from stdin, dispatches on
 * `hook_event_name`, and writes a decision to stdout as JSON — or nothing at
 * all, for an unremarkable outcome. See docs/CLAUDE_CODE_HOOK.md for the full
 * contract, the settings.json wiring, and — just as important — what this
 * hook does NOT cover.
 *
 * Two events are handled, matching docs/ROADMAP.md §2's interception table.
 * That table was verified against the official Claude Code hooks reference
 * (code.claude.com/docs/en/hooks and /hooks-guide) before writing a line of
 * this file, per the task's instruction to trust the docs over the roadmap
 * on any disagreement — none was found; every claim below is confirmed by
 * both sources:
 *
 *  - UserPromptSubmit: gates the human's typed/pasted prompt. Confirmed: the
 *    event has no prompt-rewriting mechanism at all (no `updatedPrompt`
 *    field exists — the only levers are `hookSpecificOutput.additionalContext`
 *    and a top-level `decision`/`reason` pair that can only block, never
 *    rewrite), so `redact` cannot be honoured here. Both `warn` and `redact`
 *    findings get the same treatment: BLOCK by default (a flagged prompt that
 *    is silently let through defeats the point of the hook), configurable
 *    down to allow-with-warning via `PROMPTWARDEN_HOOK_ALLOW_WARN=1` or
 *    `--allow-warn`. A `block`-level finding always blocks regardless of the
 *    flag — that override only ever loosens warn/redact, never a hard block.
 *    Confirmed: this event's command hooks default to a 30s timeout and
 *    **fail open** on it — the prompt reaches the model unscanned. Nothing in
 *    this file can change that; it is a property of the harness, not of this
 *    adapter, and is restated in docs/CLAUDE_CODE_HOOK.md so it is never
 *    quietly assumed away.
 *
 *  - PreToolUse: gates every tool call's arguments before Claude Code's own
 *    permission check runs — confirmed: "PreToolUse hooks fire before any
 *    permission-mode check, in every permission mode, including
 *    `dontAsk`... blocks the tool even in `bypassPermissions` mode." Tool
 *    input is walked generically — every string value at any depth of
 *    `tool_input`, never a hardcoded per-tool field list — so a new built-in
 *    tool, an MCP tool (`mcp__<server>__<tool>`), or the Agent tool's
 *    subagent `prompt` field are all covered without ever naming them here.
 *    `redact`-level findings use `updatedInput`, which replaces the tool's
 *    arguments outright and is the *only* redaction channel available
 *    anywhere in this CLI (UserPromptSubmit cannot rewrite a prompt).
 *    Registered with no matcher (fires on every tool), exactly as
 *    docs/ROADMAP.md §2 specifies — a matcher-scoped hook leaves any unlisted
 *    tool ungated by construction.
 *
 * Every persisted record goes through `recordEvent` (itself routed through
 * the engine's `toLogRecord`), and every string written to stdout goes
 * through `toUserMessage` — categories and actions only, never a matched
 * value. This is not optional hygiene: a UserPromptSubmit block `reason` is
 * fed straight back into the model's context, and a PreToolUse
 * `permissionDecisionReason` becomes the tool-call error the model sees, so
 * either one quoting the matched IBAN would exfiltrate exactly what the
 * block was meant to prevent (docs/ROADMAP.md §2's "second privacy gate").
 *
 * Fail-open by design: the outer try/catch in `runClaudeCodeHook` guarantees
 * that ANY unexpected failure — a malformed envelope, empty/closed stdin, a
 * policy that fails to load, an unsupported event, a bug in this file —
 * exits 0 with nothing written to stdout. A crash or a stray non-JSON byte on
 * stdout can corrupt Claude Code's hook-response parsing for the whole turn;
 * failing open (behaving exactly as if no hook were installed) is strictly
 * safer than any alternative for a guardrail that must never be the reason a
 * user's session breaks. This is a deliberate coverage/availability
 * trade-off, not an oversight — restated in docs/CLAUDE_CODE_HOOK.md.
 */
import {
  Action,
  EvaluationResult,
  Finding,
  Policy,
  evaluate,
  toUserMessage,
} from "@promptwarden/policy-engine";
import { recordEvent } from "../events.js";
import { loadPolicy } from "../policy.js";

/* --------------------------------- stdin ---------------------------------- */

/** Read all of stdin as text. Never throws; a closed/absent/TTY stdin reads as "". */
async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return "";
  try {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
  } catch {
    return "";
  }
}

/* ---------------------------------- flags ---------------------------------- */

const ALLOW_WARN_ENV = "PROMPTWARDEN_HOOK_ALLOW_WARN";

function truthy(value: string | undefined): boolean {
  if (value === undefined) return false;
  const v = value.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

/** Downgrades UserPromptSubmit's default block-on-warn/redact to allow-with-warning. */
function isAllowWarnEnabled(argv: string[]): boolean {
  return argv.includes("--allow-warn") || truthy(process.env[ALLOW_WARN_ENV]);
}

/* --------------------------------- envelope --------------------------------- */

interface HookEnvelope {
  hook_event_name?: unknown;
  prompt?: unknown;
  tool_name?: unknown;
  tool_input?: unknown;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/* ------------------------------- output helpers ------------------------------ */

/** Write exactly one JSON object to stdout. The only shape stdout may ever take on a non-clean outcome — never mixed with plain text (see the general hook contract). */
function writeJson(obj: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

/**
 * `evaluate()` already excludes `allow`-action findings, so the values seen
 * here are always observe/warn/redact/block. Not exported by the engine —
 * `apps/cli/src/policy.ts`'s `ACTION_SEVERITY` and `engine.ts`'s internal
 * `severity` are each their own private copy of the same literal map, so
 * this is a third, matching the existing convention rather than inventing a
 * new export surface for one caller.
 */
const SEVERITY: Record<Action, number> = { allow: 0, observe: 1, warn: 2, redact: 3, block: 4 };

/** Highest-severity action across `findings`, or null when there are none (the clean case). */
function topAction(findings: Finding[]): Action | null {
  let top: Action | null = null;
  for (const f of findings) {
    if (top === null || SEVERITY[f.action] > SEVERITY[top]) top = f.action;
  }
  return top;
}

/** Build a synthetic multi-finding EvaluationResult for recordEvent/toUserMessage, mirroring the same trick apps/cli/src/scan.ts uses to merge independently-evaluated sources — both consumers only ever read `findings`/`blocked`/`needsWarning`, never `redactedText` or per-finding offsets across sources. */
function mergeResult(findings: Finding[]): EvaluationResult {
  return {
    findings,
    redactedText: "",
    blocked: findings.some((f) => f.action === "block"),
    needsWarning: !findings.some((f) => f.action === "block") && findings.some((f) => f.action === "warn"),
  };
}

/* ------------------------------ UserPromptSubmit ------------------------------ */

async function handleUserPromptSubmit(envelope: HookEnvelope, policy: Policy, argv: string[]): Promise<void> {
  const prompt = typeof envelope.prompt === "string" ? envelope.prompt : "";
  const result = evaluate(prompt, policy);
  const action = topAction(result.findings);

  if (action === null) return; // clean: allow, silent — no output at all

  if (action === "observe") {
    // Silent baseline mode: record and let the prompt through with no signal
    // to the user or the model, exactly like the extension's observe action.
    await recordEvent(result, policy, "claude-code:UserPromptSubmit");
    return;
  }

  const summary = toUserMessage(result);

  if (action === "warn" || action === "redact") {
    // No prompt-rewriting mechanism exists on this event (see module doc),
    // so redact degrades to exactly the same handling as warn.
    await recordEvent(result, policy, "claude-code:UserPromptSubmit");

    if (isAllowWarnEnabled(argv)) {
      writeJson({
        systemMessage: `PromptWarden: prompt allowed with warning (${summary}). This hook cannot redact a submitted prompt — only block or allow it through.`,
        hookSpecificOutput: {
          hookEventName: "UserPromptSubmit",
          additionalContext: `PromptWarden flagged this prompt (${summary}) but allowed it under the configured warn mode. Do not restate or repeat the flagged content.`,
        },
      });
      return;
    }

    writeJson({
      decision: "block",
      reason: `PromptWarden blocked this prompt (${summary}). This hook cannot redact a submitted prompt, only block or allow it through; set ${ALLOW_WARN_ENV}=1 (or pass --allow-warn) to downgrade warn/redact findings to allow-with-warning.`,
    });
    return;
  }

  // block — never downgradable by the allow-warn flag.
  await recordEvent(result, policy, "claude-code:UserPromptSubmit");
  writeJson({
    decision: "block",
    reason: `PromptWarden blocked this prompt (${summary}).`,
  });
}

/* --------------------------------- PreToolUse --------------------------------- */

type PathSegment = string | number;

interface StringLeaf {
  path: PathSegment[];
  text: string;
}

/**
 * Recursively collect every string leaf in `value`, with its path from the
 * root. Deliberately generic — no per-tool field list — so Bash `command`,
 * Write/Edit `content`/`new_string`, WebFetch `url`/`prompt`, the Agent
 * tool's `prompt`, and arbitrary MCP tool arguments are all covered by the
 * same walk. An unlisted or future tool is covered automatically instead of
 * silently unprotected.
 */
/**
 * Depth ceiling: the envelope is JSON from the harness, and a deeply nested
 * tool input must not blow the stack — that would take the hook down and, on
 * the fail-open path, wave the call through unscanned. Anything past this
 * depth is left unscanned instead of crashing.
 */
const MAX_WALK_DEPTH = 64;

function collectStringLeaves(
  value: unknown,
  path: PathSegment[],
  out: StringLeaf[],
  depth = 0,
): void {
  if (depth > MAX_WALK_DEPTH) return;
  if (typeof value === "string") {
    out.push({ path, text: value });
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => collectStringLeaves(v, [...path, i], out, depth + 1));
  } else if (isRecord(value)) {
    for (const [k, v] of Object.entries(value)) {
      collectStringLeaves(v, [...path, k], out, depth + 1);
    }
  }
}

/** Set a value at an arbitrary path inside a plain JSON structure (objects/arrays only — the only shapes `collectStringLeaves` ever produces a path into). Explicit `any` here: generic JSON-tree navigation by a runtime-computed path has no more specific type to offer. */
function setAtPath(root: unknown, path: PathSegment[], value: unknown): void {
  let cur: any = root;
  for (let i = 0; i < path.length - 1; i++) cur = cur[path[i]];
  cur[path[path.length - 1]] = value;
}

async function handlePreToolUse(envelope: HookEnvelope, policy: Policy): Promise<void> {
  const toolInput = envelope.tool_input;
  if (!isRecord(toolInput)) return; // no string-bearing shape to scan: allow, silent

  const leaves: StringLeaf[] = [];
  collectStringLeaves(toolInput, [], leaves);

  const leafResults = leaves.map((leaf) => ({ ...leaf, result: evaluate(leaf.text, policy) }));
  const allFindings = leafResults.flatMap((lr) => lr.result.findings);
  const action = topAction(allFindings);

  if (action === null) return; // clean across every field: allow, silent

  const merged = mergeResult(allFindings);
  const summary = toUserMessage(merged);

  if (action === "observe") {
    await recordEvent(merged, policy, "claude-code:PreToolUse");
    return; // silent baseline mode, same as UserPromptSubmit's observe path
  }

  if (action === "block") {
    await recordEvent(merged, policy, "claude-code:PreToolUse");
    writeJson({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: `PromptWarden blocked this tool call (${summary}).`,
      },
    });
    return;
  }

  if (action === "redact") {
    // Rewrite only the leaves that actually carry a redact-level finding —
    // fields that merely warned/observed are left untouched, but their
    // categories still show up in `summary` so nothing is silently dropped
    // from the record even though only the redact-level text is rewritten.
    // `updatedInput` REPLACES the tool's arguments — the hooks reference:
    // "updatedInput directly under hookSpecificOutput replaces a tool's
    // arguments before it runs." So it has to be the complete input with
    // redactions applied, not just the keys that changed: sending only the
    // touched keys would drop every other argument (a Write would lose its
    // file_path) and break the call.
    const updatedInput = structuredClone(toolInput);
    for (const lr of leafResults) {
      if (lr.result.findings.some((f) => f.action === "redact")) {
        setAtPath(updatedInput, lr.path, lr.result.redactedText);
      }
    }

    await recordEvent(merged, policy, "claude-code:PreToolUse");
    writeJson({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "allow",
        permissionDecisionReason: `PromptWarden redacted this tool call (${summary}).`,
        updatedInput,
      },
    });
    return;
  }

  // warn
  await recordEvent(merged, policy, "claude-code:PreToolUse");
  writeJson({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      permissionDecisionReason: `PromptWarden allowed this tool call with a warning (${summary}).`,
    },
  });
}

/* ---------------------------------- entry ---------------------------------- */

export async function runClaudeCodeHook(argv: string[]): Promise<number> {
  try {
    const raw = await readStdin();
    if (raw.trim() === "") return 0; // closed/empty stdin: nothing to gate, fail open

    let envelope: unknown;
    try {
      envelope = JSON.parse(raw);
    } catch {
      return 0; // malformed envelope: fail open rather than ever emit malformed output
    }
    if (!isRecord(envelope)) return 0;

    const { policy } = await loadPolicy();

    switch (envelope.hook_event_name) {
      case "UserPromptSubmit":
        await handleUserPromptSubmit(envelope as HookEnvelope, policy, argv);
        return 0;
      case "PreToolUse":
        await handlePreToolUse(envelope as HookEnvelope, policy);
        return 0;
      default:
        return 0; // an event this adapter doesn't handle: fail open, no output
    }
  } catch {
    // Absolute backstop — see module doc. Nothing above should throw once
    // stdin is read and parsed, but a policy-load failure (loadPolicy()
    // rejects on a present-but-broken /etc or $PROMPTWARDEN_POLICY file) is
    // exactly the kind of real-world case this exists for.
    return 0;
  }
}
