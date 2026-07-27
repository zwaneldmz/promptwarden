/**
 * `wardkeep scan` — the CLI's own front door. Reads text from --stdin
 * and/or one or more --file paths, evaluates it against the resolved
 * policy, records one event, and prints a summary built exclusively from
 * `toUserMessage` (categories/actions only — see packages/policy-engine/src/
 * engine.ts's doc comment: this is the second privacy gate, and unlike
 * `toLogRecord` it is not governed by `policy.logging` at all).
 *
 * File input goes through the engine's `scanBytes`, the same entry point the
 * browser extension's file-scan.ts uses, so both adapters share one set of
 * size caps and file-type rules. Forking them would quietly invalidate
 * docs/THREAT_MODEL.md's coverage claims for one adapter.
 *
 * Exit codes: 0 clean, 1 blocked, 2 warn-and-`--strict`, 3 config error.
 */

import { readFile } from "node:fs/promises";
import { EvaluationResult, Finding, Policy, evaluate, scanBytes, toUserMessage } from "@wardkeep/policy-engine";
import { recordEvent } from "./events.js";
import { loadPolicy } from "./policy.js";

const USAGE = `Usage: wardkeep scan [--stdin] [--file <path>]... [--json] [--strict] [--surface <label>]

  --stdin              Read text from standard input.
  --file <path>        Scan a file (repeatable). .xlsx/.docx are text-extracted; anything else is read as plain text.
  --json               Print a machine-readable result instead of the human summary.
  --strict             Exit 2 (instead of 0) when the result is warn-only, with nothing blocked.
  --surface <label>    Label recorded as the event's host/surface (default "cli:scan").

Exit codes: 0 clean, 1 blocked, 2 warn+--strict, 3 config error.
`;

interface ScanArgs {
  stdin: boolean;
  files: string[];
  json: boolean;
  strict: boolean;
  surface?: string;
  error?: string;
}

function parseScanArgs(argv: string[]): ScanArgs {
  const args: ScanArgs = { stdin: false, files: [], json: false, strict: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--stdin") {
      args.stdin = true;
    } else if (a === "--file") {
      const value = argv[++i];
      if (value === undefined) {
        args.error = "wardkeep scan: --file requires a path";
        return args;
      }
      args.files.push(value);
    } else if (a === "--json") {
      args.json = true;
    } else if (a === "--strict") {
      args.strict = true;
    } else if (a === "--surface") {
      const value = argv[++i];
      if (value === undefined) {
        args.error = "wardkeep scan: --surface requires a label";
        return args;
      }
      args.surface = value;
    } else if (a === "--help" || a === "-h") {
      args.error = ""; // signal "print usage, exit 3" without an error line
      return args;
    } else {
      args.error = `wardkeep scan: unknown argument "${a}"`;
      return args;
    }
  }
  return args;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Scan one file through the engine's shared `scanBytes`, or return null if
 * it could not be read or extracted. An unscannable file is a scan failure
 * (exit 3), never silently "clean" — that failure mode is documented in
 * docs/ROADMAP.md §1.2 item 5.
 *
 * `redact` counts toward needsWarning here: a scanner cannot rewrite a file
 * in place, so a redact rule surfaces as a warning, matching how the browser
 * extension treats file uploads.
 *
 * `surface` is forwarded to `scanBytes`'s trailing `host` parameter — the
 * same resolved surface label passed to the stdin `evaluate()` call and to
 * `recordEvent` below, so a host-scoped policy exception applies uniformly
 * regardless of which input source produced the text.
 */
async function scanOneFile(
  filePath: string,
  policy: Policy,
  surface: string,
): Promise<{ findings: Finding[]; blocked: boolean; needsWarning: boolean } | null> {
  let bytes: Buffer;
  try {
    bytes = await readFile(filePath);
  } catch {
    return null;
  }
  const { findings, unreadable } = await scanBytes(filePath, new Uint8Array(bytes), policy, undefined, surface);
  if (unreadable) return null;
  const blocked = findings.some((f) => f.action === "block");
  const needsWarning =
    !blocked && findings.some((f) => f.action === "warn" || f.action === "redact");
  return { findings, blocked, needsWarning };
}

interface SourcedFinding extends Finding {
  source: string;
}

export async function runScan(argv: string[]): Promise<number> {
  const args = parseScanArgs(argv);
  if (args.error !== undefined) {
    if (args.error) process.stderr.write(args.error + "\n");
    process.stderr.write(USAGE);
    return 3;
  }

  let policy;
  let policySource: string;
  try {
    ({ policy, source: policySource } = await loadPolicy());
  } catch (err) {
    process.stderr.write(`${(err as Error).message}\n`);
    return 3;
  }

  // Resolved once, up front, so the same label reaches every evaluate()/
  // scanBytes() call below AND the `recordEvent` call further down — a
  // host-scoped exception and the event it's meant to suppress must agree
  // on what this surface is called.
  const surface = args.surface ?? "cli:scan";

  const perSource: {
    label: string;
    result: { findings: Finding[]; blocked: boolean; needsWarning: boolean };
  }[] = [];

  if (args.stdin) {
    perSource.push({ label: "stdin", result: evaluate(await readStdin(), policy, surface) });
  }
  for (const filePath of args.files) {
    const result = await scanOneFile(filePath, policy, surface);
    if (result === null) {
      process.stderr.write(`wardkeep scan: could not read or extract text from "${filePath}"\n`);
      return 3;
    }
    perSource.push({ label: filePath, result });
  }

  if (perSource.length === 0) {
    process.stderr.write("wardkeep scan: no input — pass --stdin and/or --file <path>\n");
    process.stderr.write(USAGE);
    return 3;
  }

  const findings: SourcedFinding[] = perSource.flatMap((s) =>
    s.result.findings.map((f) => ({ ...f, source: s.label })),
  );
  const blocked = perSource.some((s) => s.result.blocked);
  // `redact` counts as a warning here, unlike the engine's own needsWarning,
  // which excludes it because the browser rewrites the textarea in place. A
  // scanner cannot rewrite its caller's stdin or a file on disk, so a redact
  // finding has to surface — otherwise `scan` reports "clean" on input that
  // does contain sensitive data. Derived over all findings so stdin and file
  // sources agree.
  const needsWarning =
    !blocked && findings.some((f) => f.action === "warn" || f.action === "redact");

  // A synthetic, multi-source EvaluationResult purely for toUserMessage/
  // recordEvent: both only ever read `findings`/`blocked`/`needsWarning` off
  // it (toLogRecord never touches start/end/redactedText), so concatenating
  // findings from independently-evaluated sources is safe even though their
  // start/end offsets are only meaningful within their own source text.
  const merged: EvaluationResult = { findings, redactedText: "", blocked, needsWarning };

  await recordEvent(merged, policy, surface);

  const message = toUserMessage(merged);
  const summaryFindings = findings.map((f) => ({ source: f.source, detector: f.detector, action: f.action }));

  if (args.json) {
    const out = {
      policySource,
      surface,
      blocked,
      needsWarning,
      message,
      findings: summaryFindings,
    };
    process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  } else {
    process.stdout.write(`wardkeep scan — policy: ${policySource}\n`);
    process.stdout.write(message + "\n");
    process.stdout.write(`Result: ${blocked ? "BLOCKED" : needsWarning ? "WARN" : "clean"}\n`);
  }

  if (blocked) return 1;
  if (needsWarning) return args.strict ? 2 : 0;
  return 0;
}
