/**
 * CLI event sink.
 *
 * Mirrors the browser extension's event-buffer semantics (see
 * apps/extension/src/background.ts: MAX_BUFFERED, DEFAULT_RETENTION_DAYS,
 * retentionDaysOf, isExpired) against a local JSONL file instead of
 * chrome.storage.local: append one `toLogRecord` line per call to
 * `${XDG_STATE_HOME:-~/.local/state}/wardkeep/events.jsonl`, mode 0600,
 * capped at 500 records and age-pruned by the resolved policy's
 * `retentionDays` (default 90).
 *
 * Concurrency: the initial append is a single `write()` of one JSON line,
 * always well under PIPE_BUF (POSIX guarantees at least 512 bytes; Linux and
 * macOS are both 4096), issued through a file opened with the `a` (O_APPEND)
 * flag — that single write is atomic with respect to any other process
 * appending to the same file concurrently, so no lockfile is needed for it,
 * unlike the extension's chrome.storage.local, which is read-modify-write
 * and needs its own writeQueue. The cap/prune pass below IS a
 * read-modify-write (read the whole file, filter, write a temp file,
 * `rename()` over the original); the rename is atomic, so the file can never
 * be observed half-written, but two concurrent prunes racing each other can
 * each miss the other's freshly appended line when computing "the last 500".
 * That is an acceptable trade for a local, single-user CLI: the failure mode
 * is "one extra event survives a prune that should have caught it," never
 * corruption or silent data loss beyond that line.
 */

import { mkdir, open, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { EvaluationResult, Policy, toLogRecord } from "@wardkeep/policy-engine";

const MAX_BUFFERED = 500;
const DEFAULT_RETENTION_DAYS = 90;
const DAY_MS = 24 * 60 * 60 * 1000;

function eventsFilePath(): string {
  const stateHome = process.env.XDG_STATE_HOME || join(homedir(), ".local", "state");
  return join(stateHome, "wardkeep", "events.jsonl");
}

/** Same defensive read as the extension's retentionDaysOf: anything missing, non-numeric, or non-positive falls back to the documented default. */
function retentionDaysOf(policy: Policy): number {
  const raw = policy.retentionDays;
  return typeof raw === "number" && Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_RETENTION_DAYS;
}

/** True if `entry.ts` parses to a time at or before `cutoffMs`. Entries without a parseable `ts` are never treated as expired. */
function isExpired(entry: unknown, cutoffMs: number): boolean {
  const ts = entry && typeof entry === "object" ? (entry as Record<string, unknown>).ts : undefined;
  if (typeof ts !== "string") return false;
  const t = Date.parse(ts);
  return !Number.isNaN(t) && t < cutoffMs;
}

/**
 * Re-read the events file, drop expired lines and any that fail to parse,
 * cap to the most recent MAX_BUFFERED, and rewrite only if that changed
 * anything (skips the temp-file + rename on the common case of an append
 * under both the age and count limits).
 */
async function pruneEventsFile(filePath: string, policy: Policy): Promise<void> {
  let raw: string;
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    return; // nothing to prune
  }
  const lines = raw.split("\n").filter((line) => line.length > 0);

  const cutoff = Date.now() - retentionDaysOf(policy) * DAY_MS;
  const kept: string[] = [];
  for (const line of lines) {
    let entry: unknown;
    try {
      entry = JSON.parse(line);
    } catch {
      continue; // drop unparsable lines rather than propagate corruption
    }
    if (!isExpired(entry, cutoff)) kept.push(line);
  }
  const capped = kept.length > MAX_BUFFERED ? kept.slice(kept.length - MAX_BUFFERED) : kept;

  if (capped.length === lines.length) return; // nothing was pruned

  const tmpPath = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  const body = capped.length > 0 ? capped.join("\n") + "\n" : "";
  await writeFile(tmpPath, body, { mode: 0o600 });
  await rename(tmpPath, filePath);
}

/**
 * Append one `toLogRecord(result, policy, surface)` line to the CLI's event
 * log. A no-op when the policy's logging mode/findings mean there is nothing
 * to record. Never throws — a failed write (permissions, disk full, a
 * corrupted existing file, …) must not break the caller that is trying to
 * scan something.
 */
export async function recordEvent(result: EvaluationResult, policy: Policy, surface: string): Promise<void> {
  try {
    const record = toLogRecord(result, policy, surface);
    if (record === null) return;

    const filePath = eventsFilePath();
    await mkdir(dirname(filePath), { recursive: true, mode: 0o700 });

    const line = JSON.stringify(record) + "\n";
    const handle = await open(filePath, "a", 0o600);
    try {
      await handle.appendFile(line, "utf8");
    } finally {
      await handle.close();
    }

    await pruneEventsFile(filePath, policy);
  } catch {
    // Swallow everything — see doc comment above.
  }
}
