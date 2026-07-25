/**
 * File-attachment scanning.
 *
 * Only text-like files are ever read, and never more than the first
 * MAX_TEXT_FILE_BYTES of one — this is the only gate a file ever passes, so a
 * partial scan of an oversized file is strictly better than skipping it.
 * Everything non-text-like is left completely untouched: no read, no
 * filename, no event — a binary upload must not become a new logging surface.
 *
 * Redaction of file content is out of scope for v1, so a rule configured to
 * `redact` is surfaced to the user as a warning (see `needsWarning`). The
 * policy's own action is still what gets logged, via `toLogRecord`.
 */
import { EvaluationResult, Finding, Policy, evaluate } from "@promptwarden/policy-engine";

export const MAX_TEXT_FILE_BYTES = 1024 * 1024; // 1 MB

const TEXT_EXTENSIONS = [
  ".csv", ".json", ".md", ".txt", ".tsv", ".log", ".xml",
  ".yaml", ".yml", ".sql", ".eml", ".ini", ".conf",
];

export function isTextLikeFile(file: File): boolean {
  const type = (file.type || "").toLowerCase();
  // `application/json` is text in every practical sense and is what browsers
  // report for .json picked from disk on some platforms.
  if (type.startsWith("text/") || type === "application/json") return true;
  const name = (file.name || "").toLowerCase();
  return TEXT_EXTENSIONS.some((ext) => name.endsWith(ext));
}

export interface FileScan {
  /**
   * Synthetic evaluation result spanning every scanned file, shaped so it can
   * go through `toLogRecord` like any prompt evaluation. `redactedText` is
   * deliberately empty: file content is never rewritten in v1.
   */
  result: EvaluationResult;
  categories: string[];
  blocked: boolean;
  needsWarning: boolean;
  /** Files that could not be read; fail-open, but visibly so in the dialog. */
  unreadable: number;
}

/** Read and evaluate `files`. Returns null when nothing was found. */
export async function scanFiles(files: File[], policy: Policy): Promise<FileScan | null> {
  const findings: Finding[] = [];
  let unreadable = 0;
  for (const file of files) {
    let text: string;
    try {
      // Oversized files are head-scanned rather than skipped: partial
      // coverage beats a trivial size-based bypass.
      const blob = file.size > MAX_TEXT_FILE_BYTES ? file.slice(0, MAX_TEXT_FILE_BYTES) : file;
      text = await blob.text();
    } catch {
      unreadable++;
      continue;
    }
    if (!text.trim()) continue;
    findings.push(...evaluate(text, policy).findings);
  }
  // ponytail: unreadable-only scans stay silent (fail open, no dialog);
  // surface them standalone if a stricter deployment needs fail-closed
  if (findings.length === 0) return null;

  const blocked = findings.some((f) => f.action === "block");
  return {
    result: { findings, redactedText: "", blocked, needsWarning: !blocked },
    categories: [...new Set(findings.map((f) => f.detector))],
    blocked,
    needsWarning: !blocked,
    unreadable,
  };
}
