/**
 * File-attachment scanning: the browser-specific `File`/`Blob` wrapper
 * around the environment-agnostic core in
 * `packages/policy-engine/src/scan-bytes.ts`. Everything about *what* gets
 * scanned and *how* (the size caps, the text/office extension and MIME
 * lists, classification, decoding, Office extraction, evaluation) lives in
 * the engine so every adapter shares it; this file's job is narrower: read
 * bytes out of a `File` with bounded memory and hand them to `scanBytes`.
 *
 *  - Text-like files (see `isTextLikeFile`): read directly, never more than
 *    the first MAX_TEXT_FILE_BYTES of one — sliced at the `Blob` level
 *    before reading, so an oversized text file is never fully loaded into
 *    memory just to scan its first megabyte.
 *  - Office Open XML files, .xlsx/.docx (see `isOfficeFile`): a ZIP's
 *    central directory lives at the end of the file, so unlike text there is
 *    no way to head-slice an oversized upload and still parse it — the
 *    whole file must be read into memory. Files over MAX_OFFICE_FILE_BYTES
 *    are skipped rather than read at all (checked against `file.size`
 *    before ever calling `arrayBuffer()`), and counted in `unreadable` so
 *    the guardrail dialog says so.
 *
 * NOT scanned at all in v1: PDF, and the legacy binary Office formats
 * (.doc, .xls, .ppt) — none of those are ZIP/XML containers, so they need a
 * different (unbuilt) extractor. They fall through untouched, same as any
 * other binary.
 *
 * Redaction of file content is out of scope for v1, so a rule configured to
 * `redact` is surfaced to the user as a warning (see `needsWarning`). The
 * policy's own action is still what gets logged, via `toLogRecord`.
 */
import {
  EvaluationResult,
  Finding,
  Policy,
  MAX_TEXT_FILE_BYTES,
  MAX_OFFICE_FILE_BYTES,
  classifyFile,
  scanBytes,
} from "@promptwarden/policy-engine";

export { MAX_TEXT_FILE_BYTES, MAX_OFFICE_FILE_BYTES };

/** Text files only — Office files are handled entirely separately below. */
export function isTextLikeFile(file: File): boolean {
  return classifyFile(file.name, file.type) === "text";
}

/** Office Open XML files (.xlsx/.docx) only — never true for text-like files. */
export function isOfficeFile(file: File): boolean {
  return classifyFile(file.name, file.type) === "office";
}

/** Any file `scanFiles` will attempt to read: text-like or Office. */
export function isScannableFile(file: File): boolean {
  return classifyFile(file.name, file.type) !== "skip";
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
    const kind = classifyFile(file.name, file.type);
    if (kind === "skip") continue;

    if (kind === "office") {
      // No head-slicing possible (the central directory is at the end), so
      // an oversized office file is skipped outright rather than read —
      // checked against `file.size` before ever touching `arrayBuffer()`.
      if (file.size > MAX_OFFICE_FILE_BYTES) {
        unreadable++;
        continue;
      }
      let bytes: Uint8Array;
      try {
        bytes = new Uint8Array(await file.arrayBuffer());
      } catch {
        unreadable++;
        continue;
      }
      const scanned = await scanBytes(file.name, bytes, policy, file.type);
      if (scanned.unreadable) {
        unreadable++;
        continue;
      }
      findings.push(...scanned.findings);
      continue;
    }

    // Text: sliced at the Blob level before reading, so an oversized file
    // is never fully loaded into memory just to scan its first megabyte —
    // partial coverage beats a trivial size-based bypass.
    let bytes: Uint8Array;
    try {
      const blob = file.size > MAX_TEXT_FILE_BYTES ? file.slice(0, MAX_TEXT_FILE_BYTES) : file;
      bytes = new Uint8Array(await blob.arrayBuffer());
    } catch {
      unreadable++;
      continue;
    }
    const scanned = await scanBytes(file.name, bytes, policy, file.type);
    if (scanned.unreadable) {
      unreadable++;
      continue;
    }
    findings.push(...scanned.findings);
  }
  // NOTE: unreadable-only scans stay silent under onError:"closed", which
  // today only governs whole-scan failures, not per-file read errors.
  if (findings.length === 0) return null;

  const blocked = findings.some((f) => f.action === "block");
  // Observe-actioned findings are recorded but never interrupt; only
  // warn/redact-actioned ones warrant the dialog (redact surfaces as warn
  // for files since file content can't be rewritten).
  const needsWarning =
    !blocked && findings.some((f) => f.action === "warn" || f.action === "redact");
  return {
    result: { findings, redactedText: "", blocked, needsWarning },
    categories: [...new Set(findings.map((f) => f.detector))],
    blocked,
    needsWarning,
    unreadable,
  };
}
