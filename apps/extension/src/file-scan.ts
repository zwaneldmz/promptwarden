/**
 * File-attachment scanning.
 *
 * Two kinds of file are ever read — everything else is left completely
 * untouched: no read, no filename, no event, so a binary upload never
 * becomes a new logging surface.
 *
 *  - Text-like files (see `isTextLikeFile`): read directly, never more than
 *    the first MAX_TEXT_FILE_BYTES of one — this is the only gate a text
 *    file passes, so a partial scan of an oversized one is strictly better
 *    than skipping it outright.
 *  - Office Open XML files, .xlsx/.docx (see `isOfficeFile`): a ZIP's
 *    central directory lives at the end of the file, so unlike text there is
 *    no way to head-slice an oversized upload and still parse it — the
 *    whole file must be read into memory. Files over MAX_OFFICE_FILE_BYTES
 *    are skipped rather than partially read, and counted in `unreadable` so
 *    the guardrail dialog says so. Extraction goes through
 *    `extractOfficeText` (packages/policy-engine), a pure, dependency-free
 *    ZIP reader that inflates the document/sheet XML parts and strips them
 *    to plain text before handing it to the same `evaluate()` used for text.
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
  evaluate,
  extractOfficeText,
} from "@promptwarden/policy-engine";

export const MAX_TEXT_FILE_BYTES = 1024 * 1024; // 1 MB

/**
 * A ZIP's central directory lives at the end of the file, so an oversized
 * .xlsx/.docx can't be head-scanned the way an oversized text file can —
 * the whole thing has to be read. Capped instead: files over this size are
 * skipped and counted in `unreadable`, rather than read at all.
 */
export const MAX_OFFICE_FILE_BYTES = 20 * 1024 * 1024; // 20 MB

const TEXT_EXTENSIONS = [
  ".csv", ".json", ".md", ".txt", ".tsv", ".log", ".xml",
  ".yaml", ".yml", ".sql", ".eml", ".ini", ".conf",
];

/** Text files only — Office files are handled entirely separately below. */
export function isTextLikeFile(file: File): boolean {
  const type = (file.type || "").toLowerCase();
  // `application/json` is text in every practical sense and is what browsers
  // report for .json picked from disk on some platforms.
  if (type.startsWith("text/") || type === "application/json") return true;
  const name = (file.name || "").toLowerCase();
  return TEXT_EXTENSIONS.some((ext) => name.endsWith(ext));
}

const OFFICE_EXTENSIONS = [".xlsx", ".docx"];
const DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

/** Office Open XML files (.xlsx/.docx) only — never true for text-like files. */
export function isOfficeFile(file: File): boolean {
  const type = (file.type || "").toLowerCase();
  if (type === DOCX_MIME || type === XLSX_MIME) return true;
  const name = (file.name || "").toLowerCase();
  return OFFICE_EXTENSIONS.some((ext) => name.endsWith(ext));
}

/** Which office extractor applies, preferring the extension over MIME. */
function officeKind(file: File): "xlsx" | "docx" {
  const name = (file.name || "").toLowerCase();
  if (name.endsWith(".xlsx")) return "xlsx";
  if (name.endsWith(".docx")) return "docx";
  return (file.type || "").toLowerCase() === XLSX_MIME ? "xlsx" : "docx";
}

/** Any file `scanFiles` will attempt to read: text-like or Office. */
export function isScannableFile(file: File): boolean {
  return isTextLikeFile(file) || isOfficeFile(file);
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
    if (isOfficeFile(file)) {
      // No head-slicing possible (the central directory is at the end), so
      // an oversized office file is skipped outright rather than read.
      if (file.size > MAX_OFFICE_FILE_BYTES) {
        unreadable++;
        continue;
      }
      let text: string | null;
      try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        text = await extractOfficeText(bytes, officeKind(file));
      } catch {
        text = null;
      }
      if (text === null) {
        unreadable++;
        continue;
      }
      if (!text.trim()) continue;
      findings.push(...evaluate(text, policy).findings);
      continue;
    }

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
  // ponytail: unreadable-only scans stay silent (fail open, no dialog) even
  // under policy onError:"closed", which today governs whole-scan failures;
  // extend it to per-file read failures if a deployment needs that strictness
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
