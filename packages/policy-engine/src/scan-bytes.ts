/**
 * Byte-level file-scanning core, shared by every adapter (browser extension,
 * CLI, MCP gateway, …) so none of them can fork the size caps, the
 * text/office extension and MIME lists, or the scan logic itself — see
 * `apps/extension/src/file-scan.ts` for the browser-specific `File`/`Blob`
 * wrapper that reads bytes with bounded memory and delegates here.
 *
 * Two kinds of file are ever read — everything else (`classifyFile` returns
 * "skip") is left completely untouched: no read, no event, so a binary
 * upload never becomes a new logging surface.
 *
 *  - Text-like files: scanned directly, never more than the first
 *    MAX_TEXT_FILE_BYTES — this is the only gate a text file passes, so a
 *    partial scan of an oversized one is strictly better than skipping it
 *    outright.
 *  - Office Open XML files, .xlsx/.docx: a ZIP's central directory lives at
 *    the end of the file, so unlike text there is no way to head-slice an
 *    oversized upload and still parse it — the whole file must be read into
 *    memory. Files over MAX_OFFICE_FILE_BYTES are skipped rather than
 *    partially read, and reported as unreadable. Extraction goes through
 *    `extractOfficeText`, a pure, dependency-free ZIP reader that inflates
 *    the document/sheet XML parts and strips them to plain text.
 *
 * NOT scanned at all: PDF, and the legacy binary Office formats (.doc,
 * .xls, .ppt) — none of those are ZIP/XML containers, so they classify as
 * "skip" and fall through untouched, same as any other binary.
 */
import { Finding, Policy } from "./policy.js";
import { evaluate } from "./engine.js";
import { extractOfficeText } from "./extract-office.js";

export const MAX_TEXT_FILE_BYTES = 1024 * 1024; // 1 MB

/**
 * A ZIP's central directory lives at the end of the file, so an oversized
 * .xlsx/.docx can't be head-scanned the way an oversized text file can — the
 * whole thing has to be read. Capped instead: files over this size are
 * skipped and reported unreadable, rather than read at all.
 */
export const MAX_OFFICE_FILE_BYTES = 20 * 1024 * 1024; // 20 MB

export const TEXT_EXTENSIONS = [
  ".csv", ".json", ".md", ".txt", ".tsv", ".log", ".xml",
  ".yaml", ".yml", ".sql", ".eml", ".ini", ".conf",
];

export const OFFICE_EXTENSIONS = [".xlsx", ".docx"];
export const DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
export const XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

export type FileClass = "text" | "office" | "skip";

/**
 * Pure classification of a file name (with optional MIME type) into one of
 * the two scannable kinds, or "skip" for everything else. MIME is checked
 * before the extension in each category — `application/json` is what some
 * platforms report for a `.json` picked from disk, with no `text/` prefix,
 * and the OOXML MIME types are what a browser reports regardless of the
 * uploaded file's extension.
 */
export function classifyFile(name: string, mimeType?: string): FileClass {
  const type = (mimeType || "").toLowerCase();
  const lowerName = (name || "").toLowerCase();

  if (type === DOCX_MIME || type === XLSX_MIME) return "office";
  if (OFFICE_EXTENSIONS.some((ext) => lowerName.endsWith(ext))) return "office";

  // `application/json` is text in every practical sense.
  if (type.startsWith("text/") || type === "application/json") return "text";
  if (TEXT_EXTENSIONS.some((ext) => lowerName.endsWith(ext))) return "text";

  return "skip";
}

/** Which office extractor applies, preferring the extension over MIME. */
function officeKind(name: string, mimeType?: string): "xlsx" | "docx" {
  const lowerName = (name || "").toLowerCase();
  if (lowerName.endsWith(".xlsx")) return "xlsx";
  if (lowerName.endsWith(".docx")) return "docx";
  return (mimeType || "").toLowerCase() === XLSX_MIME ? "xlsx" : "docx";
}

export interface ScanBytesResult {
  findings: Finding[];
  /** True when the file could not be read/decoded/extracted; fail-open, but
   *  visibly so — callers should count this so a guardrail dialog can say
   *  "N files could not be scanned" rather than staying silent. */
  unreadable: boolean;
}

/**
 * Classify `name`/`mimeType`, decode or extract `bytes` accordingly, and
 * evaluate the result against `policy`. Applies the same size rules
 * documented above: text is head-scanned to MAX_TEXT_FILE_BYTES regardless
 * of how many bytes the caller passed in, and an office file whose bytes
 * exceed MAX_OFFICE_FILE_BYTES is reported unreadable without being
 * extracted. A file that classifies as "skip" yields no findings and is not
 * reported unreadable — it was never a scan candidate at all.
 *
 * Never throws: any failure (a decode error, a malformed archive, …) comes
 * back as `unreadable: true` instead of propagating, so one bad file never
 * aborts a caller's whole-batch scan.
 */
export async function scanBytes(
  name: string,
  bytes: Uint8Array,
  policy: Policy,
  mimeType?: string,
): Promise<ScanBytesResult> {
  try {
    const kind = classifyFile(name, mimeType);
    if (kind === "skip") return { findings: [], unreadable: false };

    if (kind === "office") {
      // No head-slicing possible (the central directory is at the end), so
      // an oversized office file is skipped outright rather than read.
      if (bytes.length > MAX_OFFICE_FILE_BYTES) return { findings: [], unreadable: true };
      const text = await extractOfficeText(bytes, officeKind(name, mimeType));
      if (text === null) return { findings: [], unreadable: true };
      if (!text.trim()) return { findings: [], unreadable: false };
      return { findings: evaluate(text, policy).findings, unreadable: false };
    }

    // Text: never decode more than the head-scan cap, regardless of how
    // much of the file `bytes` the caller happened to pass in — partial
    // coverage of an oversized file beats a trivial size-based bypass.
    const head = bytes.length > MAX_TEXT_FILE_BYTES ? bytes.subarray(0, MAX_TEXT_FILE_BYTES) : bytes;
    const text = new TextDecoder().decode(head);
    if (!text.trim()) return { findings: [], unreadable: false };
    return { findings: evaluate(text, policy).findings, unreadable: false };
  } catch {
    return { findings: [], unreadable: true };
  }
}
