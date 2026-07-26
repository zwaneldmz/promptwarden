/**
 * Text extraction for Office Open XML uploads (.xlsx / .docx). Both formats
 * are ZIP containers of XML parts; this is a minimal, dependency-free ZIP
 * reader (no DOM, no network, nothing beyond `DecompressionStream`) that
 * locates the XML parts holding document text, inflates them, strips markup
 * down to text, and hands the result to the same `evaluate()` flow as any
 * other file. Never throws, even on malformed input.
 *
 * Central-directory sizes (see APPNOTE.TXT) are trusted over the local file
 * header's own size fields: entries written with a streaming data
 * descriptor (general purpose flag bit 3) leave the local header's sizes at
 * zero, but the central directory's are always accurate.
 *
 * Hardening against attacker-controlled bytes:
 *  - central directory capped at MAX_CENTRAL_DIRECTORY_ENTRIES;
 *  - each entry's inflate output capped at MAX_ENTRY_INFLATED_BYTES, aborting
 *    the decompression stream once exceeded — the entry's claimed
 *    uncompressed size is never trusted for allocation, only actual bytes
 *    produced count (this is what stops a zip bomb);
 *  - running total of extracted text across all parts capped at
 *    MAX_TOTAL_EXTRACTED_BYTES, mirroring file-scan.ts's MAX_TEXT_FILE_BYTES;
 *  - encrypted entries (general purpose flag bit 0) are skipped silently;
 *  - malformed input (truncated file, bad signature, out-of-range offsets,
 *    unsupported compression method) returns null instead of throwing.
 */

/* -------------------------------- limits --------------------------------- */

const MAX_CENTRAL_DIRECTORY_ENTRIES = 10_000;

/**
 * Mirrors apps/extension/src/file-scan.ts's MAX_TEXT_FILE_BYTES: the hard
 * ceiling on how much text this module will ever return, no matter how many
 * XML parts a document contains.
 */
const MAX_TOTAL_EXTRACTED_BYTES = 1024 * 1024; // 1 MB

/**
 * Per-entry inflate ceiling. A small deflate stream can expand enormously
 * (a "zip bomb"); this stops any single entry's decompression well before
 * the total-text cap above would even get a chance to apply.
 */
const MAX_ENTRY_INFLATED_BYTES = 20 * 1024 * 1024; // 20 MB

/* ------------------------------ zip reading ------------------------------ */

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_DIR_SIGNATURE = 0x02014b50;
const LOCAL_FILE_SIGNATURE = 0x04034b50;
const EOCD_SIZE = 22; // fixed portion, before the variable-length comment
const MAX_EOCD_COMMENT = 65_535; // comment length field is 16 bits
const ENCRYPTED_FLAG = 0x0001;

interface ZipEntry {
  name: string;
  method: number; // 0 = stored, 8 = deflate
  compressedSize: number;
  localHeaderOffset: number;
  encrypted: boolean;
}

const utf8Decoder = new TextDecoder("utf-8", { fatal: false });

function decodeUtf8(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

/** Find the EOCD record by scanning backward for its signature. */
function findEndOfCentralDirectory(bytes: Uint8Array): DataView | null {
  if (bytes.length < EOCD_SIZE) return null;
  const scanFloor = Math.max(0, bytes.length - EOCD_SIZE - MAX_EOCD_COMMENT);
  for (let i = bytes.length - EOCD_SIZE; i >= scanFloor; i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) {
      return new DataView(bytes.buffer, bytes.byteOffset + i, EOCD_SIZE);
    }
  }
  return null;
}

/** Parse the central directory into entries. Never throws. */
function parseCentralDirectory(bytes: Uint8Array): ZipEntry[] | null {
  try {
    const eocd = findEndOfCentralDirectory(bytes);
    if (!eocd || eocd.getUint32(0, true) !== EOCD_SIGNATURE) return null;

    const totalEntries = eocd.getUint16(10, true);
    const centralDirSize = eocd.getUint32(12, true);
    const centralDirOffset = eocd.getUint32(16, true);
    if (totalEntries > MAX_CENTRAL_DIRECTORY_ENTRIES) return null;
    if (centralDirOffset > bytes.length || centralDirOffset + centralDirSize > bytes.length) return null;

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const entries: ZipEntry[] = [];
    let offset = centralDirOffset;

    for (let i = 0; i < totalEntries; i++) {
      if (offset + 46 > bytes.length) return null;
      if (view.getUint32(offset, true) !== CENTRAL_DIR_SIGNATURE) return null;

      const flag = view.getUint16(offset + 8, true);
      const method = view.getUint16(offset + 10, true);
      const compressedSize = view.getUint32(offset + 20, true);
      const nameLen = view.getUint16(offset + 28, true);
      const extraLen = view.getUint16(offset + 30, true);
      const commentLen = view.getUint16(offset + 32, true);
      const localHeaderOffset = view.getUint32(offset + 42, true);

      const nameStart = offset + 46;
      if (nameStart + nameLen > bytes.length) return null;
      const name = decodeUtf8(bytes.subarray(nameStart, nameStart + nameLen));

      entries.push({
        name,
        method,
        compressedSize,
        localHeaderOffset,
        encrypted: (flag & ENCRYPTED_FLAG) !== 0,
      });

      offset = nameStart + nameLen + extraLen + commentLen;
    }

    return entries;
  } catch {
    return null; // malformed input must never throw
  }
}

/** Concatenate chunks produced while streaming an inflate. */
function concatChunks(chunks: Uint8Array[], totalLength: number): Uint8Array {
  const out = new Uint8Array(totalLength);
  let pos = 0;
  for (const chunk of chunks) {
    out.set(chunk, pos);
    pos += chunk.length;
  }
  return out;
}

/**
 * Inflate `compressed` with the native DecompressionStream, streaming so
 * output can be aborted the moment it exceeds MAX_ENTRY_INFLATED_BYTES —
 * this is what makes the cap effective against a small-input/huge-output zip
 * bomb: allocation is never based on the declared uncompressed size.
 */
async function inflateCapped(compressed: Uint8Array): Promise<Uint8Array | null> {
  try {
    // Write + read the two sides of the transform directly instead of
    // `pipeThrough`: DOM lib types DecompressionStream's writable side as
    // WritableStream<BufferSource>, which pipeThrough's ReadableWritablePair
    // rejects as a type mismatch against ReadableStream<Uint8Array> even
    // though it's valid at runtime.
    const ds = new DecompressionStream("deflate-raw");
    const writer = ds.writable.getWriter();
    // Cast: WritableStream<BufferSource>.write() wants a view over a
    // non-shared ArrayBuffer specifically; `compressed`'s Uint8Array is
    // never actually SharedArrayBuffer-backed, only typed generically as
    // ArrayBufferLike because it comes from `Uint8Array.subarray()`.
    const writeDone = writer.write(compressed as BufferSource).then(() => writer.close());
    const reader = ds.readable.getReader();

    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.length === 0) continue;
      const remaining = MAX_ENTRY_INFLATED_BYTES - total;
      if (remaining <= 0) {
        await reader.cancel().catch(() => {});
        break;
      }
      const chunk = value.length > remaining ? value.subarray(0, remaining) : value;
      chunks.push(chunk);
      total += chunk.length;
      if (chunk.length < value.length) {
        await reader.cancel().catch(() => {});
        break;
      }
    }
    // Never let a write-side failure (e.g. the cancel() above) surface as an
    // unhandled rejection; a decode failure there doesn't change what we
    // already read from the readable side.
    await writeDone.catch(() => {});
    return concatChunks(chunks, total);
  } catch {
    return null; // e.g. corrupt deflate stream
  }
}

/**
 * Read and (if needed) inflate one entry's data. Encrypted entries and
 * entries with an unsupported compression method are skipped (return null)
 * rather than treated as errors — a partially-scannable archive is still
 * worth scanning.
 */
async function readEntryData(bytes: Uint8Array, entry: ZipEntry): Promise<Uint8Array | null> {
  if (entry.encrypted) return null;
  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const lh = entry.localHeaderOffset;
    if (lh < 0 || lh + 30 > bytes.length) return null;
    if (view.getUint32(lh, true) !== LOCAL_FILE_SIGNATURE) return null;

    const nameLen = view.getUint16(lh + 26, true);
    const extraLen = view.getUint16(lh + 28, true);
    const dataStart = lh + 30 + nameLen + extraLen;
    const dataEnd = dataStart + entry.compressedSize;
    if (dataStart > bytes.length || dataEnd > bytes.length || dataEnd < dataStart) return null;

    const compressed = bytes.subarray(dataStart, dataEnd);

    if (entry.method === 0) {
      // Stored: cap directly, no decompression amplification is possible.
      return compressed.length > MAX_ENTRY_INFLATED_BYTES
        ? compressed.subarray(0, MAX_ENTRY_INFLATED_BYTES)
        : compressed;
    }
    if (entry.method === 8) {
      return await inflateCapped(compressed);
    }
    return null; // unsupported method (e.g. legacy shrink/implode)
  } catch {
    return null;
  }
}

/* --------------------------- XML -> plain text ---------------------------- */

const XML_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  apos: "'",
  quot: '"',
};

/** Decode the five basic XML entities plus decimal numeric refs (&#NNN;). */
function decodeXmlEntities(text: string): string {
  return text.replace(/&(#\d+|[a-zA-Z]+);/g, (whole, body: string) => {
    if (body.charCodeAt(0) === 35 /* '#' */) {
      const code = Number(body.slice(1));
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole;
      try {
        return String.fromCodePoint(code);
      } catch {
        return whole;
      }
    }
    return XML_ENTITIES[body] ?? whole;
  });
}

// Closing tags that end a paragraph/row-level block become a newline;
// covers both docx (w:p, w:tr) and xlsx (row) shapes.
const NEWLINE_BOUNDARY = /<\/(?:w:p|p|w:tr|tr|row)>/gi;
// Closing tags that end a cell/run-level fragment become a space; w:tab and
// w:br are self-closing inline breaks that would otherwise glue two runs
// of text together with no separator at all.
const SPACE_BOUNDARY = /<\/(?:w:tc|tc|c)>|<w:tab\s*\/>|<w:br\s*\/>/gi;

/**
 * Strip XML markup down to plain text: paragraph/row boundaries become
 * "\n", cell/run boundaries become " ", every other tag is simply removed,
 * and the five basic entities plus decimal numeric refs are decoded.
 */
function stripXmlToText(xml: string): string {
  let out = xml.replace(NEWLINE_BOUNDARY, "\n");
  out = out.replace(SPACE_BOUNDARY, " ");
  out = out.replace(/<[^>]*>/g, "");
  return decodeXmlEntities(out);
}

/* --------------------------------- docx ----------------------------------- */

const DOCX_PART_NAMES = /^word\/(document\.xml|header\d*\.xml|footer\d*\.xml)$/i;

export async function extractDocxText(bytes: Uint8Array): Promise<string | null> {
  try {
    const entries = parseCentralDirectory(bytes);
    if (!entries) return null;

    const isDocument = (name: string) => /^word\/document\.xml$/i.test(name);
    const parts = entries.filter((e) => DOCX_PART_NAMES.test(e.name));
    if (!parts.some((e) => isDocument(e.name))) return null;
    // document.xml first, then headers/footers — order doesn't affect
    // detection, just makes the joined text read in a sane order.
    parts.sort((a, b) => Number(isDocument(b.name)) - Number(isDocument(a.name)));

    const texts: string[] = [];
    let budget = MAX_TOTAL_EXTRACTED_BYTES;
    for (const entry of parts) {
      if (budget <= 0) break;
      const data = await readEntryData(bytes, entry);
      if (!data) continue;
      const text = stripXmlToText(decodeUtf8(data)).slice(0, budget);
      if (text.length === 0) continue;
      texts.push(text);
      budget -= text.length;
    }

    return texts.length > 0 ? texts.join("\n") : null;
  } catch {
    return null;
  }
}

/* --------------------------------- xlsx ------------------------------------ */

const XLSX_SHEET_NAME = /^xl\/worksheets\/sheet\d+\.xml$/i;
const XLSX_SHARED_STRINGS_NAME = /^xl\/sharedStrings\.xml$/i;

export async function extractXlsxText(bytes: Uint8Array): Promise<string | null> {
  try {
    const entries = parseCentralDirectory(bytes);
    if (!entries) return null;

    const sheets = entries.filter((e) => XLSX_SHEET_NAME.test(e.name));
    if (sheets.length === 0) return null; // not a real workbook

    const sharedStrings = entries.find((e) => XLSX_SHARED_STRINGS_NAME.test(e.name));
    const ordered = sharedStrings ? [sharedStrings, ...sheets] : sheets;

    const texts: string[] = [];
    let budget = MAX_TOTAL_EXTRACTED_BYTES;
    for (const entry of ordered) {
      if (budget <= 0) break;
      const data = await readEntryData(bytes, entry);
      if (!data) continue;
      // Shared strings hold <t> text; sheets hold both inline <is><t> text
      // and raw <v> cell values. A plain tag-strip captures all of them
      // uniformly: every text node is kept and only tags are removed.
      const text = stripXmlToText(decodeUtf8(data)).slice(0, budget);
      if (text.length === 0) continue;
      texts.push(text);
      budget -= text.length;
    }

    return texts.length > 0 ? texts.join("\n") : null;
  } catch {
    return null;
  }
}

/* ---------------------------------- entry ---------------------------------- */

/**
 * Extract plain text from an .xlsx or .docx file's bytes for evaluation by
 * `evaluate()`. Returns null when the file isn't a valid/extractable archive
 * of the given kind — never throws, regardless of how malformed `bytes` is.
 */
export async function extractOfficeText(bytes: Uint8Array, kind: "xlsx" | "docx"): Promise<string | null> {
  try {
    return kind === "docx" ? await extractDocxText(bytes) : await extractXlsxText(bytes);
  } catch {
    return null;
  }
}
