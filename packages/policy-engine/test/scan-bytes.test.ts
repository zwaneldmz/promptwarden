import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePolicy, Policy } from "../src/policy.js";
import {
  classifyFile,
  scanBytes,
  MAX_TEXT_FILE_BYTES,
  MAX_OFFICE_FILE_BYTES,
} from "../src/scan-bytes.js";

/**
 * Minimal STORED-entry (method 0, uncompressed) ZIP builder — enough to
 * exercise scanBytes's office path without a compression library. Mirrors
 * the fixture-building approach in test/extract-office.test.ts (not
 * exported from there, so rebuilt here in trimmed form).
 */
interface ZipInputEntry {
  name: string;
  data: Uint8Array;
}

function concatAll(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

function le16(view: DataView, offset: number, value: number) {
  view.setUint16(offset, value, true);
}
function le32(view: DataView, offset: number, value: number) {
  view.setUint32(offset, value, true);
}

function buildStoredZip(entries: ZipInputEntry[]): Uint8Array {
  const encoder = new TextEncoder();
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let runningOffset = 0;

  for (const entry of entries) {
    const nameBytes = encoder.encode(entry.name);
    const size = entry.data.length;

    const localHeader = new Uint8Array(30);
    const lv = new DataView(localHeader.buffer);
    le32(lv, 0, 0x04034b50);
    le16(lv, 4, 20); // version needed
    le16(lv, 6, 0); // flag
    le16(lv, 8, 0); // method: stored
    le16(lv, 10, 0); // mod time
    le16(lv, 12, 0); // mod date
    le32(lv, 14, 0); // crc32 (unchecked by the reader)
    le32(lv, 18, size); // compressed size
    le32(lv, 22, size); // uncompressed size
    le16(lv, 26, nameBytes.length);
    le16(lv, 28, 0); // extra length

    const localHeaderOffset = runningOffset;
    localParts.push(concatAll([localHeader, nameBytes, entry.data]));
    runningOffset += localHeader.length + nameBytes.length + entry.data.length;

    const centralHeader = new Uint8Array(46);
    const cv = new DataView(centralHeader.buffer);
    le32(cv, 0, 0x02014b50);
    le16(cv, 4, 20); // version made by
    le16(cv, 6, 20); // version needed
    le16(cv, 8, 0); // flag
    le16(cv, 10, 0); // method
    le16(cv, 12, 0);
    le16(cv, 14, 0);
    le32(cv, 16, 0); // crc32
    le32(cv, 20, size); // compressed size
    le32(cv, 24, size); // uncompressed size
    le16(cv, 28, nameBytes.length);
    le16(cv, 30, 0); // extra length
    le16(cv, 32, 0); // comment length
    le16(cv, 34, 0); // disk number start
    le16(cv, 36, 0); // internal attrs
    le32(cv, 38, 0); // external attrs
    le32(cv, 42, localHeaderOffset);

    centralParts.push(concatAll([centralHeader, nameBytes]));
  }

  const localSection = concatAll(localParts);
  const centralSection = concatAll(centralParts);

  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  le32(ev, 0, 0x06054b50);
  le16(ev, 4, 0);
  le16(ev, 6, 0);
  le16(ev, 8, entries.length);
  le16(ev, 10, entries.length);
  le32(ev, 12, centralSection.length);
  le32(ev, 16, localSection.length);
  le16(ev, 20, 0); // comment length

  return concatAll([localSection, centralSection, eocd]);
}

const strict: Policy = parsePolicy({
  version: 1,
  name: "test-scan-bytes",
  hosts: ["chatgpt.com"],
  defaultAction: "warn",
  logging: "event",
  rules: [
    { detector: "credit_card", action: "block" },
    { detector: "iban", action: "redact" },
  ],
});

const IBAN = "AT61 1904 3002 3457 3201";

/* ------------------------------ classifyFile ------------------------------ */

test("classifyFile: text extensions and MIME types classify as text", () => {
  assert.equal(classifyFile("notes.txt"), "text");
  assert.equal(classifyFile("data.CSV"), "text"); // case-insensitive
  assert.equal(classifyFile("weird-name", "text/plain"), "text");
  assert.equal(classifyFile("data.json", "application/json"), "text");
});

test("classifyFile: office extensions and OOXML MIME types classify as office", () => {
  assert.equal(classifyFile("report.docx"), "office");
  assert.equal(classifyFile("sheet.XLSX"), "office"); // case-insensitive
  assert.equal(
    classifyFile("weird-name", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "office",
  );
  assert.equal(
    classifyFile("weird-name", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "office",
  );
});

test("classifyFile: unknown extension/binary MIME classifies as skip", () => {
  assert.equal(classifyFile("photo.jpg", "image/jpeg"), "skip");
  assert.equal(classifyFile("archive.zip"), "skip");
  assert.equal(classifyFile("no-extension"), "skip");
});

/* -------------------------------- scanBytes -------------------------------- */

test("scanBytes: a text file with an IBAN is found", async () => {
  const bytes = new TextEncoder().encode(`Please wire to ${IBAN} today`);
  const { findings, unreadable } = await scanBytes("wire.txt", bytes, strict);
  assert.equal(unreadable, false);
  assert.ok(findings.some((f) => f.detector === "iban"));
});

test("scanBytes: an oversized text file is head-scanned", async () => {
  // IBAN sits well past MAX_TEXT_FILE_BYTES; padding before it is plain
  // filler so only the head-scan cap determines what's visible.
  const padding = "x".repeat(MAX_TEXT_FILE_BYTES + 1000);
  const beyondCap = new TextEncoder().encode(padding + ` ${IBAN}`);
  const beyond = await scanBytes("big.txt", beyondCap, strict);
  assert.equal(beyond.unreadable, false);
  assert.equal(
    beyond.findings.some((f) => f.detector === "iban"),
    false,
    "IBAN placed past the head-scan cap must not be found",
  );

  // Same IBAN placed inside the first MAX_TEXT_FILE_BYTES must still be
  // found, proving the head IS scanned (not skipped outright).
  const withinCapPadding = "x".repeat(MAX_TEXT_FILE_BYTES - 200);
  const withinCap = new TextEncoder().encode(`${IBAN} ` + withinCapPadding);
  const within = await scanBytes("big2.txt", withinCap, strict);
  assert.equal(within.unreadable, false);
  assert.ok(within.findings.some((f) => f.detector === "iban"));
});

test("scanBytes: a minimal .docx fixture is extracted and evaluated", async () => {
  const documentXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    `<w:document><w:body><w:p><w:r><w:t>Please pay to ${IBAN}</w:t></w:r></w:p></w:body></w:document>`;
  const zip = buildStoredZip([
    { name: "word/document.xml", data: new TextEncoder().encode(documentXml) },
  ]);

  const { findings, unreadable } = await scanBytes("contract.docx", zip, strict);
  assert.equal(unreadable, false);
  assert.ok(findings.some((f) => f.detector === "iban"));
});

test("scanBytes: a minimal .xlsx fixture is extracted and evaluated", async () => {
  const sheetXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
    `<sheetData><row r="1"><c r="A1" t="str"><v>4532 0151 1283 0366</v></c></row></sheetData>` +
    "</worksheet>";
  const zip = buildStoredZip([
    { name: "xl/worksheets/sheet1.xml", data: new TextEncoder().encode(sheetXml) },
  ]);

  const { findings, unreadable } = await scanBytes("book.xlsx", zip, strict);
  assert.equal(unreadable, false);
  assert.ok(findings.some((f) => f.detector === "credit_card"));
});

test("scanBytes: an oversized office file is reported unreadable, never extracted", async () => {
  const oversized = new Uint8Array(MAX_OFFICE_FILE_BYTES + 1);
  const { findings, unreadable } = await scanBytes("huge.xlsx", oversized, strict);
  assert.equal(unreadable, true);
  assert.deepEqual(findings, []);
});

test("scanBytes: a binary/unknown-extension file classifies as skip and is never scanned", async () => {
  const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0, 1, 2, 3]); // PNG-ish magic bytes
  const { findings, unreadable } = await scanBytes("photo.png", bytes, strict, "image/png");
  assert.deepEqual(findings, []);
  assert.equal(unreadable, false, "a skipped file is not the same as an unreadable one");
});

test("scanBytes: a malformed office file returns unreadable without throwing", async () => {
  const garbage = new TextEncoder().encode("not a zip file at all, just some bytes");
  await assert.doesNotReject(async () => {
    const { findings, unreadable } = await scanBytes("broken.docx", garbage, strict);
    assert.equal(unreadable, true);
    assert.deepEqual(findings, []);
  });

  const empty = new Uint8Array(0);
  await assert.doesNotReject(async () => {
    const { unreadable } = await scanBytes("empty.xlsx", empty, strict);
    assert.equal(unreadable, true);
  });
});

test("scanBytes: an empty/whitespace-only text file yields no findings and is not unreadable", async () => {
  const bytes = new TextEncoder().encode("   \n\t  ");
  const { findings, unreadable } = await scanBytes("blank.txt", bytes, strict);
  assert.deepEqual(findings, []);
  assert.equal(unreadable, false);
});
