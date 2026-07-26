import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../src/engine.js";
import { parsePolicy, Policy } from "../src/policy.js";
import { extractOfficeText } from "../src/extract-office.js";

/**
 * Hand-built ZIP fixtures. No compression library needed: the "stored"
 * method (0) just copies bytes in verbatim, which is enough to exercise the
 * whole reader except the inflate path — one fixture below round-trips a
 * real DEFLATE stream through CompressionStream to exercise that too.
 */

interface ZipInputEntry {
  name: string;
  data: Uint8Array;
  method: 0 | 8;
  encrypted?: boolean;
  /** Overrides the declared uncompressed-size header field, independent of
   * `data`'s real length — used to simulate a lying zip-bomb-style header. */
  declaredUncompressedSize?: number;
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

function buildZip(entries: ZipInputEntry[]): Uint8Array {
  const encoder = new TextEncoder();
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let runningOffset = 0;

  for (const entry of entries) {
    const nameBytes = encoder.encode(entry.name);
    const flag = entry.encrypted ? 0x0001 : 0x0000;
    const compressedSize = entry.data.length;
    const uncompressedSize = entry.declaredUncompressedSize ?? entry.data.length;

    const localHeader = new Uint8Array(30);
    const lv = new DataView(localHeader.buffer);
    le32(lv, 0, 0x04034b50);
    le16(lv, 4, 20); // version needed
    le16(lv, 6, flag);
    le16(lv, 8, entry.method);
    le16(lv, 10, 0); // mod time
    le16(lv, 12, 0); // mod date
    le32(lv, 14, 0); // crc32 (unchecked by the reader)
    le32(lv, 18, compressedSize);
    le32(lv, 22, uncompressedSize);
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
    le16(cv, 8, flag);
    le16(cv, 10, entry.method);
    le16(cv, 12, 0);
    le16(cv, 14, 0);
    le32(cv, 16, 0); // crc32
    le32(cv, 20, compressedSize);
    le32(cv, 24, uncompressedSize);
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

async function deflateRaw(bytes: Uint8Array): Promise<Uint8Array> {
  // Write + read the transform's two sides directly rather than
  // pipeThrough — see the matching comment in src/extract-office.ts.
  const cs = new CompressionStream("deflate-raw");
  const writer = cs.writable.getWriter();
  const writeDone = writer.write(bytes as BufferSource).then(() => writer.close());
  const reader = cs.readable.getReader();

  const chunks: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) chunks.push(value);
  }
  await writeDone;
  return concatAll(chunks);
}

const strict: Policy = parsePolicy({
  version: 1,
  name: "test-office",
  hosts: ["chatgpt.com"],
  defaultAction: "warn",
  logging: "event",
  rules: [
    { detector: "credit_card", action: "block" },
    { detector: "iban", action: "redact" },
  ],
});

/* ------------------------------ happy paths ------------------------------- */

test("extractOfficeText(docx) decodes entities and evaluate() finds the IBAN", async () => {
  const documentXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    "<w:document><w:body>" +
    "<w:p><w:r><w:t>Please pay to AT61 1904 3002 3457 3201 &amp; confirm</w:t></w:r></w:p>" +
    "<w:p><w:r><w:t>Second paragraph</w:t></w:r></w:p>" +
    "</w:body></w:document>";

  const zip = buildZip([
    { name: "word/document.xml", data: new TextEncoder().encode(documentXml), method: 0 },
  ]);

  const text = await extractOfficeText(zip, "docx");
  assert.ok(text, "expected extracted text");
  assert.ok(text!.includes(" & confirm"), "entity &amp; should decode to a literal &");
  assert.ok(!text!.includes("&amp;"), "raw entity must not survive extraction");
  // Paragraph boundary became a newline separator between the two <w:p>s.
  assert.ok(text!.includes("\n"), "paragraph boundary should become a newline");

  const result = evaluate(text!, strict);
  assert.ok(
    result.findings.some((f) => f.detector === "iban"),
    "evaluate() should find the IBAN in extracted docx text",
  );
});

test("extractOfficeText(xlsx) combines a DEFLATE sheet and a stored sharedStrings part, evaluate() finds both detectors", async () => {
  const sharedStringsXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
    "<si><t>Wire to AT61 1904 3002 3457 3201 &amp; done</t></si>" +
    "</sst>";

  const sheetXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
    '<sheetData><row r="1"><c r="A1" t="str"><v>4532 0151 1283 0366</v></c></row></sheetData>' +
    "</worksheet>";

  const sheetXmlBytes = new TextEncoder().encode(sheetXml);
  const sheetCompressed = await deflateRaw(sheetXmlBytes);

  const zip = buildZip([
    { name: "xl/sharedStrings.xml", data: new TextEncoder().encode(sharedStringsXml), method: 0 },
    { name: "xl/worksheets/sheet1.xml", data: sheetCompressed, method: 8 },
  ]);

  const text = await extractOfficeText(zip, "xlsx");
  assert.ok(text, "expected extracted text");
  assert.ok(!text!.includes("&amp;"), "raw entity must not survive extraction");

  const result = evaluate(text!, strict);
  const found = new Set(result.findings.map((f) => f.detector));
  assert.ok(found.has("iban"), "evaluate() should find the IBAN from sharedStrings.xml");
  assert.ok(found.has("credit_card"), "evaluate() should find the Luhn-valid card from the DEFLATE-compressed sheet");
});

/* ------------------------------- hardening -------------------------------- */

test("malformed zip bytes return null without throwing", async () => {
  const garbage = new TextEncoder().encode("this is not a zip file at all, just some bytes");
  await assert.doesNotReject(async () => {
    const text = await extractOfficeText(garbage, "docx");
    assert.equal(text, null);
  });

  const empty = new Uint8Array(0);
  await assert.doesNotReject(async () => {
    assert.equal(await extractOfficeText(empty, "xlsx"), null);
  });

  const tooShortForEocd = new Uint8Array(10);
  await assert.doesNotReject(async () => {
    assert.equal(await extractOfficeText(tooShortForEocd, "docx"), null);
  });
});

test("an entry claiming a huge uncompressed size is capped, not OOM'd", async () => {
  const documentXml = "<w:document><w:body><w:p><w:r><w:t>hello</w:t></w:r></w:p></w:body></w:document>";
  const data = new TextEncoder().encode(documentXml);

  const zip = buildZip([
    {
      name: "word/document.xml",
      data,
      method: 0,
      // Lies about how big the uncompressed content is (~4GB); the reader
      // never allocates based on this field, only on the actual bytes
      // present (bounded by compressedSize, which is honest here).
      declaredUncompressedSize: 0xfffffffe,
    },
  ]);

  const start = Date.now();
  const text = await extractOfficeText(zip, "docx");
  const elapsed = Date.now() - start;

  assert.ok(text?.includes("hello"));
  assert.ok(elapsed < 2000, `extraction should be near-instant, took ${elapsed}ms`);
});

test("an encrypted entry is skipped silently, not treated as an error", async () => {
  const documentXml = "<w:document><w:body><w:p><w:r><w:t>secret</w:t></w:r></w:p></w:body></w:document>";
  const zip = buildZip([
    {
      name: "word/document.xml",
      data: new TextEncoder().encode(documentXml),
      method: 0,
      encrypted: true,
    },
  ]);

  // The only part that could supply text is encrypted, so extraction yields
  // nothing — but it must not throw, and must not return the plaintext.
  await assert.doesNotReject(async () => {
    const text = await extractOfficeText(zip, "docx");
    assert.equal(text, null);
  });
});

test("an encrypted entry alongside a readable one still yields the readable part", async () => {
  const encryptedXml = "<w:document><w:body><w:p><w:r><w:t>should not appear</w:t></w:r></w:p></w:body></w:document>";
  const headerXml = "<w:hdr><w:p><w:r><w:t>AT61 1904 3002 3457 3201</w:t></w:r></w:p></w:hdr>";

  const zip = buildZip([
    { name: "word/document.xml", data: new TextEncoder().encode(encryptedXml), method: 0, encrypted: true },
    { name: "word/header1.xml", data: new TextEncoder().encode(headerXml), method: 0 },
  ]);

  const text = await extractOfficeText(zip, "docx");
  assert.ok(text, "the unencrypted header part should still be extracted");
  assert.ok(!text!.includes("should not appear"), "the encrypted document.xml must not leak its content");
  const result = evaluate(text!, strict);
  assert.ok(result.findings.some((f) => f.detector === "iban"));
});

test("a non-office zip (no word/ or xl/ parts) returns null", async () => {
  const zip = buildZip([
    { name: "readme.txt", data: new TextEncoder().encode("hello"), method: 0 },
  ]);
  assert.equal(await extractOfficeText(zip, "docx"), null);
  assert.equal(await extractOfficeText(zip, "xlsx"), null);
});
