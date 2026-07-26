/**
 * Built-in detectors. Each returns candidate spans; candidates are validated
 * (checksums where the format has them) so an order number or tracking id
 * doesn't get misread as a card or IBAN.
 *
 * All detectors are pure, synchronous, and dependency-free: the inline path
 * must run in single-digit milliseconds on commodity hardware.
 */

export interface RawMatch {
  detector: string;
  start: number;
  end: number;
  match: string;
}

type DetectorFn = (text: string) => RawMatch[];

/* ------------------------------ credit card ------------------------------ */

function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

// Anchored to start and end on a digit: `(?:\d[ -]?){13,19}` would let the
// final repetition consume a trailing space or hyphen, so the match span —
// and therefore the text a `redact` action replaces — swallowed the
// separator after the card ("[REDACTED:CARD]on file"). Written as one digit
// followed by 12–18 more, each optionally separator-prefixed, the span can
// only ever end on a digit while still accepting 13–19 digit cards.
const CARD_CANDIDATE = /\b\d(?:[ -]?\d){12,18}\b/g;

// Issuer/BIN prefix gating: a long numeric string that passes Luhn (order
// numbers, tracking numbers, EAN-13 barcodes all can) is only treated as a
// card if its leading digits also match a real issuer range: Visa (4),
// Mastercard (51-55, and the newer 2221-2720 range approximated here as
// 22-27), Amex (34, 37), Discover (6011). Luhn alone isn't enough to avoid
// flagging ordinary numbers as cards.
const ISSUER_PREFIX = /^(?:4|5[1-5]|2[2-7]|3[47]|6011)/;

const creditCard: DetectorFn = (text) => {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(CARD_CANDIDATE)) {
    const raw = m[0];
    const digits = raw.replace(/[ -]/g, "");
    if (digits.length < 13 || digits.length > 19) continue;
    if (!luhnValid(digits)) continue;
    if (!ISSUER_PREFIX.test(digits)) continue;
    out.push({ detector: "credit_card", start: m.index!, end: m.index! + raw.length, match: raw });
  }
  return out;
};

/* ---------------------------------- IBAN --------------------------------- */

/** mod-97 on an arbitrarily long numeric string without BigInt. */
function mod97(numeric: string): number {
  let rem = 0;
  for (let i = 0; i < numeric.length; i++) {
    rem = (rem * 10 + (numeric.charCodeAt(i) - 48)) % 97;
  }
  return rem;
}

function ibanValid(candidate: string): boolean {
  const iban = candidate.replace(/\s/g, "").toUpperCase();
  if (iban.length < 15 || iban.length > 34) return false;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(iban)) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let numeric = "";
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    numeric += code >= 65 ? String(code - 55) : ch; // A=10 … Z=35
  }
  return mod97(numeric) === 1;
}

// Official IBAN length per ISO 13616 / SWIFT IBAN Registry, keyed by the
// 2-letter country code (full SEPA set plus the common non-EU IBAN
// countries). This is what makes candidate validation a *single* mod-97
// trial: an unknown country code gets zero trials rather than the previous
// right-trim loop's ~20 independent 1-in-97 chances against random text.
const IBAN_LENGTHS: Record<string, number> = {
  // SEPA / EU
  AD: 24, AT: 20, BE: 16, BG: 22, CH: 21, CY: 28, CZ: 24, DE: 22, DK: 18,
  EE: 20, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GI: 23, GL: 18, GR: 27,
  HR: 21, HU: 28, IE: 22, IS: 26, IT: 27, LI: 21, LT: 20, LU: 20, LV: 21,
  MC: 27, MT: 31, NL: 18, NO: 15, PL: 28, PT: 25, RO: 24, SE: 24, SI: 19,
  SK: 24, SM: 27, VA: 22, XK: 20,
  // Other IBAN-registry / commonly seen non-EU
  AE: 23, AL: 28, AZ: 28, BA: 20, BH: 22, BI: 27, BR: 29, BY: 28, CR: 22,
  DJ: 27, DO: 28, EG: 29, GE: 22, GT: 28, IL: 23, IQ: 23, JO: 30, KW: 30,
  KZ: 20, LB: 28, LC: 32, LY: 25, MD: 24, ME: 22, MK: 19, MR: 27, MU: 30,
  OM: 23, PK: 24, PS: 29, QA: 29, RS: 22, RU: 33, SA: 24, SC: 31, SD: 18,
  SO: 23, ST: 25, SV: 28, TL: 23, TN: 24, TR: 26, UA: 29, VG: 24,
};

// Case-insensitive, generous upper bound: we only need enough characters
// captured to reach the longest registered length (RU, 33) plus a little
// slack so the "not embedded in a longer run" check below has a character to
// look at. The exact candidate length is decided per-country below, not by
// this regex — there is no retry loop.
const IBAN_CANDIDATE = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){9,34}\b/gi;

const iban: DetectorFn = (text) => {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(IBAN_CANDIDATE)) {
    const raw = m[0];
    const countryCode = raw.slice(0, 2).toUpperCase();
    const officialLength = IBAN_LENGTHS[countryCode];
    if (!officialLength) continue; // unrecognized country code: zero trials

    // Walk the raw match, dropping formatting spaces, until we've collected
    // exactly the country's official compact length — the single candidate
    // that is even eligible for a mod-97 trial.
    let compact = "";
    let rawEnd = -1;
    for (let i = 0; i < raw.length; i++) {
      const ch = raw[i];
      if (ch === " ") continue;
      compact += ch;
      if (compact.length === officialLength) {
        rawEnd = i + 1;
        break;
      }
    }
    if (compact.length !== officialLength) continue; // too short for this country

    const start = m.index!;
    const end = start + rawEnd;

    // Reject if the compact candidate is just a substring of a longer
    // alphanumeric run (e.g. an ops identifier that happens to start with a
    // real country code): the character immediately following the cut must
    // not itself be alphanumeric.
    const trailing = text[end];
    if (trailing && /[A-Za-z0-9]/.test(trailing)) continue;

    if (!ibanValid(compact)) continue;
    out.push({ detector: "iban", start, end, match: text.slice(start, end) });
  }
  return out;
};

/* ---------------------------------- email -------------------------------- */

const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

const email: DetectorFn = (text) => {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(EMAIL)) {
    out.push({ detector: "email", start: m.index!, end: m.index! + m[0].length, match: m[0] });
  }
  return out;
};

/* ---------------------------------- phone -------------------------------- */

// International or common European formats with at least 9 digits. The
// leading `(?<!\d)` guards against matching a "00" that merely occurs
// mid-run inside a longer, unrelated digit string (order numbers, tracking
// numbers): without it, "00" preceded by another digit is a false trigger
// for the international-dialing prefix even though nothing there was ever a
// phone number — found via the false-positive corpus in edge-cases.test.ts.
const PHONE = /(?<!\d)(?:\+|00)[1-9]\d{0,2}[ \-/]?(?:\(?\d{1,4}\)?[ \-/]?)?\d(?:[ \-/]?\d){6,10}\b/g;

const phone: DetectorFn = (text) => {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(PHONE)) {
    const digits = m[0].replace(/\D/g, "");
    if (digits.length < 9 || digits.length > 15) continue;
    out.push({ detector: "phone", start: m.index!, end: m.index! + m[0].length, match: m[0] });
  }
  return out;
};

/* --------------------------------- api key ------------------------------- */

// Structured, high-confidence secret formats only. Entropy heuristics create
// too many false positives for an inline guardrail; they belong in the
// (opt-in) audit tier, not here. Every pattern is gated on a vendor-specific
// literal prefix/format, never on randomness alone.
const API_KEY_PATTERNS: RegExp[] = [
  /\bsk-[A-Za-z0-9_-]{20,}\b/g, // OpenAI / Anthropic-style secret keys (incl. sk-ant-…)
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, // AWS access key id (ASIA = temporary/STS)
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, // GitHub tokens: ghp_/gho_/ghu_/ghs_/ghr_
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, // GitHub fine-grained PAT
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
  /\bAIza[0-9A-Za-z_-]{35}\b/g, // Google API key
  /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g, // Stripe secret / restricted live keys
];

const apiKey: DetectorFn = (text) => {
  const out: RawMatch[] = [];
  for (const re of API_KEY_PATTERNS) {
    for (const m of text.matchAll(re)) {
      out.push({ detector: "api_key", start: m.index!, end: m.index! + m[0].length, match: m[0] });
    }
  }
  return out;
};

/* ------------------------------ private key ------------------------------ */

// PEM-armored private key blocks: OpenSSL (RSA/EC/DSA), PKCS#8 (plain and
// encrypted, i.e. "PRIVATE KEY" / "ENCRYPTED PRIVATE KEY"), OpenSSH, and PGP.
// Zero plausible false positive: this literal marker only appears when real
// key material (or a deliberate placeholder standing in for it) is present.
// Matched greedily through to the matching END marker so the key body itself
// — not just the header line — is covered by the finding and gets redacted.
const PRIVATE_KEY_BLOCK =
  /-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----[\s\S]*?-----END \1-----/g;
// Fallback for a header pasted without its matching END marker (truncated
// paste, or someone just asking about the header) — still worth flagging.
const PRIVATE_KEY_HEADER_ONLY = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g;

const privateKey: DetectorFn = (text) => {
  const out: RawMatch[] = [];
  const covered: Array<[number, number]> = [];
  for (const m of text.matchAll(PRIVATE_KEY_BLOCK)) {
    const start = m.index!;
    const end = start + m[0].length;
    out.push({ detector: "private_key", start, end, match: m[0] });
    covered.push([start, end]);
  }
  for (const m of text.matchAll(PRIVATE_KEY_HEADER_ONLY)) {
    const start = m.index!;
    if (covered.some(([s, e]) => start >= s && start < e)) continue; // already part of a full block
    out.push({ detector: "private_key", start, end: start + m[0].length, match: m[0] });
  }
  return out;
};

/* ---------------------------------- jwt ----------------------------------- */

const BASE64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Decode a base64url segment to a (Latin-1) string; null if not valid base64url. */
function base64UrlDecode(segment: string): string | null {
  if (segment.length === 0 || !/^[A-Za-z0-9_-]+$/.test(segment)) return null;
  const std = segment.replace(/-/g, "+").replace(/_/g, "/");
  let bits = 0;
  let value = 0;
  let out = "";
  for (const ch of std) {
    const idx = BASE64URL_CHARS.indexOf(ch);
    if (idx === -1) return null;
    value = (value << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += String.fromCharCode((value >> bits) & 0xff);
    }
  }
  return out;
}

// Three dot-separated base64url segments — but that alone matches too much
// (version strings, hashes). The real gate is structural: the first segment
// must decode to JSON containing an "alg" field, exactly what every real JWT
// header carries and what an arbitrary base64 blob essentially never does by
// chance. This is a decode-and-check, not a pattern match.
const JWT_CANDIDATE = /\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

const jwt: DetectorFn = (text) => {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(JWT_CANDIDATE)) {
    const headerSegment = m[0].slice(0, m[0].indexOf("."));
    const decoded = base64UrlDecode(headerSegment);
    if (!decoded) continue;
    let header: unknown;
    try {
      header = JSON.parse(decoded);
    } catch {
      continue;
    }
    if (
      typeof header !== "object" ||
      header === null ||
      typeof (header as Record<string, unknown>).alg !== "string"
    ) {
      continue;
    }
    out.push({ detector: "jwt", start: m.index!, end: m.index! + m[0].length, match: m[0] });
  }
  return out;
};

/* ----------------------------- connection string --------------------------- */

// URI-form connection strings: scheme://user:pass@host — only flagged when
// credentials are actually embedded (a bare "postgres://localhost/db" is
// just a hostname, not a secret).
const CONN_STRING_URI =
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|jdbc:(?:postgresql|mysql|sqlserver|oracle)):\/\/[^\s:@/]+:[^\s@/]+@[^\s,;'"<>]+/gi;

// ODBC / ADO.NET / JDBC key=value connection strings (MSSQL "Server=…;
// Password=…", Azure Storage "AccountName=…;AccountKey=…"). Gated on both a
// recognizable connection-string key preceding it *and* a non-trivial
// credential value, so a bare "Password=" label or short placeholder doesn't
// fire.
const CONN_STRING_KV =
  /\b(?:Server|Data Source|Host|Uid|User Id|User ID|Initial Catalog|Database|AccountName|DefaultEndpointsProtocol)\s*=\s*[^;\n]+;[\s\S]{0,200}?\b(?:AccountKey|Password|Pwd)\s*=\s*\S{8,}/gi;

const connectionString: DetectorFn = (text) => {
  const out: RawMatch[] = [];
  for (const re of [CONN_STRING_URI, CONN_STRING_KV]) {
    for (const m of text.matchAll(re)) {
      out.push({ detector: "connection_string", start: m.index!, end: m.index! + m[0].length, match: m[0] });
    }
  }
  return out;
};

/* ----------------------- Austrian social insurance ----------------------- */

/**
 * Austrian SVNR: NNNC DDMMYY where C is a check digit.
 * Check: weights 3,7,9 on the serial and 5,8,4,2,1,6 on the birthdate,
 * sum mod 11 must equal the check digit (results of 10 are invalid numbers).
 */
function svnrValid(digits: string): boolean {
  if (!/^\d{10}$/.test(digits)) return false;
  const d = digits.split("").map(Number);
  const weights = [3, 7, 9, 0, 5, 8, 4, 2, 1, 6];
  let sum = 0;
  for (let i = 0; i < 10; i++) sum += d[i] * weights[i];
  const check = sum % 11;
  return check !== 10 && check === d[3];
}

const SVNR_CANDIDATE = /\b\d{4}[ ]?\d{6}\b/g;

const atSvnr: DetectorFn = (text) => {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(SVNR_CANDIDATE)) {
    if (!svnrValid(m[0].replace(/\s/g, ""))) continue;
    out.push({ detector: "at_svnr", start: m.index!, end: m.index! + m[0].length, match: m[0] });
  }
  return out;
};

/* -------------------------------- registry ------------------------------- */

// Note: "bulk_pii" is deliberately not registered here. It isn't a per-text
// pattern detector — it's a post-pass synthesized by evaluate() once the
// detectors above have run (see engine.ts), because it needs their combined
// findings ("N+ distinct PII strings in one payload") rather than a pattern
// match of its own. Its label still lives in DEFAULT_LABELS below so it gets
// the same rule/label-resolution treatment as any other detector id.
export const BUILTIN_DETECTORS: Record<string, DetectorFn> = {
  credit_card: creditCard,
  iban,
  email,
  phone,
  api_key: apiKey,
  at_svnr: atSvnr,
  private_key: privateKey,
  jwt,
  connection_string: connectionString,
};

export const DEFAULT_LABELS: Record<string, string> = {
  credit_card: "[REDACTED:CARD]",
  iban: "[REDACTED:IBAN]",
  email: "[REDACTED:EMAIL]",
  phone: "[REDACTED:PHONE]",
  api_key: "[REDACTED:API_KEY]",
  at_svnr: "[REDACTED:SVNR]",
  private_key: "[REDACTED:PRIVATE_KEY]",
  jwt: "[REDACTED:JWT]",
  connection_string: "[REDACTED:CONNECTION_STRING]",
  bulk_pii: "[REDACTED:BULK_PII]",
};
