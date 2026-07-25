/**
 * Built-in detectors. Each returns candidate spans; candidates are validated
 * (checksums where the format has them) to keep false positives low, because
 * the guardrail UX dies the day it cries wolf on an order number.
 *
 * All detectors are pure, synchronous, and dependency-free — the inline path
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

const CARD_CANDIDATE = /\b(?:\d[ -]?){13,19}\b/g;

const creditCard: DetectorFn = (text) => {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(CARD_CANDIDATE)) {
    const raw = m[0];
    const digits = raw.replace(/[ -]/g, "");
    if (digits.length < 13 || digits.length > 19) continue;
    if (!luhnValid(digits)) continue;
    // Common false positive: long numeric IDs that accidentally pass Luhn but
    // don't start with a known major industry identifier (3–6).
    if (!/^[3-6]/.test(digits)) continue;
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

const IBAN_CANDIDATE = /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b/g;

const iban: DetectorFn = (text) => {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(IBAN_CANDIDATE)) {
    if (!ibanValid(m[0])) continue;
    out.push({ detector: "iban", start: m.index!, end: m.index! + m[0].length, match: m[0] });
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

// International or common European formats with at least 9 digits.
const PHONE = /(?:\+|00)[1-9]\d{0,2}[ \-/]?(?:\(?\d{1,4}\)?[ \-/]?)?\d(?:[ \-/]?\d){6,10}\b/g;

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
// (opt-in) audit tier, not here.
const API_KEY_PATTERNS: RegExp[] = [
  /\bsk-[A-Za-z0-9_-]{20,}\b/g, // OpenAI / Anthropic-style secret keys
  /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key id
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, // GitHub tokens
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
  /\bAIza[0-9A-Za-z_-]{35}\b/g, // Google API key
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

export const BUILTIN_DETECTORS: Record<string, DetectorFn> = {
  credit_card: creditCard,
  iban,
  email,
  phone,
  api_key: apiKey,
  at_svnr: atSvnr,
};

export const DEFAULT_LABELS: Record<string, string> = {
  credit_card: "[REDACTED:CARD]",
  iban: "[REDACTED:IBAN]",
  email: "[REDACTED:EMAIL]",
  phone: "[REDACTED:PHONE]",
  api_key: "[REDACTED:API_KEY]",
  at_svnr: "[REDACTED:SVNR]",
};
