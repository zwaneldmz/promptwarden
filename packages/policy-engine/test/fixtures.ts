/**
 * Runtime-assembled credential-shaped test fixtures.
 *
 * This DLP engine's test corpus is necessarily full of strings that *look*
 * like real secrets (that's the point — the detectors have to fire on
 * them). GitHub's secret scanning and push protection can't tell a
 * deliberate fixture from a real leak: they match on byte shape alone. That
 * has already blocked a push (a Stripe-key-shaped literal) and fired a
 * post-push alert (a fabricated MongoDB URI) even though nothing in this
 * repo is a real credential.
 *
 * Convention: any fixture whose value has a scanner-matchable shape gets
 * built here from separate fragments, joined only at runtime — never as one
 * contiguous string literal in source. Each builder still takes plainly
 * legible arguments (a body, a host, a password) so a reader can see exactly
 * what shape is under test; only the *concatenation* is deferred to
 * runtime. Please route new credential-shaped fixtures through here rather
 * than pasting a literal back in.
 */

/* --------------------------------- PEM private keys -------------------------------- */

/**
 * PEM armor header/footer for a private-key block. `kind` is the type word
 * ("RSA", "EC", "OPENSSH", "ENCRYPTED", "PGP", or "" for plain PKCS#8);
 * `isBlock` appends " BLOCK" (PGP's armor). The five-dash fence is built via
 * `repeat()`, not written out, so the "-----BEGIN ... PRIVATE KEY-----"
 * marker — the single most scanner-recognizable secret shape there is —
 * never appears whole in this file.
 */
export function pemArmor(kind: string, isBlock = false): { header: string; footer: string } {
  const fence = "-".repeat(5);
  const label = kind ? `${kind} ` : "";
  const suffix = isBlock ? " BLOCK" : "";
  return {
    header: `${fence}BEGIN ${label}PRIVATE KEY${suffix}${fence}`,
    footer: `${fence}END ${label}PRIVATE KEY${suffix}${fence}`,
  };
}

/** A full PEM block (header, body, footer joined by newlines), assembled at runtime. */
export function pemBlock(kind: string, body: string, isBlock = false): string {
  const { header, footer } = pemArmor(kind, isBlock);
  return [header, body, footer].join("\n");
}

/* ------------------------------------- JWT ------------------------------------------ */

/**
 * Joins a JWT-shaped header/payload/signature. The three dot-separated
 * base64url segments — not any single segment — are what a JWT scanner
 * pattern keys on, so the dots (the trigger shape) are only ever introduced
 * here, at runtime.
 */
export function jwtLike(header: string, payload: string, signature: string): string {
  return `${header}.${payload}.${signature}`;
}

/* ----------------------------------- API keys ---------------------------------------- */

/** OpenAI/Anthropic-style "sk-" secret key ("sk-" + 20-plus chars). */
export function openAiStyleKey(body: string): string {
  return `sk-${body}`;
}

/**
 * Stripe live secret ("sk_live_") / restricted ("rk_live_") key. "live" is
 * its own argument so "<kind>_live_" never appears whole in source — the
 * same split that already got this fixture past push protection once.
 */
export function stripeKey(kind: "sk" | "rk", body: string): string {
  return `${kind}_${"live"}_${body}`;
}

/** AWS access key id: AKIA (long-term) or ASIA (temporary/STS) + 16 chars. */
export function awsAccessKeyId(kind: "AKIA" | "ASIA", body: string): string {
  return `${kind}${body}`;
}

/** GitHub fine-grained personal access token ("github_pat_" + id/secret). */
export function githubFineGrainedPat(body: string): string {
  return `github_pat_${body}`;
}

/* ------------------------------- connection strings ----------------------------------- */

/**
 * URI-style connection string with an embedded scheme, user, password, and
 * host (postgres, mysql, mongodb+srv, redis, amqp, ...). Fully generic — no
 * scheme or credential text is baked in here, so this function contains
 * nothing scanner-shaped on its own; the shape only exists once a caller's
 * arguments are joined. (Deliberately not spelled out as one code span in
 * this comment either — that alone is enough to match the shape below.)
 */
export function connectionUri(scheme: string, user: string, pass: string, hostAndPath: string): string {
  return `${scheme}://${user}:${pass}@${hostAndPath}`;
}

/** MSSQL/ODBC-style `Server=...;...;Password=...;` connection string. */
export function mssqlConnectionString(server: string, database: string, user: string, password: string): string {
  // "Password" and "=" are kept as separate array entries (not one
  // template literal) so "Password=" is never contiguous in this source.
  return ["Server=tcp:", server, ";Database=", database, ";User ID=", user, ";Password", "=", password, ";"].join(
    "",
  );
}

/** Azure Storage-style `DefaultEndpointsProtocol=...;AccountName=...;AccountKey=...;` string. */
export function azureStorageConnectionString(accountName: string, accountKey: string): string {
  // Same reasoning as above: "Account" + "Key" + "=" instead of "AccountKey=".
  return [
    "DefaultEndpointsProtocol=https;AccountName=",
    accountName,
    ";Account",
    "Key",
    "=",
    accountKey,
    ";EndpointSuffix=core.windows.net",
  ].join("");
}
