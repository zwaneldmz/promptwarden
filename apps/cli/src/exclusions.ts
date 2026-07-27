/**
 * `wardkeep emit-exclusions` — renders vendor-specific, PATH-based
 * exclusion files (`.cursorignore`, a GitHub Copilot content-exclusion YAML
 * block, `.aiignore`) from the same policy document the rest of this CLI
 * scans against.
 *
 * WHAT THIS IS NOT, stated once here and repeated in every rendered file's
 * header because it is the single most important thing to get right: this
 * does not scan, intercept, or block anything. Per docs/ROADMAP.md §3, IDE
 * inline completions (Copilot, Cursor Tab, JetBrains AI) are architecturally
 * out of reach for a local OSS tool — the payload is assembled inside a
 * closed process and never crosses anything wardkeep can observe. The
 * only lever available for that surface is *path exclusion*: telling the
 * vendor's own tooling which files to leave out of its context, enforced
 * (or not) entirely by that vendor, outside this process. See docs/IDE.md.
 *
 * Content is driven by which detectors the resolved policy actually enables
 * (any action other than "allow"): a policy that allows `email` outright
 * gets no email-shaped path hints; a policy that blocks `api_key` gets the
 * secrets-shaped patterns. This keeps the exclusion file and the scanning
 * policy expressing the same intent from the same document, rather than two
 * independently-maintained lists that drift apart.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { Action, DetectorId, Policy } from "@wardkeep/policy-engine";
import { loadPolicy } from "./policy.js";

export type ExclusionFormat = "cursorignore" | "copilot-yaml" | "aiignore";

const VALID_FORMATS: ExclusionFormat[] = ["cursorignore", "copilot-yaml", "aiignore"];

function isExclusionFormat(value: string): value is ExclusionFormat {
  return (VALID_FORMATS as string[]).includes(value);
}

/**
 * Default path patterns for the kinds of files that hold what each detector
 * looks for, keyed by the detector id that justifies excluding them. Only
 * detectors where a *filename* is a meaningful signal are listed —
 * `email`/`phone` have no distinctive path shape (any text file can contain
 * one), so including them would just be noise, not a "sensible default".
 */
const PATTERNS_BY_DETECTOR: Partial<Record<DetectorId, string[]>> = {
  api_key: [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_rsa.*",
    "id_ed25519",
    "id_ed25519.*",
    "credentials",
    "credentials.*",
    "secrets",
    "secrets.*",
    "*.p12",
    "*.pfx",
    ".aws/**",
    ".kube/**",
    "service-account*.json",
  ],
  private_key: ["*.pem", "*.key", "id_rsa", "id_rsa.*", "id_ed25519", "id_ed25519.*", "*.p12", "*.pfx"],
  connection_string: [".env", ".env.*", "credentials", "credentials.*", "secrets", "secrets.*"],
  jwt: [".env", ".env.*"],
  credit_card: ["*.sql", "*dump.sql", "*.csv"],
  iban: ["*.sql", "*dump.sql", "*.csv"],
  at_svnr: ["*.sql", "*dump.sql", "*.csv"],
  bulk_pii: ["*.sql", "*dump.sql", "*.csv"],
};

/** Mirrors engine.ts's own rule resolution: an explicit rule wins, else the policy default. */
function actionFor(policy: Policy, detector: string): Action {
  const rule = policy.rules.find((r) => r.detector === detector);
  return rule ? rule.action : policy.defaultAction;
}

/**
 * The deduped, sorted union of path patterns for every detector this policy
 * enables (action !== "allow"). Sorting makes the result independent of
 * `PATTERNS_BY_DETECTOR`'s own key order, so rendering is deterministic by
 * construction rather than by accident of object iteration order. Exported
 * for direct unit testing.
 */
export function activeExclusionPatterns(policy: Policy): string[] {
  const set = new Set<string>();
  for (const [detector, patterns] of Object.entries(PATTERNS_BY_DETECTOR)) {
    if (actionFor(policy, detector) === "allow") continue;
    for (const pattern of patterns) set.add(pattern);
  }
  return [...set].sort();
}

interface FormatSpec {
  commentPrefix: string;
  /** Caveat lines specific to this format's real-world enforcement story. */
  caveat: string[];
  listItem: (pattern: string) => string;
  emptyNote: string;
}

const FORMAT_SPECS: Record<ExclusionFormat, FormatSpec> = {
  cursorignore: {
    commentPrefix: "#",
    caveat: [
      "Cursor describes .cursorignore as BEST-EFFORT: excluding a path here is not a",
      "guarantee Cursor never reads it or sends it to a model. Treat this as a hint,",
      "not a control.",
    ],
    listItem: (p) => p,
    emptyNote: "# (no active detector in the resolved policy maps to a known file pattern)",
  },
  "copilot-yaml": {
    commentPrefix: "#",
    caveat: [
      'GitHub Copilot "content exclusion" is enforced SERVER-SIDE once this list is',
      "pasted into the target repository's or organization's Settings > Copilot >",
      "Content exclusion. Per GitHub's own documentation it is NOT applied to Copilot",
      "CLI, the Copilot coding agent, or Copilot Chat's agent mode — only to editor",
      "code completions and Copilot Chat's own context. This file has no effect on",
      "its own; wardkeep makes no network calls and cannot push it to GitHub for",
      "you.",
    ],
    listItem: (p) => `- "${p}"`,
    emptyNote: "# (no active detector in the resolved policy maps to a known file pattern)",
  },
  aiignore: {
    commentPrefix: "#",
    caveat: [
      ".aiignore is a COMMUNITY CONVENTION, comparable to .copilotignore — not a",
      "feature every AI coding tool guarantees to enforce. Some tools document",
      "honoring a file with this name; others ignore it entirely. Treat this as a",
      "best-effort, local-only hint, never as a substitute for scanning.",
    ],
    listItem: (p) => p,
    emptyNote: "# (no active detector in the resolved policy maps to a known file pattern)",
  },
};

/**
 * Render the full contents of an exclusion file for `format` from `policy`.
 * Pure and deterministic: same (format, policy) always produces the same
 * string, byte for byte. Exported for direct unit testing.
 */
export function renderExclusions(format: ExclusionFormat, policy: Policy): string {
  const spec = FORMAT_SPECS[format];
  const c = spec.commentPrefix;
  const patterns = activeExclusionPatterns(policy);

  const lines: string[] = [
    `${c} Generated by wardkeep emit-exclusions from policy "${policy.name}".`,
    `${c} Regenerate, do not hand-edit: wardkeep emit-exclusions --format ${format}`,
    `${c}`,
    `${c} ENFORCEMENT IS VENDOR-SIDE AND BEST-EFFORT ONLY. This file does not scan or`,
    `${c} block anything itself — wardkeep's scanning runs entirely elsewhere (see`,
    `${c} \`wardkeep scan\`, the Claude Code hook, the MCP gateway). It only tells a`,
    `${c} supporting IDE feature which paths to leave out of its own context, and`,
    `${c} wardkeep cannot verify that any editor actually honors it.`,
    `${c}`,
    ...spec.caveat.map((l) => `${c} ${l}`),
    "",
  ];

  if (patterns.length === 0) {
    lines.push(spec.emptyNote);
  } else {
    for (const p of patterns) lines.push(spec.listItem(p));
  }

  return lines.join("\n") + "\n";
}

const USAGE = `Usage: wardkeep emit-exclusions --format <cursorignore|copilot-yaml|aiignore> [--out <path>]

  --format <fmt>   Which vendor exclusion file to render: cursorignore, copilot-yaml, or aiignore.
  --out <path>     Write the rendered file to <path> instead of stdout.

Renders PATH-based exclusion hints from the resolved policy (same discovery precedence as
\`wardkeep scan\`). These are vendor-side, best-effort signals for surfaces this tool cannot
otherwise reach (IDE inline completions) — see docs/IDE.md for exactly what each format does and
does not enforce. This command does not scan or block anything itself.

Exit codes: 0 written, 3 config/argument error.
`;

interface EmitExclusionsArgs {
  format?: ExclusionFormat;
  out?: string;
  error?: string;
}

function parseArgs(argv: string[]): EmitExclusionsArgs {
  const args: EmitExclusionsArgs = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--format") {
      const value = argv[++i];
      if (value === undefined) {
        args.error = "wardkeep emit-exclusions: --format requires a value";
        return args;
      }
      if (!isExclusionFormat(value)) {
        args.error = `wardkeep emit-exclusions: unknown format "${value}" (expected cursorignore, copilot-yaml, or aiignore)`;
        return args;
      }
      args.format = value;
    } else if (a === "--out") {
      const value = argv[++i];
      if (value === undefined) {
        args.error = "wardkeep emit-exclusions: --out requires a path";
        return args;
      }
      args.out = value;
    } else if (a === "--help" || a === "-h") {
      args.error = ""; // signal "print usage, exit 3" without an error line
      return args;
    } else {
      args.error = `wardkeep emit-exclusions: unknown argument "${a}"`;
      return args;
    }
  }
  if (args.format === undefined) {
    args.error = "wardkeep emit-exclusions: --format is required";
  }
  return args;
}

export async function runEmitExclusions(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args.error !== undefined || args.format === undefined) {
    if (args.error) process.stderr.write(args.error + "\n");
    process.stderr.write(USAGE);
    return 3;
  }

  let policy: Policy;
  let policySource: string;
  try {
    ({ policy, source: policySource } = await loadPolicy());
  } catch (err) {
    process.stderr.write(`${(err as Error).message}\n`);
    return 3;
  }

  const content = renderExclusions(args.format, policy);

  if (args.out) {
    try {
      await mkdir(dirname(args.out), { recursive: true });
      await writeFile(args.out, content, "utf8");
    } catch (err) {
      process.stderr.write(`wardkeep emit-exclusions: could not write "${args.out}": ${(err as Error).message}\n`);
      return 3;
    }
    process.stderr.write(
      `wardkeep emit-exclusions: wrote ${args.out} (format: ${args.format}, policy: "${policy.name}", source: ${policySource})\n`,
    );
  } else {
    process.stdout.write(content);
  }

  return 0;
}
