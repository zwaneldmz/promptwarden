/**
 * CLI policy discovery.
 *
 * Precedence (highest wins), per docs/ROADMAP.md §2 — deliberately the
 * INVERSE of "nearest file wins", because a `.wardkeep.json` shipped
 * inside an untrusted `git clone` must never be able to downgrade a strict
 * rule:
 *
 *   1. /etc/wardkeep/policy.json  — root-owned, the managed-storage
 *      analogue; what makes the existing GPO/Intune/Jamf docs extend to
 *      the CLI.
 *   2. $WARDKEEP_POLICY           — a PATH, never inline JSON (env vars
 *      leak via `ps -E` and CI logs).
 *   3. $XDG_CONFIG_HOME/wardkeep/policy.json (default ~/.config)
 *   4. repo-local .wardkeep.json, found by walking up from cwd, applied
 *      STRICTNESS-MONOTONIC ONLY: it may raise a rule's action (per the
 *      severity order allow < observe < warn < redact < block), never lower
 *      it below the built-in default's floor, never turn logging up to
 *      "content", and is rejected outright if the file is a symlink or not
 *      owned by the invoking uid.
 *   5. The built-in default (below).
 *
 * Every candidate is validated with the engine's own `parsePolicy` — this
 * module never trusts a hand-rolled shape check.
 *
 * A policy document that is *present* at levels 1-3 but fails to parse is
 * treated as a genuine configuration error (this function rejects/throws):
 * those locations are only ever populated deliberately by a human, so a
 * broken file there is worth surfacing loudly rather than silently
 * downgrading to a less-trusted source underneath it — the same privilege-
 * inversion concern the browser extension's managed-policy handling
 * documents (see docs/ROADMAP.md §1.1 item 2). The repo-local layer is the
 * opposite case — it can appear in a checkout without anyone deciding to put
 * it there — so a malformed or unsafe repo-local file is only ever skipped
 * (with a stderr note) in favour of the built-in default, never fatal.
 *
 * `hosts` is browser-only: `hostMatches` returns false for `hosts: []`, so
 * the CLI's built-in default carries an empty `hosts` array and every CLI
 * evaluation is unconditional — `hostMatches` is never consulted here.
 */

import { lstat, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { Action, DetectorRule, Policy, parsePolicy } from "@wardkeep/policy-engine";

const ACTION_SEVERITY: Record<Action, number> = {
  allow: 0,
  observe: 1,
  warn: 2,
  redact: 3,
  block: 4,
};

/**
 * Built-in default policy. Mirrors apps/extension/src/default-policy.ts's
 * FALLBACK_POLICY (the "privacy-conscious individual" profile) with one
 * change: `hosts: []`, since the CLI has no notion of a browser tab's host
 * and evaluates every input unconditionally. Run through `parsePolicy` like
 * every other candidate, even though its shape is statically known-valid.
 */
export const BUILTIN_DEFAULT_POLICY: Policy = parsePolicy({
  version: 1,
  name: "cli-standalone-default",
  hosts: [],
  defaultAction: "allow",
  logging: "off",
  rules: [
    { detector: "credit_card", action: "warn" },
    { detector: "iban", action: "warn" },
    { detector: "api_key", action: "warn" },
    { detector: "at_svnr", action: "warn" },
    { detector: "email", action: "allow" },
    { detector: "phone", action: "allow" },
  ],
} satisfies Policy);

function raiseAction(candidate: Action, floor: Action): Action {
  return ACTION_SEVERITY[candidate] >= ACTION_SEVERITY[floor] ? candidate : floor;
}

/**
 * Clamp `candidate` so no rule (and no default fallback) is weaker than the
 * corresponding entry in `floor` — raises are allowed, lowers are not, and
 * `logging: "content"` is forced down to `"event"`. Exported for direct unit
 * testing; `loadPolicy`/`loadPolicyFrom` are the only callers in production.
 */
export function applyStrictnessMonotonicClamp(candidate: Policy, floor: Policy): Policy {
  const floorRuleFor = new Map(floor.rules.map((r) => [r.detector, r.action]));

  const clampedRules: DetectorRule[] = candidate.rules.map((rule) => {
    const floorAction = floorRuleFor.get(rule.detector);
    if (floorAction === undefined) return rule;
    return { ...rule, action: raiseAction(rule.action, floorAction) };
  });

  // A detector the floor constrains but the candidate never mentions would
  // otherwise fall through to candidate.defaultAction, which is not
  // necessarily >= the floor for that specific detector. Materialize an
  // explicit rule so the guarantee holds even for detectors the candidate
  // is silent about.
  for (const [detector, floorAction] of floorRuleFor) {
    if (!clampedRules.some((r) => r.detector === detector)) {
      clampedRules.push({ detector, action: floorAction });
    }
  }

  return {
    ...candidate,
    rules: clampedRules,
    defaultAction: raiseAction(candidate.defaultAction, floor.defaultAction),
    logging: candidate.logging === "content" ? "event" : candidate.logging,
    // `exceptions` (ROADMAP §1.4 #17) is a strictness REDUCTION — each entry
    // can only ever drop a finding a detector would otherwise raise, never
    // add one. Unlike a rule's action, there is no "floor" to raise an
    // exception list toward: the only strictness-monotonic value for the
    // untrusted repo-local layer is none at all, so it is stripped outright
    // rather than merged/intersected with the floor's (which never carries
    // any). Without this, a `.wardkeep.json` inside an untrusted `git
    // clone` could ship an exception with a broad pattern (e.g. `.*`) that
    // silently suppresses every finding for a detector the floor requires.
    exceptions: undefined,
  };
}

/** Read + JSON.parse + parsePolicy a file. `undefined` only for ENOENT. */
async function loadPolicyFile(filePath: string): Promise<Policy | undefined> {
  let raw: string;
  try {
    raw = await readFile(filePath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new Error(`wardkeep: cannot read policy file ${filePath}: ${(err as Error).message}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (err) {
    throw new Error(`wardkeep: ${filePath} is not valid JSON: ${(err as Error).message}`);
  }
  try {
    return parsePolicy(json);
  } catch (err) {
    throw new Error(`wardkeep: ${filePath} failed policy validation: ${(err as Error).message}`);
  }
}

/**
 * Walk from `startDir` up to the filesystem root looking for
 * `.wardkeep.json`. Returns the first match's path, or undefined.
 */
export async function findRepoLocalPolicyPath(startDir: string): Promise<string | undefined> {
  let dir = resolve(startDir);
  for (;;) {
    const candidate = join(dir, ".wardkeep.json");
    try {
      await lstat(candidate);
      return candidate;
    } catch {
      // not here — keep walking up
    }
    const parent = dirname(dir);
    if (parent === dir) return undefined; // reached the filesystem root
    dir = parent;
  }
}

/**
 * The repo-local layer is the one candidate an attacker (or just an
 * unrelated project) can plant without the invoking user's intent, so it is
 * rejected outright if it is a symlink (could point anywhere) or not owned
 * by the process's own uid. `process.getuid` is POSIX-only — the ownership
 * half of the check is skipped (not failed) on platforms without it.
 */
export async function isSafeLocalPolicyFile(filePath: string): Promise<boolean> {
  try {
    const st = await lstat(filePath);
    if (st.isSymbolicLink()) return false;
    if (typeof process.getuid === "function" && st.uid !== process.getuid()) return false;
    return true;
  } catch {
    return false;
  }
}

/** The real, host-derived discovery locations `loadPolicy()` uses. */
export interface PolicyDiscoveryPaths {
  /** Root-owned managed-storage analogue. */
  etcPath: string;
  /** Resolved value of $WARDKEEP_POLICY, or undefined if unset. */
  envPolicyPath: string | undefined;
  /** Resolved value of $XDG_CONFIG_HOME (default ~/.config). */
  xdgConfigHome: string;
  /** Directory to start the repo-local walk-up from. */
  cwd: string;
}

function defaultDiscoveryPaths(): PolicyDiscoveryPaths {
  return {
    etcPath: "/etc/wardkeep/policy.json",
    envPolicyPath: process.env.WARDKEEP_POLICY,
    xdgConfigHome: process.env.XDG_CONFIG_HOME || join(homedir(), ".config"),
    cwd: process.cwd(),
  };
}

/**
 * Resolve the effective policy from `paths` — the parameterized core of
 * `loadPolicy()`, split out so tests can exercise every precedence level and
 * the strictness-monotonic clamp against temp-directory fixtures instead of
 * real system paths (writing to a real /etc requires root, which a test
 * suite must never assume or attempt).
 */
export async function loadPolicyFrom(paths: PolicyDiscoveryPaths): Promise<{ policy: Policy; source: string }> {
  // 1. /etc/wardkeep/policy.json — present-but-broken is a hard error;
  // falling through would hand control to a less-trusted layer underneath.
  const etc = await loadPolicyFile(paths.etcPath);
  if (etc) return { policy: etc, source: paths.etcPath };

  // 2. $WARDKEEP_POLICY, as a path. Set-but-unreadable/invalid is a hard
  // error for the same reason — the user explicitly named this file.
  if (paths.envPolicyPath && paths.envPolicyPath.trim() !== "") {
    const fromEnv = await loadPolicyFile(paths.envPolicyPath);
    if (fromEnv === undefined) {
      throw new Error(
        `wardkeep: $WARDKEEP_POLICY is set to "${paths.envPolicyPath}", but that file does not exist`,
      );
    }
    return { policy: fromEnv, source: paths.envPolicyPath };
  }

  // 3. $XDG_CONFIG_HOME/wardkeep/policy.json
  const xdgPath = join(paths.xdgConfigHome, "wardkeep", "policy.json");
  const fromXdg = await loadPolicyFile(xdgPath);
  if (fromXdg) return { policy: fromXdg, source: xdgPath };

  // 4. repo-local .wardkeep.json — strictness-monotonic only, and only
  // ever skipped (never fatal) on any rejection.
  const repoLocalPath = await findRepoLocalPolicyPath(paths.cwd);
  if (repoLocalPath) {
    const safe = await isSafeLocalPolicyFile(repoLocalPath);
    if (!safe) {
      process.stderr.write(
        `wardkeep: ignoring ${repoLocalPath} — it is a symlink or not owned by the current user\n`,
      );
    } else {
      let candidate: Policy | undefined;
      try {
        candidate = await loadPolicyFile(repoLocalPath);
      } catch (err) {
        process.stderr.write(`${(err as Error).message} — ignoring, falling back further\n`);
        candidate = undefined;
      }
      if (candidate) {
        const clamped = applyStrictnessMonotonicClamp(candidate, BUILTIN_DEFAULT_POLICY);
        return { policy: clamped, source: `${repoLocalPath} (strictness-monotonic clamp applied)` };
      }
    }
  }

  // 5. built-in default
  return { policy: BUILTIN_DEFAULT_POLICY, source: "built-in default" };
}

/** Resolve the effective policy for this invocation. See module doc for precedence. */
export async function loadPolicy(): Promise<{ policy: Policy; source: string }> {
  return loadPolicyFrom(defaultDiscoveryPaths());
}
