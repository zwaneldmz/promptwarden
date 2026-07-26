import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BUILTIN_DEFAULT_POLICY,
  applyStrictnessMonotonicClamp,
  findRepoLocalPolicyPath,
  isSafeLocalPolicyFile,
  loadPolicyFrom,
} from "../dist/policy.js";
// `@promptwarden/policy-engine` is not a real resolvable package (no
// package.json; it only resolves via esbuild's --alias at CLI-build time and
// tsconfig `paths` at typecheck time — see ROADMAP §1.1 #24). For a plain
// `node --test` run against a built engine, reach it via the built engine
// package's own dist path instead.
import { evaluate } from "../../../packages/policy-engine/dist/src/engine.js";

async function tmpDir(prefix) {
  return mkdtemp(join(tmpdir(), prefix));
}

/** A minimal, valid Policy document as a plain object ready for JSON.stringify. */
function policyDoc(overrides = {}) {
  return {
    version: 1,
    name: "test-policy",
    hosts: [],
    defaultAction: "allow",
    logging: "event",
    rules: [],
    ...overrides,
  };
}

/** discoveryPaths pointing at locations that are guaranteed empty/absent by default. */
async function emptyPaths(cwd) {
  return {
    etcPath: join(cwd, "does-not-exist", "etc-policy.json"),
    envPolicyPath: undefined,
    xdgConfigHome: join(cwd, "does-not-exist-xdg"),
    cwd,
  };
}

test("loadPolicyFrom resolves the built-in default when nothing is configured", async () => {
  const cwd = await tmpDir("pw-policy-none-");
  const paths = await emptyPaths(cwd);
  const { policy, source } = await loadPolicyFrom(paths);
  assert.equal(source, "built-in default");
  assert.deepEqual(policy, BUILTIN_DEFAULT_POLICY);
});

test("precedence: etcPath wins over env, xdg, and repo-local all being present", async () => {
  const root = await tmpDir("pw-policy-precedence-etc-");
  const etcPath = join(root, "etc", "policy.json");
  const envPath = join(root, "env-policy.json");
  const xdgHome = join(root, "xdg");
  const cwd = join(root, "repo");
  await mkdir(join(root, "etc"), { recursive: true });
  await mkdir(cwd, { recursive: true });
  await writeFile(etcPath, JSON.stringify(policyDoc({ name: "from-etc" })));
  await writeFile(envPath, JSON.stringify(policyDoc({ name: "from-env" })));
  await mkdir(join(xdgHome, "promptwarden"), { recursive: true });
  await writeFile(join(xdgHome, "promptwarden", "policy.json"), JSON.stringify(policyDoc({ name: "from-xdg" })));
  await writeFile(join(cwd, ".promptwarden.json"), JSON.stringify(policyDoc({ name: "from-repo-local" })));

  const { policy, source } = await loadPolicyFrom({ etcPath, envPolicyPath: envPath, xdgConfigHome: xdgHome, cwd });
  assert.equal(policy.name, "from-etc");
  assert.equal(source, etcPath);
});

test("precedence: envPolicyPath wins over xdg and repo-local when etc is absent", async () => {
  const root = await tmpDir("pw-policy-precedence-env-");
  const etcPath = join(root, "etc", "policy.json"); // never created
  const envPath = join(root, "env-policy.json");
  const xdgHome = join(root, "xdg");
  const cwd = join(root, "repo");
  await mkdir(cwd, { recursive: true });
  await writeFile(envPath, JSON.stringify(policyDoc({ name: "from-env" })));
  await mkdir(join(xdgHome, "promptwarden"), { recursive: true });
  await writeFile(join(xdgHome, "promptwarden", "policy.json"), JSON.stringify(policyDoc({ name: "from-xdg" })));
  await writeFile(join(cwd, ".promptwarden.json"), JSON.stringify(policyDoc({ name: "from-repo-local" })));

  const { policy, source } = await loadPolicyFrom({ etcPath, envPolicyPath: envPath, xdgConfigHome: xdgHome, cwd });
  assert.equal(policy.name, "from-env");
  assert.equal(source, envPath);
});

test("precedence: xdg wins over repo-local when etc and env are absent", async () => {
  const root = await tmpDir("pw-policy-precedence-xdg-");
  const etcPath = join(root, "etc", "policy.json");
  const xdgHome = join(root, "xdg");
  const cwd = join(root, "repo");
  await mkdir(cwd, { recursive: true });
  await mkdir(join(xdgHome, "promptwarden"), { recursive: true });
  await writeFile(join(xdgHome, "promptwarden", "policy.json"), JSON.stringify(policyDoc({ name: "from-xdg" })));
  await writeFile(join(cwd, ".promptwarden.json"), JSON.stringify(policyDoc({ name: "from-repo-local" })));

  const { policy, source } = await loadPolicyFrom({ etcPath, envPolicyPath: undefined, xdgConfigHome: xdgHome, cwd });
  assert.equal(policy.name, "from-xdg");
  assert.equal(source, join(xdgHome, "promptwarden", "policy.json"));
});

test("repo-local is found by walking up from a nested cwd", async () => {
  const root = await tmpDir("pw-policy-walkup-");
  const nested = join(root, "a", "b", "c");
  await mkdir(nested, { recursive: true });
  await writeFile(join(root, ".promptwarden.json"), JSON.stringify(policyDoc({ name: "root-of-repo" })));

  const found = await findRepoLocalPolicyPath(nested);
  assert.equal(found, join(root, ".promptwarden.json"));

  const paths = await emptyPaths(nested);
  const { policy, source } = await loadPolicyFrom(paths);
  assert.equal(policy.name, "root-of-repo");
  assert.match(source, /strictness-monotonic/);
});

test("etcPath present but not valid JSON is a hard error (never falls through)", async () => {
  const root = await tmpDir("pw-policy-etc-malformed-");
  const etcPath = join(root, "policy.json");
  await writeFile(etcPath, "{ not json");
  const cwd = join(root, "repo");
  await mkdir(cwd, { recursive: true });
  // Even a valid, more-permissive-looking repo-local file must not be reached.
  await writeFile(join(cwd, ".promptwarden.json"), JSON.stringify(policyDoc({ name: "should-not-be-used" })));

  await assert.rejects(
    () => loadPolicyFrom({ etcPath, envPolicyPath: undefined, xdgConfigHome: join(root, "xdg"), cwd }),
    /not valid JSON/,
  );
});

test("envPolicyPath set but the file does not exist is a hard error", async () => {
  const root = await tmpDir("pw-policy-env-missing-");
  const cwd = join(root, "repo");
  await mkdir(cwd, { recursive: true });
  const envPath = join(root, "nope.json");

  await assert.rejects(
    () =>
      loadPolicyFrom({
        etcPath: join(root, "etc-nope.json"),
        envPolicyPath: envPath,
        xdgConfigHome: join(root, "xdg-nope"),
        cwd,
      }),
    /PROMPTWARDEN_POLICY/,
  );
});

test("xdg policy present but fails schema validation is a hard error", async () => {
  const root = await tmpDir("pw-policy-xdg-invalid-");
  const xdgHome = join(root, "xdg");
  await mkdir(join(xdgHome, "promptwarden"), { recursive: true });
  // Valid JSON, invalid Policy shape (bad action).
  await writeFile(
    join(xdgHome, "promptwarden", "policy.json"),
    JSON.stringify(policyDoc({ rules: [{ detector: "credit_card", action: "nuke" }] })),
  );
  const cwd = join(root, "repo");
  await mkdir(cwd, { recursive: true });

  await assert.rejects(
    () =>
      loadPolicyFrom({
        etcPath: join(root, "etc-nope.json"),
        envPolicyPath: undefined,
        xdgConfigHome: xdgHome,
        cwd,
      }),
    /failed policy validation/,
  );
});

test("repo-local malformed JSON is skipped, not fatal — falls back to the built-in default", async () => {
  const root = await tmpDir("pw-policy-repo-malformed-");
  const cwd = join(root, "repo");
  await mkdir(cwd, { recursive: true });
  await writeFile(join(cwd, ".promptwarden.json"), "{ not json at all");

  const paths = await emptyPaths(cwd);
  const { policy, source } = await loadPolicyFrom(paths);
  assert.equal(source, "built-in default");
  assert.deepEqual(policy, BUILTIN_DEFAULT_POLICY);
});

test("repo-local symlink is rejected — falls back to the built-in default", async () => {
  const root = await tmpDir("pw-policy-repo-symlink-");
  const cwd = join(root, "repo");
  await mkdir(cwd, { recursive: true });
  const real = join(root, "real-policy.json");
  await writeFile(real, JSON.stringify(policyDoc({ name: "should-not-be-used", defaultAction: "block" })));
  await symlink(real, join(cwd, ".promptwarden.json"));

  const safe = await isSafeLocalPolicyFile(join(cwd, ".promptwarden.json"));
  assert.equal(safe, false);

  const paths = await emptyPaths(cwd);
  const { policy, source } = await loadPolicyFrom(paths);
  assert.equal(source, "built-in default");
  assert.deepEqual(policy, BUILTIN_DEFAULT_POLICY);
});

test("repo-local file not owned by the invoking uid is rejected", async (t) => {
  if (typeof process.getuid !== "function") {
    t.skip("no process.getuid on this platform");
    return;
  }
  const root = await tmpDir("pw-policy-repo-owner-");
  const cwd = join(root, "repo");
  await mkdir(cwd, { recursive: true });
  const filePath = join(cwd, ".promptwarden.json");
  await writeFile(filePath, JSON.stringify(policyDoc({ name: "not-mine" })));

  const realGetuid = process.getuid;
  const realUid = realGetuid.call(process);
  // Simulate "the file is owned by someone else" by having the *process*
  // report a uid that does not match the real owner of the file we just
  // created (which is genuinely owned by whoever is running this test).
  process.getuid = () => realUid + 1;
  try {
    const safe = await isSafeLocalPolicyFile(filePath);
    assert.equal(safe, false);
  } finally {
    process.getuid = realGetuid;
  }
});

test("applyStrictnessMonotonicClamp raises a weakened rule, keeps a stricter one, fills in a missing floor rule, and forces logging content -> event", () => {
  const floor = BUILTIN_DEFAULT_POLICY; // credit_card: warn, iban: warn, api_key: warn, at_svnr: warn, email: allow, phone: allow; defaultAction: allow
  const candidate = policyDoc({
    name: "untrusted-repo-local",
    defaultAction: "allow",
    logging: "content",
    rules: [
      { detector: "credit_card", action: "allow" }, // attempts to weaken warn -> allow
      { detector: "iban", action: "block" }, // already stricter than warn — must be kept as-is
      // at_svnr is not mentioned at all — floor (warn) must be synthesized
    ],
  });

  const clamped = applyStrictnessMonotonicClamp(candidate, floor);

  const ruleFor = (id) => clamped.rules.find((r) => r.detector === id);
  assert.equal(ruleFor("credit_card").action, "warn", "weakened rule must be raised to the floor");
  assert.equal(ruleFor("iban").action, "block", "already-stricter rule must be left alone");
  assert.ok(ruleFor("at_svnr"), "a floor-constrained detector missing from the candidate must be synthesized");
  assert.equal(ruleFor("at_svnr").action, "warn");
  assert.equal(clamped.logging, "event", 'logging:"content" must never survive the repo-local layer');
});

test("applyStrictnessMonotonicClamp strips exceptions entirely — a repo-local policy cannot introduce or extend them", () => {
  // exceptions is a strictness REDUCTION (ROADMAP §1.4 #17): a repo-local
  // .promptwarden.json must not be able to suppress a finding the floor
  // requires by shipping a broad exception pattern.
  const floor = BUILTIN_DEFAULT_POLICY;
  const candidate = policyDoc({
    name: "untrusted-repo-local-with-exception",
    defaultAction: "allow",
    logging: "event",
    rules: [{ detector: "credit_card", action: "block" }], // stricter than the floor, kept as-is
    exceptions: [{ detector: "credit_card", pattern: ".*", note: "attempts to disable credit_card entirely" }],
  });

  const clamped = applyStrictnessMonotonicClamp(candidate, floor);
  assert.equal(clamped.exceptions, undefined, "exceptions must not survive the clamp");
});

test("loadPolicyFrom: a repo-local policy carrying an exception cannot suppress a finding end-to-end", async () => {
  const root = await tmpDir("pw-policy-repo-exception-");
  const cwd = join(root, "repo");
  await mkdir(cwd, { recursive: true });
  await writeFile(
    join(cwd, ".promptwarden.json"),
    JSON.stringify(
      policyDoc({
        name: "weak-repo-local-with-exception",
        defaultAction: "allow",
        logging: "event",
        rules: [{ detector: "credit_card", action: "block" }],
        // A broad exception that, if it survived the clamp, would suppress
        // every credit_card finding — exactly what an untrusted `git clone`
        // must not be able to do.
        exceptions: [{ detector: "credit_card", pattern: ".*" }],
      }),
    ),
  );

  const paths = await emptyPaths(cwd);
  const { policy, source } = await loadPolicyFrom(paths);
  assert.match(source, /strictness-monotonic/);
  assert.equal(policy.exceptions, undefined);

  const r = evaluate("card on file: 4532 0151 1283 0366", policy); // Luhn-valid Visa test number
  assert.equal(r.blocked, true, "the repo-local exception must not have suppressed the credit_card finding");
});

test("loadPolicyFrom applies the clamp end-to-end to a resolved repo-local policy", async () => {
  const root = await tmpDir("pw-policy-repo-clamp-e2e-");
  const cwd = join(root, "repo");
  await mkdir(cwd, { recursive: true });
  await writeFile(
    join(cwd, ".promptwarden.json"),
    JSON.stringify(
      policyDoc({
        name: "weak-repo-local",
        defaultAction: "allow",
        logging: "content",
        rules: [{ detector: "credit_card", action: "allow" }],
      }),
    ),
  );

  const paths = await emptyPaths(cwd);
  const { policy, source } = await loadPolicyFrom(paths);
  assert.match(source, /\.promptwarden\.json \(strictness-monotonic clamp applied\)$/);
  assert.equal(policy.logging, "event");
  assert.equal(policy.rules.find((r) => r.detector === "credit_card").action, "warn");
});
