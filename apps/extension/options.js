/**
 * Options page: a local-first policy editor.
 *
 * Vanilla JS, no framework, no build step for this file itself — the real
 * detection engine (and the shared editor UI module it drives) arrives
 * already bundled as an ES module, ./engine.bundle.js, built by
 * `npm run build:playground` (apps/playground/build.mjs) from
 * packages/policy-engine and apps/playground/policy-editor.js. See that
 * build script's header comment for why bundling lands there rather than
 * in the existing "build:extension" script.
 *
 * Policy precedence mirrors background.ts's resolvePolicy: a managed policy
 * (read directly from chrome.storage.managed here, the same direct-read
 * pattern popup.js already uses for extraHosts) always wins and is rendered
 * read-only; otherwise the locally saved policy (chrome.storage.local) is
 * editable, defaulting to a starter template when nothing has been saved
 * yet.
 */
import * as bundle from "./engine.bundle.js";

const { mountPolicyEditor, ...engine } = bundle;

async function loadManaged() {
  try {
    const managed = await chrome.storage.managed.get(["policy"]);
    return typeof managed.policy === "string" && managed.policy.length > 0 ? managed.policy : null;
  } catch {
    return null; // managed storage unavailable outside enterprise deployments
  }
}

async function loadLocal() {
  const local = await chrome.storage.local.get(["policy"]);
  return local.policy && typeof local.policy === "object" ? local.policy : null;
}

async function saveLocal(policy) {
  await chrome.storage.local.set({ policy });
}

mountPolicyEditor(document.getElementById("pw-editor-root"), {
  engine,
  loadManaged,
  loadLocal,
  saveLocal,
});

// A managed policy pushed or corrected while this page is already open
// should be reflected without asking the user to reopen the tab. Reload is
// the simplest correct response here since mountPolicyEditor only wires
// itself up once per call.
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "managed" && "policy" in changes) {
    location.reload();
  }
});
