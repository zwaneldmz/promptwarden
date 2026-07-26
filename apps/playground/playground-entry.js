/**
 * Bootstrap for the standalone playground build (apps/playground/dist/).
 *
 * No chrome.* APIs, no network calls: policy storage is an in-page
 * localStorage-backed store, falling back to a plain in-memory store for
 * this tab when localStorage is unavailable (some file:// contexts reject
 * it outright) — never throws either way. There is no managed-policy
 * concept here: this is the "try it with no install" surface, so
 * `loadManaged` always resolves to null.
 */
import * as engine from "../../packages/policy-engine/src/index.ts";
import { mountPolicyEditor } from "./policy-editor.js";

const STORAGE_KEY = "promptwarden-playground-policy";

function makeStore() {
  let memory = null;
  let ls = null;
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem("__pw_probe__", "1");
      localStorage.removeItem("__pw_probe__");
      ls = localStorage;
    }
  } catch {
    ls = null; // file:// or a privacy mode may block storage access entirely
  }
  return {
    get() {
      if (!ls) return memory;
      try {
        const raw = ls.getItem(STORAGE_KEY);
        return raw ? JSON.parse(raw) : null;
      } catch {
        return null;
      }
    },
    set(policy) {
      memory = policy;
      if (!ls) return;
      try {
        ls.setItem(STORAGE_KEY, JSON.stringify(policy));
      } catch {
        /* storage full or blocked — the in-memory copy above still holds
           for the rest of this tab's session */
      }
    },
  };
}

const store = makeStore();

mountPolicyEditor(document.getElementById("pw-editor-root"), {
  engine,
  loadManaged: async () => null,
  loadLocal: async () => store.get(),
  saveLocal: async (policy) => store.set(policy),
  environmentNote:
    "Standalone playground — nothing typed here is uploaded anywhere. Saved policies stay in this browser tab only (or in memory for this tab if storage is unavailable), never sent over the network.",
});
