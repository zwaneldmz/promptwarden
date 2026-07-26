/**
 * Bundle entry for the extension's options page.
 *
 * Re-exports the policy engine's public API plus the shared policy-editor
 * UI module as a single ES module — built by build.mjs into
 * apps/extension/engine.bundle.js (gitignored, matching the existing
 * `*.bundle.js` pattern alongside content.bundle.js/background.js).
 * options.js imports from that bundle rather than being bundled itself, so
 * options.js/options.html stay hand-written vanilla JS with no build step
 * of their own — matching popup.js's house style — while still running the
 * real engine, not a reimplementation. See build.mjs's header comment for
 * why this bundling step lives here rather than in the root package.json's
 * existing "build:extension" script.
 */
export * from "../../packages/policy-engine/src/index.ts";
export { mountPolicyEditor } from "./policy-editor.js";
