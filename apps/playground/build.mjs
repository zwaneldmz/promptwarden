#!/usr/bin/env node
/**
 * Builds two things from one command (`npm run build:playground`):
 *
 * 1. apps/extension/engine.bundle.js — the real policy engine
 *    (packages/policy-engine/src/index.ts) plus the shared policy-editor UI
 *    module (./policy-editor.js), bundled together as a single ES module.
 *    Gitignored, matching the existing `*.bundle.js` pattern alongside
 *    content.bundle.js/background.js. apps/extension/options.js imports
 *    directly from it (`import ... from "./engine.bundle.js"`).
 *
 *    Why here and not in the root package.json's existing "build:extension"
 *    script: this task's file ownership is scoped to options.html/
 *    options.js/popup.js/apps/playground/** and exactly one new package.json
 *    script ("build:playground") — build:extension (which bundles
 *    content.ts/background.ts) belongs to a different part of the codebase
 *    and is intentionally left untouched. Folding the options-page engine
 *    bundle into build:extension instead of here is a reasonable follow-up
 *    for whoever owns that script; until then, running
 *    `npm run build:playground` at least once (e.g. as part of packaging,
 *    or in CI alongside build:extension) is required for the options page's
 *    live preview to have a real engine to call. It does not affect
 *    typecheck/build:extension/build:cli/test — none of them read
 *    options.js or this output.
 *
 * 2. apps/playground/dist/index.html — a single, self-contained HTML file
 *    (styles + the bundled engine/editor/bootstrap inlined into one
 *    <script> tag) that can be opened directly from disk or served
 *    statically. No network calls, no analytics, no external fonts —
 *    everything the page needs is inlined into this one file.
 *
 * Uses esbuild's JS API (esbuild is already a devDependency; this adds no
 * new runtime dependency) rather than shelling out, so the whole thing is a
 * single `node` invocation.
 */
import { build } from "esbuild";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");

async function buildExtensionEngineBundle() {
  await build({
    entryPoints: [path.join(here, "extension-entry.js")],
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    outfile: path.join(repoRoot, "apps/extension/engine.bundle.js"),
    logLevel: "info",
  });
}

async function buildPlaygroundBundle() {
  const result = await build({
    entryPoints: [path.join(here, "playground-entry.js")],
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "es2022",
    write: false,
    logLevel: "info",
  });
  const js = result.outputFiles[0].text;
  const html = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Wardkeep Playground</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  html,body{margin:0;background:#101418;color:#e8edf2;font:14px/1.5 system-ui,sans-serif;}
</style>
</head>
<body>
<div id="pw-editor-root"></div>
<script>
${js}
</script>
</body>
</html>
`;
  const distDir = path.join(here, "dist");
  await mkdir(distDir, { recursive: true });
  await writeFile(path.join(distDir, "index.html"), html, "utf8");
}

await buildExtensionEngineBundle();
await buildPlaygroundBundle();
console.log("build:playground — wrote apps/extension/engine.bundle.js and apps/playground/dist/index.html");
