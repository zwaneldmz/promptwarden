/**
 * Live-browser smoke regression for the extension's interception paths.
 *
 * Loads the unpacked extension into a local Chromium-family browser and
 * checks that the guardrail fires on a real chat site for:
 *   1. Enter-submit  (keydown path)
 *   2. click-to-send (focusin-tracked fallback, since focus moves to the
 *      send button before a plain activeEditable() check would catch it)
 *   3. paste         (paste path)
 *
 * Not covered: the <form> submit path (no supported host uses a plain form
 * submit; verified manually) and the bypass-expiry timer (needs a real
 * send; verified manually).
 *
 * Usage:
 *   node tools/e2e-smoke.mjs
 *     chatgpt.com only. Any failure, including a missing editor (e.g. a
 *     login wall), throws and exits non-zero.
 *
 *   node tools/e2e-smoke.mjs --all
 *     Runs against every host in apps/extension/manifest.json's
 *     content_scripts[0].matches. A host where no editor is found within
 *     the timeout (login wall, bot wall, CAPTCHA) is logged SKIP and does
 *     not fail the run; any other failure is a FAIL and does. Prints a
 *     PASS/FAIL/SKIP summary table and exits non-zero iff any host FAILed.
 *     See docs/HOST_COVERAGE.md and .github/workflows/smoke.yml.
 *
 *   PW_BROWSER=/path/to/chrome overrides the browser binary.
 *
 * Requires a headed-capable environment (xvfb-run on headless CI).
 */
import { chromium } from "playwright-core";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXT = path.join(ROOT, "apps", "extension");
const BROWSER =
  process.env.PW_BROWSER ?? "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";

const ALL = process.argv.includes("--all");

// Read the host matrix from the manifest so it can't drift from the
// extension's declared coverage.
const manifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8"));
const MANIFEST_HOSTS = manifest.content_scripts[0].matches.map(
  (m) => new URL(m.replace(/\*$/, "")).origin + "/",
);

const SITES = ALL ? MANIFEST_HOSTS : ["https://chatgpt.com/"];

const IBAN_TEXT = "please pay invoice 118 to AT61 1904 3002 3457 3201 thanks";
const CARD_TEXT = "customer card on file: 4532 0151 1283 0366";
const GUARDRAIL = "#promptwarden-guardrail";

async function editor(page) {
  for (const s of ["#prompt-textarea", "textarea", '[contenteditable="true"]']) {
    const el = page.locator(s).first();
    try {
      await el.waitFor({ state: "visible", timeout: 4000 });
      return el;
    } catch {}
  }
  throw new Error("no editor found (login/bot wall?)");
}

async function expectGuardrail(page, label) {
  await page.locator(GUARDRAIL).waitFor({ state: "visible", timeout: 4000 });
  const text = await page.locator(GUARDRAIL).innerText();
  console.log(`  PASS ${label}: ${text.split("\n")[0]} | ${text.split("\n")[1] ?? ""}`);
  await page.locator(`${GUARDRAIL} button`, { hasText: /Cancel|Close/ }).click();
  await page.locator(GUARDRAIL).waitFor({ state: "hidden", timeout: 2000 });
}

async function clearEditor(page, ed) {
  await ed.click();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+a" : "Control+a");
  await page.keyboard.press("Backspace");
}

async function runChecks(ctx, page) {
  const ed = await editor(page);

  // 1. Enter path
  await ed.click();
  await page.keyboard.type(IBAN_TEXT, { delay: 10 });
  await page.keyboard.press("Enter");
  await expectGuardrail(page, "enter-submit (iban)");

  // 2. Click-to-send path — focus moves to the button before our listener runs
  await clearEditor(page, ed);
  await page.keyboard.type(CARD_TEXT, { delay: 10 });
  const send = page
    .locator('button[data-testid*="send" i], button[aria-label*="end" i], button[type="submit"]')
    .first();
  await send.click();
  await expectGuardrail(page, "click-to-send (credit_card)");

  // 3. Paste path
  await clearEditor(page, ed);
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], {
    origin: new URL(page.url()).origin,
  });
  await page.evaluate((t) => navigator.clipboard.writeText(t), IBAN_TEXT);
  await ed.click();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+v" : "Control+v");
  await expectGuardrail(page, "paste (iban)");
}

async function smokeHost(site) {
  const profile = path.join(os.tmpdir(), `pw-smoke-${process.pid}-${new URL(site).hostname}`);
  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: BROWSER,
    headless: false,
    viewport: { width: 1280, height: 860 },
    args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`],
  });
  try {
    const page = ctx.pages()[0] ?? (await ctx.newPage());
    console.log(`\n== ${site} ==`);
    await page.goto(site, { waitUntil: "domcontentloaded", timeout: 30000 });
    await page.waitForTimeout(3500);
    await runChecks(ctx, page);
    return { host: site, status: "PASS", detail: "" };
  } catch (e) {
    const noEditor = /no editor found/.test(e.message);
    if (ALL && noEditor) {
      console.log(`  SKIP ${site}: ${e.message}`);
      return { host: site, status: "SKIP", detail: e.message };
    }
    console.log(`  FAIL ${site}: ${e.message}`);
    if (!ALL) throw e; // default single-host run: propagate, non-zero exit, as before
    return { host: site, status: "FAIL", detail: e.message };
  } finally {
    await ctx.close();
  }
}

const results = [];
for (const site of SITES) {
  results.push(await smokeHost(site));
}

if (ALL) {
  console.log("\n=== Summary ===");
  for (const r of results) {
    console.log(`${r.status.padEnd(4)} ${r.host}${r.detail ? `  (${r.detail})` : ""}`);
  }
  const passes = results.filter((r) => r.status === "PASS").length;
  const fails = results.filter((r) => r.status === "FAIL").length;
  const skips = results.filter((r) => r.status === "SKIP").length;
  console.log(`\n${passes} passed, ${fails} failed, ${skips} skipped (of ${results.length} hosts)`);
  if (fails > 0) {
    console.log("SMOKE FAILED");
    process.exit(1);
  }
  console.log("SMOKE DONE (a skip is not a pass — see counts above)");
} else {
  console.log("\nALL PASS");
}
