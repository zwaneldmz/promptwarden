/**
 * Live-browser smoke regression for the extension's interception paths.
 *
 * Loads the unpacked extension into a local Chromium-family browser and
 * checks that the guardrail fires on a real chat site for:
 *   1. Enter-submit  (keydown path)
 *   2. click-to-send (focusin-tracked fallback, since focus moves to the
 *      send button before a plain activeEditable() check would catch it)
 *   3. paste         (paste path)
 *   4. click-to-send with document.body.id set to the guardrail's OLD fixed
 *      id ("promptwarden-guardrail") beforehand — regression for
 *      ROADMAP.md §1.2 item 4: the click listener's self-exemption used to
 *      be `target.closest("#" + UI_ID)`, and closest() walks up through
 *      ancestors including <body>, so a page setting *body's* id to that
 *      string made the exemption match every click on the page, silently
 *      disabling the whole click-to-send path. See content.ts.
 *
 * Not covered: the <form> submit path (no supported host uses a plain form
 * submit; verified manually) and the bypass-expiry timer (needs a real
 * send; verified manually).
 *
 * How interception is asserted, and why:
 * The dialog renders inside a *closed* ShadowRoot, so nothing outside the
 * extension's own module can query into it — including Playwright, whose
 * locator engine traverses shadow trees via the `element.shadowRoot`
 * getter, which reads null for a closed root. This file does not try to
 * reach inside; weakening the boundary to make the test easier would
 * defeat the fix it guards.
 *
 * What it checks instead is the shadow *host*: a <div> with a
 * crypto.randomUUID() id appended to <html> only when a dialog is shown.
 * The host lives in the light DOM and is therefore observable — a page can
 * see that it exists; what it cannot do is target it by a stable id or
 * reach inside it. Its presence is a direct positive signal that the
 * guardrail fired, and it works for every path (a blocked paste inserts
 * nothing, so text-based heuristics read backwards there).
 *
 * Each check runs on a freshly reloaded page, since the dialog cannot be
 * dismissed by locating a button inside it.
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
const SEND_BUTTON_SELECTOR =
  'button[data-testid*="send" i], button[aria-label*="end" i], button[type="submit"]';
const RELOAD_SETTLE_MS = 3500;

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

/**
 * True once the guardrail's shadow host is in the page — see the file
 * header. Identified by shape (a direct <html> child whose id is a UUID and
 * whose own shadowRoot reads null, i.e. closed), never by a fixed id.
 */
async function guardrailShowing(page) {
  return page.evaluate(() => {
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return [...document.documentElement.children].some(
      (el) => el.tagName === "DIV" && uuid.test(el.id) && el.shadowRoot === null,
    );
  });
}

/** Wait for the guardrail to appear, or fail with what the editable held. */
async function expectIntercepted(page, ed) {
  const deadline = Date.now() + 4000;
  while (Date.now() < deadline) {
    if (await guardrailShowing(page)) return;
    await page.waitForTimeout(100);
  }
  throw new Error("guardrail did not intercept — no dialog host appeared");
}

/**
 * Click the site's send button. Waits for it to become enabled first: these
 * editors are React-backed and the button stays disabled until the typed
 * text lands in component state, so an immediate click is a flaky no-op.
 */
async function clickSend(page) {
  const btn = page.locator(SEND_BUTTON_SELECTOR).first();
  await btn.waitFor({ state: "visible", timeout: 5000 });
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline && !(await btn.isEnabled())) {
    await page.waitForTimeout(100);
  }
  await btn.click();
}

async function reload(page) {
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForTimeout(RELOAD_SETTLE_MS);
}

async function checkEnterSubmit(ctx, page) {
  const ed = await editor(page);
  await ed.click();
  await page.keyboard.type(IBAN_TEXT, { delay: 10 });
  await page.keyboard.press("Enter");
  await expectIntercepted(page, ed);
}

async function checkClickToSend(ctx, page) {
  const ed = await editor(page);
  await ed.click();
  await page.keyboard.type(CARD_TEXT, { delay: 10 });
  await clickSend(page);
  await expectIntercepted(page, ed);
}

async function checkPaste(ctx, page) {
  const ed = await editor(page);
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], {
    origin: new URL(page.url()).origin,
  });
  await page.evaluate((t) => navigator.clipboard.writeText(t), IBAN_TEXT);
  await ed.click();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+v" : "Control+v");
  await expectIntercepted(page, ed);
}

/** Regression for ROADMAP.md §1.2 item 4 — see file header. */
async function checkBodyIdClobber(ctx, page) {
  await page.evaluate(() => {
    document.body.id = "promptwarden-guardrail";
  });
  const ed = await editor(page);
  await ed.click();
  await page.keyboard.type(CARD_TEXT, { delay: 10 });
  await clickSend(page);
  await expectIntercepted(page, ed);
}

const CHECKS = [
  { label: "enter-submit (iban)", run: checkEnterSubmit },
  { label: "click-to-send (credit_card)", run: checkClickToSend },
  { label: "paste (iban)", run: checkPaste },
  { label: "click-to-send after document.body.id clobber (credit_card)", run: checkBodyIdClobber },
];

async function runChecks(ctx, page) {
  for (const check of CHECKS) {
    try {
      await check.run(ctx, page);
    } catch (e) {
      e.message = `${check.label}: ${e.message}`;
      throw e;
    }
    console.log(`  PASS ${check.label}`);
    // Fresh page for the next check rather than dismissing the current
    // dialog: see file header for why this suite can't locate a button
    // inside it. This also re-injects the content script, so it exercises
    // the real cold-load path each time rather than reusing warmed-up state.
    await reload(page);
  }
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
    await page.waitForTimeout(RELOAD_SETTLE_MS);
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
