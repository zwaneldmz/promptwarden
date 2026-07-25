/**
 * Live-browser smoke regression for the extension's interception paths.
 *
 * Loads the unpacked extension into a local Chromium-family browser and
 * verifies on a real policy-matched site that the guardrail fires for:
 *   1. Enter-submit  (keydown path)
 *   2. click-to-send (focusin-tracked fallback — regression for the
 *      "activeEditable(null) misses when focus moved to the button" hole)
 *   3. paste         (paste path)
 *
 * Not covered here: the <form> submit path (no supported host uses a plain
 * form submit; verified manually against a local page) and the
 * bypass-expiry timer (needs a real send; verified manually).
 *
 * Usage: node tools/e2e-smoke.mjs
 *   PW_BROWSER=/path/to/chrome overrides the browser binary.
 * Requires a headed environment; not wired into CI.
 */
import { chromium } from "playwright-core";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const EXT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "apps", "extension");
const BROWSER =
  process.env.PW_BROWSER ?? "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";
const SITE = "https://chatgpt.com/";
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
  console.log(`PASS ${label}: ${text.split("\n")[0]} | ${text.split("\n")[1] ?? ""}`);
  await page.locator(`${GUARDRAIL} button`, { hasText: /Cancel|Close/ }).click();
  await page.locator(GUARDRAIL).waitFor({ state: "hidden", timeout: 2000 });
}

async function clearEditor(page, ed) {
  await ed.click();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+a" : "Control+a");
  await page.keyboard.press("Backspace");
}

const profile = path.join(os.tmpdir(), `pw-smoke-${process.pid}`);
const ctx = await chromium.launchPersistentContext(profile, {
  executablePath: BROWSER,
  headless: false,
  viewport: { width: 1280, height: 860 },
  args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`],
});

try {
  const page = ctx.pages()[0] ?? (await ctx.newPage());
  await page.goto(SITE, { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.waitForTimeout(3500);
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
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: SITE });
  await page.evaluate((t) => navigator.clipboard.writeText(t), IBAN_TEXT);
  await ed.click();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+v" : "Control+v");
  await expectGuardrail(page, "paste (iban)");

  console.log("ALL PASS");
} finally {
  await ctx.close();
}
