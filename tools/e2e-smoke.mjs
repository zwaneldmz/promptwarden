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
 *   5. a policy pushed into chrome.storage.local (via the extension's own
 *      background service-worker context, not the page) takes effect in the
 *      still-open tab with no reload — regression for ROADMAP.md §1.5 item
 *      19. Uses the paste path for both halves so the deliberately
 *      unintercepted "before" half never actually submits anything to the
 *      live site. See checkLocalPolicyLiveUpdate() and content.ts.
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
// default-policy.ts ships `email: allow`, so this is deliberately something
// the fallback/standalone policy lets through untouched — see
// checkLocalPolicyLiveUpdate() below.
const EMAIL_TEXT = "please reach out to jane.doe@example.com about the renewal";
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

/**
 * Regression for ROADMAP.md §1.5 item 19: content.ts used to fetch the
 * policy once at document_start and never again, so a corrected or
 * tightened push needed a browser restart to reach a tab already open.
 *
 * Uses the paste path, not a real submit, for both halves of the assertion:
 * an unintercepted paste is inert (the text lands in the local textarea and
 * goes nowhere), whereas an unintercepted Enter/click would actually submit
 * the message to a live chat site. That would make this check's "before"
 * half — which is *supposed* to go unintercepted — send a real message,
 * which is not an acceptable side effect of a smoke test.
 *
 * The policy push itself goes through the extension's own background
 * service-worker context (Playwright's `context.serviceWorkers()`), an
 * extension context with its own `chrome.storage` access — not the page's
 * main world, and not a reach into the guardrail's dialog. It does not
 * touch, weaken, or need to pierce the closed shadow root this suite
 * deliberately leaves alone; see the file header.
 *
 * Run last in CHECKS: it leaves a policy behind in this profile's
 * chrome.storage.local for the rest of the run, which would change what
 * later checks should expect.
 */
async function checkLocalPolicyLiveUpdate(ctx, page) {
  const ed = await editor(page);
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], {
    origin: new URL(page.url()).origin,
  });

  // Baseline: default-policy.ts ships `email: allow`, so a lone email
  // pasted in should not intercept yet.
  await page.evaluate((t) => navigator.clipboard.writeText(t), EMAIL_TEXT);
  await ed.click();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+v" : "Control+v");
  await page.waitForTimeout(800); // confirming absence, not presence — no need for expectIntercepted's poll
  if (await guardrailShowing(page)) {
    throw new Error("guardrail fired before the policy push — baseline assumption is wrong");
  }

  let sw = ctx.serviceWorkers()[0];
  if (!sw) {
    sw = await ctx.waitForEvent("serviceworker", { timeout: 5000 }).catch(() => null);
  }
  if (!sw) throw new Error("no background service worker found to push a policy through");

  const host = new URL(page.url()).hostname;
  await sw.evaluate(
    (h) =>
      chrome.storage.local.set({
        policy: {
          version: 1,
          name: "smoke-live-update",
          hosts: [h],
          defaultAction: "allow",
          logging: "off",
          rules: [{ detector: "email", action: "warn" }],
        },
      }),
    host,
  );

  // No reload: paste the same text into the still-open tab and confirm the
  // now-updated policy intercepts it.
  //
  // Retried rather than pasted once, because the content script picks the new
  // policy up asynchronously — storage.onChanged fires, then a get-policy
  // round trip through the service worker resolves and parses it. A single
  // paste can win that race, and a paste that isn't intercepted is simply
  // allowed: it inserts its text and is over, so polling after the fact can
  // never see a guardrail that was never going to appear. Each attempt clears
  // the box first so an un-intercepted paste can't accumulate.
  const deadline = Date.now() + 10_000;
  for (;;) {
    await ed.click();
    await page.keyboard.press(process.platform === "darwin" ? "Meta+a" : "Control+a");
    await page.keyboard.press("Backspace");
    await page.evaluate((t) => navigator.clipboard.writeText(t), EMAIL_TEXT);
    await page.keyboard.press(process.platform === "darwin" ? "Meta+v" : "Control+v");
    await page.waitForTimeout(400);
    if (await guardrailShowing(page)) return;
    if (Date.now() > deadline) {
      throw new Error(
        "policy pushed to chrome.storage.local never reached the open tab (no guardrail after 10s of retried pastes)",
      );
    }
  }
}

const CHECKS = [
  { label: "enter-submit (iban)", run: checkEnterSubmit },
  { label: "click-to-send (credit_card)", run: checkClickToSend },
  { label: "paste (iban)", run: checkPaste },
  { label: "click-to-send after document.body.id clobber (credit_card)", run: checkBodyIdClobber },
  { label: "local-policy push takes effect without reload (email)", run: checkLocalPolicyLiveUpdate },
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
