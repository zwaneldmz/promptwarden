/**
 * Shared policy-editor UI module — vanilla JS, no framework, DOM-only.
 *
 * Mounted by two hosts:
 *  - apps/extension/options.js (real chrome.storage.local/managed, wrapped
 *    in an adapter passed in as `opts`)
 *  - apps/playground/playground-entry.js (a localStorage/in-memory stand-in
 *    adapter, no chrome.* APIs, no network)
 *
 * This module itself never touches chrome.* or the network — every
 * environment difference is injected via `opts` (loadManaged/loadLocal/
 * saveLocal), which is what "reuse the same UI module rather than forking
 * it" means in practice. It runs the real policy engine (opts.engine:
 * parsePolicy/evaluate, plus DEFAULT_LABELS for the known-detector list) —
 * never a reimplementation of detection logic.
 *
 * Rendering never uses innerHTML with interpolated data: the only innerHTML
 * assignment is the static skeleton template below (authored here, zero
 * interpolation); every value derived from a policy document, an imported
 * file, or engine output is written through textContent/.value, so nothing
 * user- or admin-supplied can ever be interpreted as markup.
 */

const KNOWN_ACTIONS = ["allow", "observe", "warn", "redact", "block"];
const KNOWN_LOGGING = ["off", "event", "content"];
const CUSTOM_DETECTOR_MARKER = "__custom__";

// Mirrors apps/extension/src/default-policy.ts's "standalone-default"
// profile. Duplicated as a literal here (rather than imported) because
// apps/playground/** must not depend on apps/extension/src files owned by a
// different part of the codebase — this is the one deliberate, documented
// copy, used only as a starting point when nothing has been saved yet.
const DEFAULT_TEMPLATE = {
  version: 1,
  name: "standalone-default",
  hosts: [
    "chatgpt.com",
    "chat.openai.com",
    "claude.ai",
    "gemini.google.com",
    "copilot.microsoft.com",
    "chat.mistral.ai",
    "www.perplexity.ai",
  ],
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
};

const FALLBACK_DETECTOR_IDS = [
  "credit_card",
  "iban",
  "email",
  "phone",
  "api_key",
  "at_svnr",
  "private_key",
  "jwt",
  "connection_string",
  "bulk_pii",
];

const STYLE_ID = "pw-editor-style";

const STYLE = `
.pw-editor{display:grid;grid-template-columns:1fr 1fr;grid-template-areas:"banner banner" "note note" "form preview";
  gap:20px;max-width:1200px;margin:0 auto;padding:24px;box-sizing:border-box;}
.pw-editor *{box-sizing:border-box;}
.pw-editor h2{font-size:13px;text-transform:uppercase;letter-spacing:.4px;color:#7f8a95;margin:0 0 10px;font-weight:600;}
.pw-editor h3{font-size:12px;text-transform:uppercase;letter-spacing:.3px;color:#7f8a95;margin:16px 0 6px;font-weight:600;}
.pw-card{background:#171d24;border:1px solid #1d242c;border-radius:8px;padding:16px;margin-bottom:16px;}
.pw-editor label{display:block;margin-bottom:12px;font-size:12px;color:#9aa5b1;}
.pw-editor input[type=text],.pw-editor input[type=number],.pw-editor select,.pw-editor textarea{
  display:block;width:100%;margin-top:4px;padding:7px 9px;background:#101418;border:1px solid #2a323b;
  border-radius:5px;color:#e8edf2;font:13px/1.4 system-ui,sans-serif;}
.pw-editor textarea{resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;}
.pw-editor input:focus,.pw-editor select:focus,.pw-editor textarea:focus{outline:2px solid #3f8cff;outline-offset:1px;}
.pw-hint-inline{color:#5c6672;font-weight:400;text-transform:none;letter-spacing:0;margin-left:4px;}
.pw-hint{color:#7f8a95;font-size:11px;margin:4px 0 10px;}
.pw-warning{background:#2a2416;border:1px solid #4a3f22;color:#d7bd7f;padding:8px 10px;border-radius:6px;font-size:12px;margin:-4px 0 12px;}
.pw-error{background:#3a1a1a;border:1px solid #5a2727;color:#ff8a8a;padding:8px 10px;border-radius:6px;font-size:12px;margin:8px 0;white-space:pre-wrap;}
.pw-success{background:#14301c;border:1px solid #275a33;color:#7fd79a;padding:8px 10px;border-radius:6px;font-size:12px;margin:8px 0;}
.pw-note{grid-area:note;background:#14232f;border:1px solid #244258;color:#9fd0ff;padding:10px 12px;border-radius:6px;font-size:12px;}
.pw-banner-managed{grid-area:banner;background:#2a2416;border:1px solid #4a3f22;border-radius:8px;padding:14px 16px;}
.pw-banner-managed strong{color:#d7bd7f;font-size:13px;}
.pw-banner-managed p{color:#c9b783;font-size:12px;margin:6px 0 0;}
.pw-table-wrap{overflow-x:auto;}
.pw-rules-table{width:100%;border-collapse:collapse;font-size:12px;}
.pw-rules-table th{text-align:left;color:#7f8a95;font-weight:600;padding:4px 6px;border-bottom:1px solid #1d242c;white-space:nowrap;}
.pw-rules-table td{padding:4px 6px;vertical-align:top;}
.pw-rules-table input,.pw-rules-table select{margin-top:0;min-width:110px;}
.pw-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;align-items:center;}
.pw-editor button{padding:7px 14px;border-radius:5px;border:1px solid #2a323b;background:#171d24;color:#e8edf2;
  font:inherit;font-size:12px;cursor:pointer;}
.pw-editor button:hover:not(:disabled){background:#1d242c;}
.pw-editor button:disabled,.pw-editor input:disabled,.pw-editor select:disabled,.pw-editor textarea:disabled{opacity:.5;cursor:not-allowed;}
.pw-editor button.pw-primary{background:#3f8cff;border-color:#3f8cff;color:#0b1520;font-weight:600;}
.pw-editor button.pw-primary:hover:not(:disabled){background:#5b9cff;}
.pw-file-label{display:inline-flex;align-items:center;padding:7px 14px;border-radius:5px;border:1px solid #2a323b;
  background:#171d24;color:#e8edf2;font-size:12px;cursor:pointer;margin:0;}
.pw-file-label input{display:none;}
.pw-managed-string{margin-top:10px;width:100%;min-height:60px;font-family:ui-monospace,monospace;font-size:11px;}
.pw-status{color:#9fd0ff;font-size:12px;margin:8px 0;}
.pw-findings{list-style:none;margin:0;padding:0;max-height:220px;overflow-y:auto;}
.pw-findings li{display:flex;gap:8px;align-items:baseline;padding:5px 0;border-top:1px solid #1d242c;font-size:12px;flex-wrap:wrap;}
.pw-findings li:first-child{border-top:0;}
.pw-findings li.pw-empty{color:#7f8a95;font-style:italic;}
.pw-tag{text-transform:uppercase;font-size:10px;letter-spacing:.3px;padding:1px 5px;border-radius:3px;background:#1d242c;color:#9aa5b1;}
.pw-tag-block{background:#3a1a1a;color:#ff8a8a;}
.pw-tag-warn{background:#2a2416;color:#d7bd7f;}
.pw-tag-redact{background:#142430;color:#9fd0ff;}
.pw-detector{color:#7f8a95;}
.pw-match{color:#e8edf2;background:#101418;border:1px solid #1d242c;border-radius:3px;padding:0 4px;overflow-wrap:anywhere;}
.pw-redacted{white-space:pre-wrap;word-break:break-word;background:#101418;border:1px solid #1d242c;border-radius:6px;padding:10px;
  font-family:ui-monospace,monospace;font-size:12px;max-height:200px;overflow-y:auto;}
.pw-form{grid-area:form;}
.pw-preview{grid-area:preview;}
@media (max-width:880px){.pw-editor{grid-template-columns:1fr;grid-template-areas:"banner" "note" "form" "preview";}}
`;

const SKELETON = `
<div class="pw-editor">
  <div class="pw-banner-managed" data-ref="managedBanner" hidden>
    <strong>Managed by your organization</strong>
    <p>This policy is pushed by your organization's admin console and applies fleet-wide. Local edits on this device are ignored while a managed policy is present — settings below are shown for reference only.</p>
    <div class="pw-error" data-ref="managedError" hidden></div>
  </div>

  <p class="pw-note" data-ref="envNote" hidden></p>

  <form class="pw-form" data-ref="form" novalidate>
    <section class="pw-card">
      <h2>Policy</h2>
      <label>Name
        <input data-ref="name" type="text" placeholder="e.g. Standalone default">
      </label>
      <label>Hosts <span class="pw-hint-inline">one per line, e.g. claude.ai or *.example.com</span>
        <textarea data-ref="hosts" rows="4" placeholder="claude.ai"></textarea>
      </label>
      <label>Logging mode
        <select data-ref="logging">
          <option value="off">off — nothing recorded</option>
          <option value="event">event — category + host + timestamp</option>
          <option value="content">content — full matched text</option>
        </select>
      </label>
      <p class="pw-warning" data-ref="loggingWarning" hidden>⚠ Content logging stores the exact matched text (card numbers, IBANs, emails, etc.) on this device. Enable only with a documented basis for retaining it.</p>
      <label>Default action <span class="pw-hint-inline">applied to any detector with no explicit rule below</span>
        <select data-ref="defaultAction">
          <option value="allow">allow</option>
          <option value="observe">observe</option>
          <option value="warn">warn</option>
          <option value="redact">redact</option>
          <option value="block">block</option>
        </select>
      </label>
      <label>On scan error <span class="pw-hint-inline">what an unreadable/unscannable file does</span>
        <select data-ref="onError">
          <option value="">(default: open)</option>
          <option value="open">open — release unscanned</option>
          <option value="closed">closed — block it</option>
        </select>
      </label>
      <label>Retention (days) <span class="pw-hint-inline">default 90, max 365</span>
        <input data-ref="retentionDays" type="number" min="1" max="365" placeholder="90">
      </label>
      <label>Bulk-PII threshold <span class="pw-hint-inline">default 5</span>
        <input data-ref="bulkPiiThreshold" type="number" min="1" placeholder="5">
      </label>
    </section>

    <section class="pw-card">
      <h2>Rules</h2>
      <div class="pw-table-wrap">
        <table class="pw-rules-table">
          <thead><tr><th>Detector</th><th>Action</th><th>Pattern <span class="pw-hint-inline">(custom ids only)</span></th><th>Label</th><th></th></tr></thead>
          <tbody data-ref="rulesBody"></tbody>
        </table>
      </div>
      <button type="button" data-ref="addRule">Add rule</button>
    </section>

    <div class="pw-error" data-ref="saveError" hidden></div>
    <div class="pw-success" data-ref="saveSuccess" hidden></div>

    <div class="pw-actions">
      <button type="submit" class="pw-primary" data-ref="save">Save policy</button>
      <button type="button" data-ref="export">Export JSON</button>
      <label class="pw-file-label">Import JSON
        <input type="file" accept="application/json" data-ref="import">
      </label>
      <button type="button" data-ref="copyManaged">Copy for managed storage</button>
    </div>
    <textarea class="pw-managed-string" data-ref="managedString" readonly hidden></textarea>
  </form>

  <section class="pw-card pw-preview">
    <h2>Live preview</h2>
    <p class="pw-hint">Runs the real detection engine locally, on this device, as you type. Nothing typed here is saved or sent anywhere.</p>
    <textarea data-ref="sampleInput" rows="8" placeholder="Paste sample text to see what this policy would catch…"></textarea>
    <p class="pw-status" data-ref="previewStatus"></p>
    <h3>Findings</h3>
    <ul class="pw-findings" data-ref="previewFindings"></ul>
    <h3>Redacted output</h3>
    <pre class="pw-redacted" data-ref="previewRedacted"></pre>
  </section>
</div>`;

function injectStylesOnce(doc) {
  if (doc.getElementById(STYLE_ID)) return;
  const style = doc.createElement("style");
  style.id = STYLE_ID;
  style.textContent = STYLE;
  doc.head.appendChild(style);
}

function buildSkeleton(root) {
  root.innerHTML = SKELETON; // static template, zero interpolation — see file header
  const refs = {};
  for (const el of root.querySelectorAll("[data-ref]")) {
    refs[el.getAttribute("data-ref")] = el;
  }
  refs.root = root;
  return refs;
}

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

function parseHosts(text) {
  return text
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

function errorMessage(e) {
  return e instanceof Error ? e.message : String(e);
}

/* --------------------------------- rules table --------------------------------- */

function addRuleRow(refs, rule) {
  const tr = document.createElement("tr");

  const tdDetector = document.createElement("td");
  const select = document.createElement("select");
  select.className = "rule-detector";
  for (const id of refs.knownDetectorIds) {
    const opt = document.createElement("option");
    opt.value = id;
    opt.textContent = id;
    select.appendChild(opt);
  }
  const customOpt = document.createElement("option");
  customOpt.value = CUSTOM_DETECTOR_MARKER;
  customOpt.textContent = "(custom id)…";
  select.appendChild(customOpt);

  const isKnown = refs.knownDetectorIds.includes(rule.detector);
  select.value = isKnown ? rule.detector : CUSTOM_DETECTOR_MARKER;
  tdDetector.appendChild(select);

  const customInput = document.createElement("input");
  customInput.type = "text";
  customInput.className = "rule-detector-custom";
  customInput.placeholder = "custom detector id";
  customInput.value = isKnown ? "" : rule.detector || "";
  customInput.hidden = isKnown;
  customInput.style.marginTop = "4px";
  tdDetector.appendChild(customInput);
  select.addEventListener("change", () => {
    customInput.hidden = select.value !== CUSTOM_DETECTOR_MARKER;
  });

  const tdAction = document.createElement("td");
  const actionSelect = document.createElement("select");
  actionSelect.className = "rule-action";
  for (const a of KNOWN_ACTIONS) {
    const opt = document.createElement("option");
    opt.value = a;
    opt.textContent = a;
    actionSelect.appendChild(opt);
  }
  actionSelect.value = KNOWN_ACTIONS.includes(rule.action) ? rule.action : "warn";
  tdAction.appendChild(actionSelect);

  const tdPattern = document.createElement("td");
  const patternInput = document.createElement("input");
  patternInput.type = "text";
  patternInput.className = "rule-pattern";
  patternInput.placeholder = "regex (custom ids only)";
  patternInput.value = typeof rule.pattern === "string" ? rule.pattern : "";
  tdPattern.appendChild(patternInput);

  const tdLabel = document.createElement("td");
  const labelInput = document.createElement("input");
  labelInput.type = "text";
  labelInput.className = "rule-label";
  labelInput.placeholder = "[REDACTED:…]";
  labelInput.value = typeof rule.label === "string" ? rule.label : "";
  tdLabel.appendChild(labelInput);

  const tdRemove = document.createElement("td");
  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.textContent = "Remove";
  removeBtn.addEventListener("click", () => {
    tr.remove();
    refs.onRulesChanged?.();
  });
  tdRemove.appendChild(removeBtn);

  tr.append(tdDetector, tdAction, tdPattern, tdLabel, tdRemove);
  refs.rulesBody.appendChild(tr);
}

function readRulesRows(refs) {
  const rows = [...refs.rulesBody.querySelectorAll("tr")];
  return rows
    .map((row) => {
      const detectorSelect = row.querySelector(".rule-detector");
      const customInput = row.querySelector(".rule-detector-custom");
      const detector =
        detectorSelect.value === CUSTOM_DETECTOR_MARKER ? customInput.value.trim() : detectorSelect.value;
      const action = row.querySelector(".rule-action").value;
      const pattern = row.querySelector(".rule-pattern").value.trim();
      const label = row.querySelector(".rule-label").value.trim();
      const rule = { detector, action };
      if (pattern) rule.pattern = pattern;
      if (label) rule.label = label;
      return rule;
    })
    .filter((r) => r.detector.length > 0);
}

/* --------------------------------- form <-> policy --------------------------------- */

function readForm(refs) {
  const base = refs.loadedPolicyBase && typeof refs.loadedPolicyBase === "object" ? refs.loadedPolicyBase : {};
  const merged = {
    ...base, // preserves any field this editor has no control for (e.g. a
    // future `exceptions` array) across an edit/save cycle instead of
    // silently dropping it
    version: 1,
    name: refs.name.value.trim(),
    hosts: parseHosts(refs.hosts.value),
    logging: refs.logging.value,
    defaultAction: refs.defaultAction.value,
    rules: readRulesRows(refs),
  };
  const onErrorVal = refs.onError.value;
  if (onErrorVal) merged.onError = onErrorVal;
  else delete merged.onError;

  const retentionVal = refs.retentionDays.value.trim();
  if (retentionVal) merged.retentionDays = Number(retentionVal);
  else delete merged.retentionDays;

  const thresholdVal = refs.bulkPiiThreshold.value.trim();
  if (thresholdVal) merged.bulkPiiThreshold = Number(thresholdVal);
  else delete merged.bulkPiiThreshold;

  return merged;
}

function applyPolicyToForm(refs, policy) {
  const p = policy && typeof policy === "object" ? policy : {};
  refs.loadedPolicyBase = p;

  refs.name.value = typeof p.name === "string" ? p.name : "";
  refs.hosts.value = Array.isArray(p.hosts) ? p.hosts.filter((h) => typeof h === "string").join("\n") : "";
  refs.logging.value = KNOWN_LOGGING.includes(p.logging) ? p.logging : "event";
  refs.defaultAction.value = KNOWN_ACTIONS.includes(p.defaultAction) ? p.defaultAction : "allow";
  refs.onError.value = p.onError === "open" || p.onError === "closed" ? p.onError : "";
  refs.retentionDays.value = typeof p.retentionDays === "number" ? String(p.retentionDays) : "";
  refs.bulkPiiThreshold.value = typeof p.bulkPiiThreshold === "number" ? String(p.bulkPiiThreshold) : "";

  refs.rulesBody.innerHTML = "";
  const rules = Array.isArray(p.rules) ? p.rules : [];
  if (rules.length === 0) {
    addRuleRow(refs, { detector: refs.knownDetectorIds[0], action: "warn" });
  } else {
    for (const r of rules) {
      if (r && typeof r === "object" && typeof r.detector === "string") addRuleRow(refs, r);
    }
  }
  updateLoggingWarning(refs);
}

function setFormDisabled(refs, disabled) {
  for (const el of refs.form.querySelectorAll("input, select, textarea, button")) {
    el.disabled = disabled;
  }
}

function updateLoggingWarning(refs) {
  refs.loggingWarning.hidden = refs.logging.value !== "content";
}

/* --------------------------------- managed banner --------------------------------- */

async function initManagedBanner(refs, engine, loadManaged) {
  let raw = null;
  try {
    raw = await loadManaged();
  } catch {
    raw = null;
  }
  if (typeof raw !== "string" || raw.length === 0) {
    refs.managedBanner.hidden = true;
    return false;
  }

  refs.managedBanner.hidden = false;
  let obj = null;
  let errMsg = null;
  try {
    obj = JSON.parse(raw);
  } catch (e) {
    errMsg = "Not valid JSON: " + errorMessage(e);
  }
  if (!errMsg) {
    try {
      obj = engine.parsePolicy(obj);
    } catch (e) {
      errMsg = errorMessage(e);
    }
  }
  if (errMsg) {
    refs.managedError.textContent =
      "Your organization's policy failed validation (" +
      errMsg +
      "). The extension falls back to its built-in default until this is fixed — contact IT.";
    refs.managedError.hidden = false;
  } else {
    refs.managedError.hidden = true;
  }
  applyPolicyToForm(refs, obj ?? {});
  setFormDisabled(refs, true);
  return true;
}

/* --------------------------------- live preview --------------------------------- */

function runPreview(refs, engine) {
  let parsed;
  try {
    parsed = engine.parsePolicy(readForm(refs));
  } catch (e) {
    refs.previewStatus.textContent = "Fix the policy errors below to preview (" + errorMessage(e) + ").";
    refs.previewFindings.innerHTML = "";
    refs.previewRedacted.textContent = "";
    return;
  }

  const text = refs.sampleInput.value;
  if (!text) {
    refs.previewStatus.textContent = "Paste sample text above to see what this policy would catch.";
    refs.previewFindings.innerHTML = "";
    refs.previewRedacted.textContent = "";
    return;
  }

  const result = engine.evaluate(text, parsed);
  refs.previewStatus.textContent = result.blocked
    ? "This would be BLOCKED."
    : result.needsWarning
      ? "This would show a warning to the user."
      : "This would pass without interruption.";

  refs.previewFindings.innerHTML = "";
  if (result.findings.length === 0) {
    const li = document.createElement("li");
    li.className = "pw-empty";
    li.textContent = "No findings.";
    refs.previewFindings.appendChild(li);
  } else {
    for (const f of result.findings) {
      const li = document.createElement("li");
      const tag = document.createElement("span");
      tag.className = "pw-tag pw-tag-" + f.action;
      tag.textContent = f.action;
      const det = document.createElement("span");
      det.className = "pw-detector";
      det.textContent = f.detector;
      const match = document.createElement("code");
      match.className = "pw-match";
      match.textContent = f.match;
      li.append(tag, det, match);
      refs.previewFindings.appendChild(li);
    }
  }
  refs.previewRedacted.textContent = result.redactedText;
}

/* --------------------------------- actions --------------------------------- */

async function onSave(refs, engine, saveLocal) {
  refs.saveError.hidden = true;
  refs.saveSuccess.hidden = true;
  let parsed;
  try {
    parsed = engine.parsePolicy(readForm(refs));
  } catch (e) {
    // Shown verbatim — these messages (e.g. the bare "*" host rejection) are
    // written to be read as-is, not wrapped or reworded.
    refs.saveError.textContent = errorMessage(e);
    refs.saveError.hidden = false;
    return;
  }
  try {
    if (saveLocal) await saveLocal(parsed);
    refs.saveSuccess.textContent = "Saved.";
    refs.saveSuccess.hidden = false;
  } catch (e) {
    refs.saveError.textContent = "Save failed: " + errorMessage(e);
    refs.saveError.hidden = false;
  }
}

function onExport(refs) {
  const draft = readForm(refs);
  const blob = new Blob([JSON.stringify(draft, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "promptwarden-policy.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function onImport(refs, engine, event) {
  const file = event.target.files && event.target.files[0];
  event.target.value = "";
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    let obj;
    try {
      obj = JSON.parse(String(reader.result));
    } catch (e) {
      refs.saveError.textContent = "Could not parse file: " + errorMessage(e);
      refs.saveError.hidden = false;
      return;
    }
    let errMsg = null;
    try {
      engine.parsePolicy(obj);
    } catch (e) {
      errMsg = errorMessage(e);
    }
    applyPolicyToForm(refs, obj);
    runPreview(refs, engine);
    if (errMsg) {
      refs.saveError.textContent = errMsg;
      refs.saveError.hidden = false;
    } else {
      refs.saveError.hidden = true;
    }
  };
  reader.readAsText(file);
}

async function onCopyManaged(refs, engine) {
  let parsed;
  try {
    parsed = engine.parsePolicy(readForm(refs));
  } catch (e) {
    refs.saveError.textContent = errorMessage(e);
    refs.saveError.hidden = false;
    return;
  }
  refs.saveError.hidden = true;
  const str = JSON.stringify(parsed);
  refs.managedString.hidden = false;
  refs.managedString.value = str;
  refs.managedString.select();
  try {
    await navigator.clipboard.writeText(str);
    refs.saveSuccess.textContent = 'Copied to clipboard — paste it as the managed policy\'s "policy" value.';
    refs.saveSuccess.hidden = false;
  } catch {
    refs.saveSuccess.textContent = "Clipboard copy blocked — the string is selected below; copy it manually.";
    refs.saveSuccess.hidden = false;
  }
}

/* --------------------------------- mount --------------------------------- */

function wireEvents(refs, engine, saveLocal) {
  const schedulePreview = debounce(() => runPreview(refs, engine), 250);
  refs.onRulesChanged = schedulePreview;

  refs.sampleInput.addEventListener("input", schedulePreview);
  refs.form.addEventListener("input", schedulePreview);
  refs.form.addEventListener("change", schedulePreview);
  refs.logging.addEventListener("change", () => updateLoggingWarning(refs));

  refs.addRule.addEventListener("click", () => {
    addRuleRow(refs, { detector: refs.knownDetectorIds[0], action: "warn" });
    schedulePreview();
  });

  refs.form.addEventListener("submit", (e) => {
    e.preventDefault();
    onSave(refs, engine, saveLocal);
  });

  refs.export.addEventListener("click", () => onExport(refs));
  refs.import.addEventListener("change", (e) => onImport(refs, engine, e));
  refs.copyManaged.addEventListener("click", () => onCopyManaged(refs, engine));
}

/**
 * Mount the policy editor into `root`.
 *
 * `opts.engine` must expose `parsePolicy` and `evaluate` (the real
 * @promptwarden/policy-engine exports — `DEFAULT_LABELS` is used too, when
 * present, to populate the rules table's known-detector dropdown so it
 * tracks the engine's actual registry instead of a hand-maintained copy).
 *
 * `opts.loadManaged()` returns the raw managed-policy JSON *string* (or
 * null/undefined) — never a parsed object, matching how Chrome's managed
 * storage actually stores it (see managed_schema.json). `opts.loadLocal()`
 * returns a parsed policy object or null. `opts.saveLocal(policy)` persists
 * an already-`parsePolicy`-validated policy object.
 */
export async function mountPolicyEditor(root, opts) {
  const { engine, loadManaged, loadLocal, saveLocal, environmentNote } = opts || {};
  if (!engine || typeof engine.parsePolicy !== "function" || typeof engine.evaluate !== "function") {
    throw new Error("mountPolicyEditor: opts.engine must expose parsePolicy and evaluate");
  }

  injectStylesOnce(root.ownerDocument || document);
  const refs = buildSkeleton(root);
  const known = Object.keys(engine.DEFAULT_LABELS || {});
  refs.knownDetectorIds = known.length > 0 ? known : FALLBACK_DETECTOR_IDS;

  if (environmentNote) {
    refs.envNote.textContent = environmentNote;
    refs.envNote.hidden = false;
  }

  wireEvents(refs, engine, saveLocal);

  const isManaged = await initManagedBanner(refs, engine, loadManaged || (async () => null));
  if (!isManaged) {
    let local = null;
    try {
      local = loadLocal ? await loadLocal() : null;
    } catch {
      local = null;
    }
    applyPolicyToForm(refs, local ?? DEFAULT_TEMPLATE);
    setFormDisabled(refs, false);
  }

  runPreview(refs, engine);
}
