(async () => {
  // GitHub repo the "Problem melden" link opens issues against.
  const ISSUE_REPO_URL = "https://github.com/zwaneldmz/promptwarden";

  const ACTION_PRIORITY = { block: 3, redact: 2, warn: 1 };

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
    ));
  }

  function formatTime(ts) {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return "–";
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  // Explicit allowlist: only these fields are ever read off a stored event
  // record. `match` / `matches` (present only under logging: "content") are
  // never touched here, so the popup can never render prompt content.
  //
  // `pairs` (detector, action) is a newer field than `categories`/`actions`
  // — a record written before it landed simply won't have it. Validated the
  // same way as everything else here: non-array/malformed entries are
  // dropped rather than rendered.
  function safeFields(record) {
    const r = record && typeof record === "object" ? record : {};
    const actions = Array.isArray(r.actions) ? r.actions.filter((a) => typeof a === "string") : [];
    const categories = Array.isArray(r.categories) ? r.categories.filter((c) => typeof c === "string") : [];
    const pairs = Array.isArray(r.pairs)
      ? r.pairs
          .filter((p) => p && typeof p === "object" && typeof p.detector === "string" && typeof p.action === "string")
          .map((p) => ({ detector: p.detector, action: p.action }))
      : [];
    return {
      ts: typeof r.ts === "string" ? r.ts : null,
      host: typeof r.host === "string" ? r.host : "–",
      actions,
      categories,
      pairs,
    };
  }

  function primaryAction(actions) {
    let best = null;
    for (const a of actions) {
      if (ACTION_PRIORITY[a] && (!best || ACTION_PRIORITY[a] > ACTION_PRIORITY[best])) best = a;
    }
    return best;
  }

  // "YYYY-MM-DD" for a valid timestamp, otherwise null. Never finer than a
  // calendar day — this is the only granularity the aggregate export uses.
  function dayBucket(ts) {
    if (typeof ts !== "string") return null;
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return null;
    return d.toISOString().slice(0, 10);
  }

  /**
   * Build the aggregate export: day-bucketed counts from this device keyed by
   * host, category, and action, plus the extension version and policy name.
   * Not k-anonymous on its own — cells can be 1. Suppressing small cells
   * requires merging several devices' exports out of band.
   * Built exclusively off `safeFields()` — the same allowlist the popup's
   * own rendering uses — so this can never surface a per-event row, a
   * finer-than-day timestamp, a device identifier, or a content field, even
   * by accident. Each event contributes once per category, under its single
   * highest-severity action (mirrors renderCounts' own primaryAction use).
   */
  function buildAggregate(events, policy) {
    const counts = {};
    for (const ev of events) {
      const { ts, host, actions, categories } = safeFields(ev);
      const day = dayBucket(ts);
      if (!day) continue; // can't bucket without a parseable day — drop, never guess
      const action = primaryAction(actions) ?? (actions[0] || "unknown");
      const cats = categories.length ? categories : ["unknown"];
      counts[day] ??= {};
      counts[day][host] ??= {};
      for (const category of cats) {
        counts[day][host][category] ??= {};
        counts[day][host][category][action] = (counts[day][host][category][action] ?? 0) + 1;
      }
    }
    const hosts = Array.isArray(policy?.hosts)
      ? [...new Set(policy.hosts.filter((h) => typeof h === "string"))].sort()
      : [];
    return {
      extensionVersion: chrome.runtime.getManifest().version,
      policyName: typeof policy?.name === "string" ? policy.name : "standalone-default",
      hosts,
      generatedDay: dayBucket(new Date().toISOString()),
      counts,
    };
  }

  function downloadJson(filename, obj) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // Resolution (managed > local > built-in default, with a malformed managed
  // policy failing to the built-in default rather than to the user-writable
  // local one) lives in background.ts's resolvePolicy — asked here over
  // chrome.runtime.sendMessage rather than duplicated, so the popup can never
  // show a healthier picture than what background.ts actually resolved and
  // acted on (e.g. the badge). A malformed managed policy comes back with
  // `errored: true` and `source: "built-in"` — never null, never a silent
  // "Managed" badge over an empty policy.
  async function loadPolicyInfo() {
    try {
      const resp = await chrome.runtime.sendMessage({ type: "get-policy" });
      return {
        policy: resp && typeof resp === "object" && resp.policy ? resp.policy : null,
        source: resp && typeof resp.source === "string" ? resp.source : "built-in",
        errored: !!(resp && resp.errored),
      };
    } catch {
      // Background service worker unreachable — never silently render a
      // healthy state over an unknown one.
      return { policy: null, source: "built-in", errored: true };
    }
  }

  async function loadEvents() {
    const local = await chrome.storage.local.get(["pw-events"]);
    return Array.isArray(local["pw-events"]) ? local["pw-events"] : [];
  }

  async function loadDiagnostics() {
    const local = await chrome.storage.local.get(["pw-diagnostics"]);
    return Array.isArray(local["pw-diagnostics"]) ? local["pw-diagnostics"] : [];
  }

  // Mirrors apps/extension/src/background.ts's isValidHttpsMatchPattern.
  // popup.js is loaded directly by popup.html (unbundled — see
  // package.json's build:extension, which only bundles content.ts and
  // background.ts), so there's no shared module to import this from without
  // adding a build step. Keep the two in sync by hand if the grammar ever
  // changes.
  function isValidHttpsMatchPattern(pattern) {
    if (typeof pattern !== "string") return false;
    const m = /^https:\/\/([^/]+)(\/.*)$/.exec(pattern);
    if (!m) return false;
    const host = m[1];
    if (host.length === 0) return false;
    if (host === "*") return false; // bare wildcard rejected — mirror background.ts
    if (host.startsWith("*.")) {
      const rest = host.slice(2);
      return rest.length > 0 && !rest.includes("*");
    }
    return !host.includes("*");
  }

  // Declared extraHosts, filtered to well-formed https patterns. Reads
  // managed storage directly (not via background.ts) because this only
  // needs to know what to *ask permission for* / *check permission
  // against* — it never registers anything itself.
  async function loadExtraHosts() {
    try {
      const managed = await chrome.storage.managed.get(["extraHosts"]);
      const raw = managed.extraHosts;
      if (!Array.isArray(raw)) return [];
      return raw.filter(isValidHttpsMatchPattern);
    } catch {
      return []; // managed storage unavailable outside enterprise deployments
    }
  }

  /**
   * Show the "extended coverage" notice + button only when the admin has
   * declared extraHosts AND the permission grant for them is missing.
   * Nothing renders for the common standalone case (no managed extraHosts
   * at all) or once the grant already covers every declared host.
   */
  async function refreshExtraHostsNotice() {
    const notice = document.getElementById("extra-hosts-notice");
    const extraHosts = await loadExtraHosts();
    if (extraHosts.length === 0) {
      notice.hidden = true;
      return;
    }
    let granted = false;
    try {
      granted = await chrome.permissions.contains({ permissions: ["scripting"], origins: extraHosts });
    } catch {
      granted = false;
    }
    notice.hidden = granted;
  }

  // Category-level counts only — kind -> occurrence count. Never the raw
  // diagnostic entries (which carry a `host`), and never anything from
  // pw-events (which can carry per-event categories/actions but is a
  // different buffer entirely and is not touched here).
  function summarizeDiagnostics(diagnostics) {
    const counts = {};
    for (const d of diagnostics) {
      const kind = d && typeof d === "object" && typeof d.kind === "string" ? d.kind : "unknown";
      counts[kind] = (counts[kind] ?? 0) + 1;
    }
    return counts;
  }

  /**
   * Build the prefilled GitHub issue URL for "Problem melden". Query params
   * carry ONLY the extension version and a category-level diagnostics
   * summary (counts per pw-diagnostics `kind`) — never `navigator.userAgent`
   * (it identifies the reporter, not the bug, in a body posted to a PUBLIC
   * issue tracker whose realistic user action is "Submit"), never event
   * data, never hostnames from pw-events or pw-diagnostics. The user still
   * has to review and click "Submit new issue" on GitHub themselves; this
   * only opens the compose form pre-filled. Called lazily from the link's
   * click handler, not on every popup render, so opening the popup never
   * touches `pw-diagnostics` on its own.
   */
  async function buildReportUrl() {
    const diagnostics = await loadDiagnostics();
    const counts = summarizeDiagnostics(diagnostics);
    const version = chrome.runtime.getManifest().version;
    const summaryLines = Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([kind, n]) => `- ${kind}: ${n}`);
    const body = [
      `Extension version: ${version}`,
      "",
      "Diagnostics summary (category counts only, no event data, no hostnames):",
      summaryLines.length > 0 ? summaryLines.join("\n") : "(none recorded)",
    ].join("\n");
    const params = new URLSearchParams({ title: `PromptWarden issue (v${version})`, body });
    return `${ISSUE_REPO_URL}/issues/new?${params.toString()}`;
  }

  // `source` — not the mere presence of a managed-storage string — decides
  // the badge. A managed policy that failed to parse resolves (in
  // background.ts) to `source: "built-in"` and `errored: true`, so this can
  // never again render "Managed by your organization" over an unrelated
  // fallback policy the old presence-only `managed` boolean produced.
  function renderPolicy({ policy, source, errored }) {
    document.getElementById("policy-name").textContent = policy?.name ?? "standalone-default";
    document.getElementById("rule-count").textContent = Array.isArray(policy?.rules) ? policy.rules.length : 0;
    document.getElementById("host-count").textContent = Array.isArray(policy?.hosts) ? policy.hosts.length : 0;
    const badge = document.getElementById("mode");
    badge.classList.remove("unmanaged", "errored");
    if (errored) {
      badge.textContent = "Policy error — contact IT";
      badge.classList.add("errored");
    } else if (source === "managed") {
      badge.textContent = "Managed by your organization";
    } else {
      badge.textContent = "Standalone";
      badge.classList.add("unmanaged");
    }
  }

  function renderCounts(events) {
    const counts = { block: 0, warn: 0, redact: 0 };
    for (const ev of events) {
      const { actions } = safeFields(ev);
      for (const a of new Set(actions)) {
        if (a in counts) counts[a] += 1;
      }
    }
    document.getElementById("count-blocked").textContent = counts.block;
    document.getElementById("count-warned").textContent = counts.warn;
    document.getElementById("count-redacted").textContent = counts.redact;
  }

  function renderList(events, loggingOff) {
    const list = document.getElementById("event-list");
    list.innerHTML = "";
    const recent = events.slice(-20).reverse();
    if (recent.length === 0) {
      const li = document.createElement("li");
      li.className = "empty";
      // With logging "off" (the standalone default) toLogRecord returns null
      // and no event ever reaches storage — say so instead of implying
      // activity is being tracked.
      li.textContent = loggingOff
        ? "Event logging is disabled by this policy. The export button appears once events exist."
        : "No events yet. The export button appears once events exist.";
      list.appendChild(li);
      return;
    }
    for (const ev of recent) {
      const { ts, host, actions, categories, pairs } = safeFields(ev);
      const li = document.createElement("li");
      // `pairs` says which detector had which action — a precise
      // replacement for the old primaryAction-over-every-category guess.
      // Records written before `pairs` existed fall back to the previous
      // rendering so old events don't disappear or misrender.
      const metaHtml =
        pairs.length > 0
          ? pairs
              .map(
                (p) =>
                  `<span class="ev-action ${escapeHtml(p.action)}">${escapeHtml(p.action)}</span>${escapeHtml(p.detector)}`,
              )
              .join(" ")
          : (() => {
              const action = primaryAction(actions) ?? (actions[0] || "event");
              return (
                `<span class="ev-action ${escapeHtml(action)}">${escapeHtml(action)}</span>` +
                `${escapeHtml(categories.join(", ") || "–")}`
              );
            })();
      li.innerHTML =
        `<div class="ev-top"><span class="ev-host">${escapeHtml(host)}</span>` +
        `<span class="ev-time">${escapeHtml(formatTime(ts))}</span></div>` +
        `<div class="ev-meta">${metaHtml}</div>`;
      list.appendChild(li);
    }
  }

  // Per-kind occurrence counts, rendered as plain text nodes — never
  // innerHTML — so a diagnostic `kind` can never be interpreted as markup
  // even though the set is closed-by-construction on both writers
  // (background.ts's BackgroundDiagnosticKind, content.ts's DiagnosticKind).
  function renderDiagnosticCounts(diagnostics) {
    const list = document.getElementById("diag-counts");
    list.innerHTML = "";
    const counts = summarizeDiagnostics(diagnostics);
    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) {
      const li = document.createElement("li");
      li.className = "empty";
      li.textContent = "No diagnostics recorded.";
      list.appendChild(li);
      return;
    }
    for (const [kind, n] of entries) {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = kind;
      const count = document.createElement("span");
      count.className = "val";
      count.textContent = String(n);
      li.append(label, count);
      list.appendChild(li);
    }
  }

  /** Health block: extension version, policy name, resolved source, and
   * per-kind diagnostic counts — enough for a helpdesk call without opening
   * DevTools. */
  function renderDiagnosticsBlock(policyInfo, diagnostics) {
    document.getElementById("diag-version").textContent = chrome.runtime.getManifest().version;
    document.getElementById("diag-policy-name").textContent = policyInfo.policy?.name ?? "standalone-default";
    document.getElementById("diag-source").textContent = policyInfo.source;
    renderDiagnosticCounts(diagnostics);
  }

  /**
   * Self-contained JSON export for helpdesk: extension version, policy name,
   * resolved source (managed/local/built-in), errored state, and per-kind
   * diagnostic counts. No GitHub, no `navigator.userAgent` — this is handed
   * over by ticket, not posted to a public tracker.
   */
  function buildDiagnosticsExport(policyInfo, diagnostics) {
    return {
      extensionVersion: chrome.runtime.getManifest().version,
      policyName: policyInfo.policy?.name ?? "standalone-default",
      policySource: policyInfo.source,
      policyErrored: policyInfo.errored,
      generatedAt: new Date().toISOString(),
      diagnosticCounts: summarizeDiagnostics(diagnostics),
    };
  }

  async function refresh() {
    const [policyInfo, events, diagnostics] = await Promise.all([
      loadPolicyInfo(),
      loadEvents(),
      loadDiagnostics(),
    ]);
    renderPolicy(policyInfo);
    renderCounts(events);
    renderList(events, (policyInfo.policy?.logging ?? "off") === "off");
    renderDiagnosticsBlock(policyInfo, diagnostics);
    // The export button only appears once there is something to export —
    // an empty aggregate isn't worth a download and hides accidentally
    // exporting one-line-of-context-free "nothing" as if it meant something.
    document.getElementById("export-aggregate").hidden = events.length === 0;
  }

  document.getElementById("clear-events").addEventListener("click", async () => {
    // Clears pw-diagnostics too — it's a second persistence path with no
    // other way for the user to clear it.
    await chrome.storage.local.set({ "pw-events": [], "pw-diagnostics": [] });
    await refresh();
  });

  document.getElementById("export-aggregate").addEventListener("click", async () => {
    const [policyInfo, events] = await Promise.all([loadPolicyInfo(), loadEvents()]);
    const aggregate = buildAggregate(events, policyInfo.policy);
    downloadJson(`pw-aggregate-${aggregate.generatedDay}.json`, aggregate);
  });

  document.getElementById("export-diagnostics").addEventListener("click", async () => {
    const [policyInfo, diagnostics] = await Promise.all([loadPolicyInfo(), loadDiagnostics()]);
    const report = buildDiagnosticsExport(policyInfo, diagnostics);
    downloadJson(`pw-diagnostics-${report.generatedAt.slice(0, 10)}.json`, report);
  });

  document.getElementById("enable-extra-hosts").addEventListener("click", async () => {
    // chrome.permissions.request requires an active user gesture — this
    // click handler is that gesture. Never called from background.ts or on
    // popup load.
    const extraHosts = await loadExtraHosts();
    if (extraHosts.length === 0) return;
    let granted = false;
    try {
      granted = await chrome.permissions.request({ permissions: ["scripting"], origins: extraHosts });
    } catch {
      granted = false; // e.g. the user dismissed Chrome's native prompt
    }
    if (granted) {
      try {
        // Ask background.ts to reconcile immediately rather than waiting for
        // its own chrome.permissions.onAdded listener to fire.
        await chrome.runtime.sendMessage({ type: "sync-extra-hosts" });
      } catch {
        /* background re-syncs on its own via onAdded regardless */
      }
    }
    await refreshExtraHostsNotice();
  });

  // Built lazily here, on the user's click, rather than eagerly on every
  // popup open — buildReportUrl() only needs to run once anyone is actually
  // about to file a report. href stays "#" (see popup.html) until then.
  document.getElementById("report-problem").addEventListener("click", (e) => {
    e.preventDefault();
    buildReportUrl().then((url) => {
      window.open(url, "_blank", "noopener,noreferrer");
    });
  });

  // Inserted here rather than in popup.html: this file's ownership doesn't
  // extend to that markup, and a plain DOM insertion keeps the same visual
  // language (dark surface, blue accent) without needing a new CSS rule
  // there. Idempotent so a stray double-call never produces two buttons.
  // Requires the manifest's "options_ui" entry (added separately) — without
  // it, chrome.runtime.openOptionsPage() rejects and the click is a no-op.
  function ensureOptionsButton() {
    if (document.getElementById("open-options")) return;
    const badge = document.getElementById("mode");
    if (!badge || !badge.parentNode) return;
    const btn = document.createElement("button");
    btn.id = "open-options";
    btn.type = "button";
    btn.textContent = "Open policy settings";
    btn.style.cssText =
      "display:block;width:100%;margin-top:10px;padding:6px 0;border-radius:5px;" +
      "border:1px solid #2c4a72;background:#171d24;color:#9fd0ff;font:inherit;cursor:pointer;";
    btn.addEventListener("click", () => {
      if (chrome.runtime.openOptionsPage) chrome.runtime.openOptionsPage();
    });
    badge.insertAdjacentElement("afterend", btn);
  }
  ensureOptionsButton();

  await Promise.all([refresh(), refreshExtraHostsNotice()]);
})();
