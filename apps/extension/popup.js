(async () => {
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
  function safeFields(record) {
    const r = record && typeof record === "object" ? record : {};
    const actions = Array.isArray(r.actions) ? r.actions.filter((a) => typeof a === "string") : [];
    const categories = Array.isArray(r.categories) ? r.categories.filter((c) => typeof c === "string") : [];
    return {
      ts: typeof r.ts === "string" ? r.ts : null,
      host: typeof r.host === "string" ? r.host : "–",
      actions,
      categories,
    };
  }

  function primaryAction(actions) {
    let best = null;
    for (const a of actions) {
      if (ACTION_PRIORITY[a] && (!best || ACTION_PRIORITY[a] > ACTION_PRIORITY[best])) best = a;
    }
    return best;
  }

  async function loadPolicyInfo() {
    let managed = false;
    let policy = null;
    try {
      const m = await chrome.storage.managed.get(["policy"]);
      if (typeof m.policy === "string" && m.policy) {
        managed = true;
        try { policy = JSON.parse(m.policy); } catch { /* malformed managed policy */ }
      }
    } catch { /* managed storage unavailable outside enterprise deployments */ }
    if (!policy) {
      const local = await chrome.storage.local.get(["policy"]);
      if (local.policy) policy = local.policy;
    }
    return { managed, policy };
  }

  async function loadEvents() {
    const local = await chrome.storage.local.get(["pw-events"]);
    return Array.isArray(local["pw-events"]) ? local["pw-events"] : [];
  }

  function renderPolicy({ managed, policy }) {
    document.getElementById("policy-name").textContent = policy?.name ?? "standalone-default";
    document.getElementById("rule-count").textContent = Array.isArray(policy?.rules) ? policy.rules.length : 0;
    document.getElementById("host-count").textContent = Array.isArray(policy?.hosts) ? policy.hosts.length : 0;
    const badge = document.getElementById("mode");
    if (managed) {
      badge.textContent = "Managed by your organization";
      badge.classList.remove("unmanaged");
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
        ? "Event logging is disabled by this policy."
        : "No events yet.";
      list.appendChild(li);
      return;
    }
    for (const ev of recent) {
      const { ts, host, actions, categories } = safeFields(ev);
      const action = primaryAction(actions) ?? (actions[0] || "event");
      const li = document.createElement("li");
      li.innerHTML =
        `<div class="ev-top"><span class="ev-host">${escapeHtml(host)}</span>` +
        `<span class="ev-time">${escapeHtml(formatTime(ts))}</span></div>` +
        `<div class="ev-meta"><span class="ev-action ${escapeHtml(action)}">${escapeHtml(action)}</span>` +
        `${escapeHtml(categories.join(", ") || "–")}</div>`;
      list.appendChild(li);
    }
  }

  async function refresh() {
    const [policyInfo, events] = await Promise.all([loadPolicyInfo(), loadEvents()]);
    renderPolicy(policyInfo);
    renderCounts(events);
    renderList(events, (policyInfo.policy?.logging ?? "off") === "off");
  }

  document.getElementById("clear-events").addEventListener("click", async () => {
    await chrome.storage.local.set({ "pw-events": [] });
    await refresh();
  });

  await refresh();
})();
