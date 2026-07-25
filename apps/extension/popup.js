(async () => {
  let managed = false, name = "standalone-default";
  try {
    const m = await chrome.storage.managed.get(["policy"]);
    if (typeof m.policy === "string" && m.policy) {
      managed = true;
      try { name = JSON.parse(m.policy).name ?? name; } catch {}
    }
  } catch {}
  const local = await chrome.storage.local.get(["policy", "pw-events"]);
  if (!managed && local.policy?.name) name = local.policy.name;
  document.getElementById("policy-name").textContent = name;
  document.getElementById("event-count").textContent =
    Array.isArray(local["pw-events"]) ? local["pw-events"].length : 0;
  const badge = document.getElementById("mode");
  if (managed) { badge.textContent = "Managed by your organization"; badge.classList.remove("unmanaged"); }
})();
