const $ = (id) => document.getElementById(id);
let session = "",
  tab = "traffic",
  offset = 0,
  selected = null,
  detailTab = "request",
  state = {},
  generation = 0;
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
async function api(url, body) {
  const r = await fetch("/api/" + url, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      "x-capture-token": CAPTURE_TOKEN,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok) throw Error(data.error || r.statusText);
  return data;
}
function toast(s) {
  $("toast").textContent = s;
  $("toast").hidden = false;
  clearTimeout(window.toastTimer);
  window.toastTimer = setTimeout(() => ($("toast").hidden = true), 6000);
}
function params(filtered = true) {
  const q = new URLSearchParams({ session, limit: 200, offset });
  if (tab === "scripts") q.set("js", "1");
  if (filtered)
    for (const [id, key] of [
      ["search", "q"],
      ["method", "method"],
      ["host", "host"],
      ["status", "status"],
    ])
      if ($(id).value) q.set(key, $(id).value);
  return q;
}
async function refresh() {
  const g = ++generation;
  try {
    state = await api("state");
    if (tab !== "recon") {
      const labels = document.querySelectorAll(".stats small");
      labels[0].textContent = "CAPTURED REQUESTS";
      labels[1].textContent = "VISIBLE RESULTS";
      labels[3].textContent = "CAPTURE ENGINE";
      document.querySelector(".stats .engine").innerHTML =
        "Chromium <span>↗</span>";
    }
    if (!session && state.sessions.length)
      session = state.active || state.sessions[0].id;
    const s = state.sessions.find((s) => s.id === session);
    $("sessions").innerHTML = state.sessions
      .map(
        (s) =>
          `<button class="session ${s.id === session ? "active" : ""}" data-session="${s.id}"><strong>${esc(s.name)}</strong><small>${new Date(s.created).toLocaleDateString()} · ${s.count} requests ${s.id === state.active ? " • LIVE" : ""}</small></button>`,
      )
      .join("");
    $("title").textContent = s?.name || "Your browser, in detail.";
    $("subtitle").textContent = s
      ? `Created ${new Date(s.created).toLocaleString()} · Captured traffic stays on your device.`
      : "Start a capture to see every request unfold.";
    $("totalCount").textContent = s?.count || 0;
    $("live").textContent = state.active
      ? state.paused
        ? "PAUSED"
        : "● CAPTURING"
      : "IDLE";
    $("live").className =
      "badge " + (state.active && !state.paused ? "live" : "");
    $("pause").disabled = !state.active;
    $("stop").disabled = !state.active;
    $("newCapture").disabled = !!state.active;
    $("resume").hidden = !!state.active || !session;
    $("pause").textContent = state.paused ? "Resume capture" : "Pause capture";
    if (typeof refreshWorkbench === "function") await refreshWorkbench();
    if (tab === "handoff") {
      if (typeof refreshHandoff === "function") await refreshHandoff();
      return;
    }
    if (tab === "recon") {
      if (typeof refreshRecon === "function") await refreshRecon();
      return;
    }
    if (tab === "intercept" || tab === "repeater") return;
    const js = await api(
      "traffic?" + new URLSearchParams({ session, js: 1, limit: 1 }),
    );
    $("jsCount").textContent = js.total;
    if (tab === "tech") {
      await loadTech();
      return;
    }
    const data = await api("traffic?" + params());
    if (g !== generation) return;
    $("visibleCount").textContent = data.total;
    $("resultLabel").textContent =
      tab === "scripts" ? "JAVASCRIPT LIBRARY" : "HTTP HISTORY";
    $("traffic").innerHTML = data.rows
      .map(
        (r) =>
          `<tr data-id="${r.id}" class="${selected?.id === r.id ? "selected" : ""}"><td>${r.id}</td><td class="method ${esc(r.method)}">${esc(r.method)}</td><td class="${r.status >= 400 || r.error ? "bad" : "ok"}">${r.status || (r.error ? "ERR" : "…")}</td><td title="${esc(r.url)}">${esc(r.url)}</td><td>${esc(r.type)}</td><td>${r.size == null ? "—" : size(r.size)}</td><td>${r.duration == null ? "—" : Math.round(r.duration) + " ms"}</td></tr>`,
      )
      .join("");
    $("empty").hidden = data.total > 0;
    $("emptyStart").hidden = !!state.active;
    $("empty").querySelector("h2").textContent = s
      ? "No requests match this view."
      : "Every action leaves a trace.";
    $("pageInfo").textContent = data.total
      ? `${offset + 1}–${Math.min(offset + 200, data.total)} of ${data.total} matching requests`
      : "No matching requests";
    $("prev").disabled = !offset;
    $("next").disabled = offset + 200 >= data.total;
  } catch (e) {
    toast(e.message);
  }
}
function size(n) {
  return n < 1024
    ? n + " B"
    : n < 1048576
      ? (n / 1024).toFixed(1) + " KB"
      : (n / 1048576).toFixed(1) + " MB";
}
async function loadTech() {
  const data = await api("technologies?session=" + session);
  $("technologies").innerHTML = data.length
    ? data
        .map(
          (r) =>
            `<article class="techOrigin"><h3>${esc(r.origin)} <span class="badge">${esc(r.engine)}</span></h3><div class="techGrid">${r.result.length ? r.result.map((t) => `<div class="techChip">${esc(t.name)} ${esc(t.version || "")}<small>${esc((t.categories || []).join(" · "))} ${t.confidence ? ` · ${t.confidence}% confidence` : ""}</small></div>`).join("") : "No fingerprints detected for this origin."}</div></article>`,
        )
        .join("")
    : '<div class="empty"><h2>Discover what powers the page.</h2><p>Browse a site to collect passive Wappalyzer fingerprints.</p></div>';
}
function openDialog() {
  $("launchError").textContent = "";
  $("sessionName").value = "Capture " + new Date().toLocaleString();
  $("launchDialog").showModal();
  $("startUrl").focus();
}
$("newCapture").onclick = $("emptyStart").onclick = openDialog;
$("cancelLaunch").onclick = () => $("launchDialog").close();
$("launchForm").onsubmit = async (e) => {
  e.preventDefault();
  $("launchButton").disabled = true;
  try {
    const r = await api("launch", {
      name: $("sessionName").value,
      url: $("startUrl").value,
      browser: $("browser").value,
    });
    session = r.id;
    offset = 0;
    $("launchDialog").close();
    await refresh();
    toast(
      "Capture browser opened. Browse normally; all its tabs are recorded.",
    );
  } catch (e) {
    $("launchError").textContent = e.message;
  } finally {
    $("launchButton").disabled = false;
  }
};
$("sessions").onclick = (e) => {
  const b = e.target.closest("[data-session]");
  if (b) {
    session = b.dataset.session;
    offset = 0;
    $("inspector").hidden = true;
    refresh();
  }
};
document.querySelectorAll("[data-tab]").forEach(
  (b) =>
    (b.onclick = () => {
      tab = b.dataset.tab;
      offset = 0;
      document
        .querySelectorAll("[data-tab]")
        .forEach((x) => x.classList.toggle("active", x === b));
      $("captureView").hidden = !["traffic", "scripts"].includes(tab);
      $("techView").hidden = tab !== "tech";
      $("interceptView").hidden = tab !== "intercept";
      $("repeaterView").hidden = tab !== "repeater";
      $("reconView").hidden = tab !== "recon";
      $("handoffView").hidden = tab !== "handoff";
      $("exportFormat").value = tab === "scripts" ? "zip" : "har";
      refresh();
    }),
);
let debounce;
for (const id of ["search", "method", "host", "status"])
  $(id).oninput = () => {
    offset = 0;
    clearTimeout(debounce);
    debounce = setTimeout(refresh, 180);
  };
$("reset").onclick = () => {
  for (const id of ["search", "method", "host", "status"]) $(id).value = "";
  offset = 0;
  refresh();
};
$("prev").onclick = () => {
  offset = Math.max(0, offset - 200);
  refresh();
};
$("next").onclick = () => {
  offset += 200;
  refresh();
};
$("pause").onclick = async () => {
  try {
    await api("pause", {});
    refresh();
  } catch (e) {
    toast(e.message);
  }
};
$("stop").onclick = async () => {
  try {
    $("stop").disabled = true;
    await api("stop", {});
    refresh();
  } catch (e) {
    toast(e.message);
  }
};
function download(filtered) {
  if (!session) return toast("Create a capture first.");
  const q = params(filtered);
  q.set("format", $("exportFormat").value);
  if (q.get("format") === "zip") q.set("js", "1");
  q.set("token", CAPTURE_TOKEN);
  const a = document.createElement("a");
  a.href = "/api/export?" + q;
  a.download = "";
  a.click();
  toast(
    filtered
      ? "Exporting requests matching the current filters."
      : "Exporting all requests in this view.",
  );
}
$("exportAll").onclick = () => download(false);
$("exportFiltered").onclick = () => download(true);
$("traffic").onclick = async (e) => {
  const row = e.target.closest("[data-id]");
  if (!row) return;
  try {
    selected = await api("traffic/" + row.dataset.id);
    $("inspector").hidden = false;
    $("detailSummary").innerHTML =
      `<span class="method">${esc(selected.method)}</span> <span class="ok">${selected.status || "Pending"}</span><br>${esc(selected.url)}<br><span style="color:var(--muted)">${size(selected.size)} · ${Math.round(selected.duration || 0)} ms · ${esc(selected.error || "")}</span>`;
    renderDetail();
  } catch (e) {
    toast(e.message);
  }
};
function detailText() {
  if (!selected) return "";
  if (detailTab === "source") {
    if (selected.text) return selected.text;
    if (selected.size)
      return "[Binary response — download the body to inspect it.]";
    return selected.error || "[Empty or pending response body]";
  }
  const headers = JSON.parse(
    (detailTab === "request"
      ? selected.requestHeaders
      : selected.responseHeaders) || "{}",
  );
  return (
    (detailTab === "request"
      ? `${selected.method} ${selected.url}`
      : `HTTP ${selected.status || "pending"}`) +
    "\n" +
    Object.entries(headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n") +
    (detailTab === "request" ? "\n\n" + (selected.requestBody || "") : "")
  );
}
function renderDetail() {
  const text = detailText(),
    term = $("detailSearch").value;
  let html = esc(text);
  if (term) {
    const bits = text.toLowerCase().split(term.toLowerCase());
    let i = 0;
    html = bits
      .map((b, index) => {
        const part = esc(text.slice(i, i + b.length));
        i += b.length;
        if (index < bits.length - 1) {
          const match = esc(text.slice(i, i + term.length));
          i += term.length;
          return part + "<mark>" + match + "</mark>";
        }
        return part;
      })
      .join("");
  }
  $("detailContent").innerHTML = html;
}
document.querySelectorAll("[data-detail]").forEach(
  (b) =>
    (b.onclick = () => {
      detailTab = b.dataset.detail;
      document
        .querySelectorAll("[data-detail]")
        .forEach((x) => x.classList.toggle("active", x === b));
      renderDetail();
    }),
);
$("detailSearch").oninput = renderDetail;
$("closeInspector").onclick = () => ($("inspector").hidden = true);
$("copy").onclick = async () => {
  await navigator.clipboard.writeText(detailText());
  toast("Copied to clipboard.");
};
$("download").onclick = () => {
  if (selected)
    location.href = "/api/body/" + selected.id + "?token=" + CAPTURE_TOKEN;
};
$("probe").onclick = async () => {
  $("probe").disabled = true;
  $("probe").textContent = "Probing captured origins…";
  try {
    const r = await api("httpx", { session });
    toast(`httpx finished: ${r.count} origins returned results.`);
    await loadTech();
  } catch (e) {
    toast(e.message);
  } finally {
    $("probe").disabled = false;
    $("probe").textContent = "Run httpx -tech-detect ↗";
  }
};
document.onkeydown = (e) => {
  if (e.key === "Escape") $("inspector").hidden = true;
  if (
    e.key === "/" &&
    !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)
  ) {
    e.preventDefault();
    $("search").focus();
  }
};
refresh();
setInterval(() => {
  if (!$("launchDialog").open) refresh();
}, 2500);

$("resume").onclick = async () => {
  try {
    $("resume").disabled = true;
    await api("launch", { session, browser: "chromium" });
    await refresh();
    toast("Session reopened with its saved browser profile.");
  } catch (e) {
    toast(e.message);
  } finally {
    $("resume").disabled = false;
  }
};
