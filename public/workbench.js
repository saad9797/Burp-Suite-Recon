let heldId = "",
  heldData = null,
  interceptSnapshot = { enabled: false, queue: [] };
let repeatResult = null,
  previousRepeat = null,
  repeatClient = "",
  repeatSending = false,
  repeatSession = "";
const headerText = (headers) =>
  Object.entries(headers || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
function parseHeaders(text) {
  const headers = {};
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const colon = line.indexOf(":");
    if (colon < 1) throw Error("Each header needs a name and a colon: " + line);
    const name = line.slice(0, colon).trim().toLowerCase();
    if (name in headers)
      throw Error(
        "Duplicate header: " + name + ". Combine its values on one line.",
      );
    headers[name] = line.slice(colon + 1).trim();
  }
  return headers;
}
function editorRequest(prefix) {
  return {
    method: $(prefix + "Method").value.trim(),
    url: $(prefix + "Url").value.trim(),
    headers: parseHeaders($(prefix + "Headers").value),
    body: $(prefix + "Body").value,
    encoding: $(prefix + "Encoding").value,
  };
}
function fillRequest(prefix, request) {
  $(prefix + "Method").value = request.method || "GET";
  $(prefix + "Url").value = request.url || "";
  $(prefix + "Headers").value = headerText(request.headers);
  $(prefix + "Body").value = request.body || "";
  $(prefix + "Encoding").value = request.encoding || "utf8";
}
function selectHeld(id) {
  if (heldId && heldId !== id) {
    try {
      updateCollectedHeld();
    } catch {}
  }
  const item = interceptSnapshot.queue.find((r) => r.id === id);
  heldId = item?.id || "";
  heldData = item || null;
  $("interceptEditor").hidden = !item;
  $("interceptEmpty").hidden = !!item;
  $("heldError").textContent = "";
  if (item) {
    fillRequest("held", item);
    $("heldLabel").textContent = `${item.method} · ${item.type}`;
  }
  $("interceptQueue")
    .querySelectorAll("[data-held]")
    .forEach((b) => b.classList.toggle("active", b.dataset.held === heldId));
}
async function refreshWorkbench() {
  interceptSnapshot = await api("intercept");
  $("queueCount").textContent = interceptSnapshot.queue.length;
  $("interceptToggle").textContent = interceptSnapshot.enabled
    ? "Interception is ON — turn off & forward all"
    : "Interception is off — turn on";
  $("interceptToggle").classList.toggle(
    "interceptOn",
    interceptSnapshot.enabled,
  );
  $("interceptToggle").disabled = !state.active;
  $("interceptState").textContent = state.active
    ? `${interceptSnapshot.queue.length} held · ${interceptSnapshot.enabled ? "New matching requests will stop here." : "Traffic passes through."}`
    : "Open a capture browser to intercept traffic.";
  $("interceptQueue").innerHTML = interceptSnapshot.queue.length
    ? interceptSnapshot.queue
        .map(
          (r) =>
            `<button class="queueItem ${r.id === heldId ? "active" : ""}" data-held="${r.id}"><strong><span class="method">${esc(r.method)}</span> ${esc(new URL(r.url).pathname)}</strong><small>${esc(new URL(r.url).host)} · ${esc(r.type)}</small></button>`,
        )
        .join("")
    : '<p class="workbenchNote" style="padding:16px">No requests held.</p>';
  // Preserve unsaved edits when the queue is polled or grows.
  if (!interceptSnapshot.queue.some((r) => r.id === heldId))
    selectHeld(interceptSnapshot.queue[0]?.id || "");
  collectHeldRequests();
  renderWorkspace();
  if (tab === "repeater") await loadRepeaterHistory();
}
$("interceptQueue").onclick = (e) => {
  const b = e.target.closest("[data-held]");
  if (b) selectHeld(b.dataset.held);
};
async function setInterception(enabled) {
  try {
    if (!enabled) updateCollectedHeld();
    await api("intercept", {
      enabled,
      method: $("interceptMethod").value,
      url: $("interceptUrl").value,
    });
    await refresh();
  } catch (e) {
    toast(e.message);
  }
}
$("interceptToggle").onclick = () =>
  setInterception(!interceptSnapshot.enabled);
$("applyInterceptRules").onclick = () =>
  setInterception(interceptSnapshot.enabled);
async function releaseHeld(action) {
  if (!heldId) return;
  const id = heldId;
  $("heldForward").disabled = $("heldDrop").disabled = true;
  $("heldError").textContent = "";
  try {
    updateCollectedHeld();
    await api("intercept/" + id, {
      action,
      ...(action === "forward" ? { request: editorRequest("held") } : {}),
    });
    heldId = "";
    await refresh();
  } catch (e) {
    $("heldError").textContent = e.message;
  } finally {
    $("heldForward").disabled = $("heldDrop").disabled = false;
  }
}
$("heldForward").onclick = () => releaseHeld("forward");
$("heldDrop").onclick = () => releaseHeld("drop");
function openRepeater(request, sourceSession, name) {
  if (repeatSending)
    return toast("Wait for the current repeater send or cancel it first.");
  saveRepeatTab();
  fillRequest("repeat", request);
  if (sourceSession) session = sourceSession;
  $("repeatName").value =
    name || `${request.method} ${new URL(request.url).pathname}`;
  repeatSession = sourceSession || session;
  repeatResult = null;
  previousRepeat = null;
  $("repeatSummary").textContent = "NOT SENT";
  $("repeatError").textContent = "";
  $("repeatDownload").disabled = true;
  renderRepeatResponse();
  $("inspector").hidden = true;
  document.querySelector('[data-tab="repeater"]').click();
  createRepeatTab();
  toast("Request copied to Repeater. Edit it, then click Send.");
}
$("heldRepeater").onclick = () => {
  try {
    openRepeater(editorRequest("held"), heldData?.session);
  } catch (e) {
    toast(e.message);
  }
};
$("sendToRepeater").onclick = () => {
  if (selected)
    openRepeater(
      {
        method: selected.method,
        url: selected.url,
        headers: JSON.parse(selected.requestHeaders || "{}"),
        body:
          selected.requestEncoding === "base64"
            ? selected.requestBase64
            : selected.requestBody || "",
        encoding: selected.requestEncoding || "utf8",
      },
      session,
    );
};
$("repeaterNew").onclick = () => {
  if (repeatSending) return;
  saveRepeatTab();
  fillRequest("repeat", { method: "GET", url: "", headers: {}, body: "" });
  repeatSession = session;
  repeatResult = null;
  previousRepeat = null;
  $("repeatName").value = "";
  $("repeatSummary").textContent = "NOT SENT";
  $("repeatDownload").disabled = true;
  $("repeatError").textContent = "";
  renderRepeatResponse();
  createRepeatTab();
  $("repeatUrl").focus();
};
async function loadRepeaterHistory() {
  const history = await api("repeater?session=" + encodeURIComponent(session));
  $("repeaterHistory").innerHTML = history.length
    ? history
        .map(
          (r) =>
            `<button class="queueItem ${repeatResult?.id === r.id ? "active" : ""}" data-repeat="${r.id}"><strong>${esc(r.name)}</strong><small>${r.status || "ERR"} · ${Math.round(r.duration || 0)} ms · ${new Date(r.created).toLocaleTimeString()}</small></button>`,
        )
        .join("")
    : '<p class="workbenchNote" style="padding:16px">Send a captured request here from its inspector, or start with a blank request.</p>';
}
$("repeaterHistory").onclick = async (e) => {
  const b = e.target.closest("[data-repeat]");
  if (!b || repeatSending) return;
  try {
    const result = await api("repeater/" + b.dataset.repeat);
    saveRepeatTab();
    previousRepeat = repeatResult;
    repeatResult = result;
    repeatSession = result.session;
    fillRequest("repeat", result.request);
    $("repeatName").value = result.name;
    showRepeatResult();
    createRepeatTab();
    await loadRepeaterHistory();
  } catch (e) {
    toast(e.message);
  }
};
function showRepeatResult() {
  const r = repeatResult?.response;
  if (!r) return;
  $("repeatSummary").textContent =
    `${r.status || "ERROR"} · ${Math.round(r.duration || 0)} ms · ${size(r.size || 0)}`;
  $("repeatError").textContent = r.error || "";
  $("repeatDownload").disabled = !repeatResult;
  renderRepeatResponse();
}
function repeatText() {
  if (!repeatResult) return "Send a request to inspect its response here.";
  const r = repeatResult.response;
  switch ($("repeatDisplay").value) {
    case "headers":
      return (
        `HTTP ${r.status} ${r.statusText || ""}\n` +
        r.headers.map((h) => `${h.name}: ${h.value}`).join("\n")
      );
    case "pretty":
      try {
        return JSON.stringify(JSON.parse(r.text), null, 2);
      } catch {
        return r.text || r.error || "[Empty response]";
      }
    case "compare":
      if (!previousRepeat)
        return "Send another request, or open an older result, to compare responses.";
      return `PREVIOUS: ${previousRepeat.request.method} ${previousRepeat.request.url}\n${previousRepeat.response.text}\n\nCURRENT: ${repeatResult.request.method} ${repeatResult.request.url}\n${r.text}`;
    default:
      return r.text || r.error || "[Empty response]";
  }
}
function renderRepeatResponse() {
  const text = repeatText(),
    term = $("repeatFind").value;
  let html = esc(text);
  if (term) {
    const re = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    html = "";
    let end = 0;
    for (const match of text.matchAll(re)) {
      html +=
        esc(text.slice(end, match.index)) +
        "<mark>" +
        esc(match[0]) +
        "</mark>";
      end = match.index + match[0].length;
    }
    html += esc(text.slice(end));
  }
  $("repeatResponse").innerHTML = html;
  if (previousRepeat && repeatResult) {
    const old = previousRepeat.response,
      now = repeatResult.response;
    $("repeatComparison").textContent =
      `Previous → current: status ${old.status} → ${now.status}; size ${size(old.size)} → ${size(now.size)}; ${Math.round(old.duration)} → ${Math.round(now.duration)} ms; body ${old.bodyBase64 === now.bodyBase64 ? "unchanged" : "changed"}.`;
  } else $("repeatComparison").textContent = "";
}
$("repeatDisplay").onchange = $("repeatFind").oninput = renderRepeatResponse;
$("repeatSend").onclick = async () => {
  if (repeatSending) return;
  $("repeatError").textContent = "";
  try {
    const request = editorRequest("repeat");
    if (!workspace.active) createRepeatTab();
    const targetSession = repeatSession || session;
    if (!targetSession) throw Error("Create a capture session first.");
    repeatSending = true;
    repeatClient = crypto.randomUUID();
    $("repeatSend").disabled = true;
    $("repeatCancel").hidden = false;
    $("repeatSummary").textContent = "SENDING…";
    const result = await api("repeater/send", {
      ...request,
      session: targetSession,
      name: $("repeatName").value,
      clientId: repeatClient,
      timeout: Number($("repeatTimeout").value),
      verifyTLS: $("repeatTLS").checked,
    });
    previousRepeat = repeatResult;
    repeatResult = result;
    showRepeatResult();
    saveRepeatTab();
    renderWorkspace();
    await loadRepeaterHistory();
  } catch (e) {
    $("repeatError").textContent = e.message;
    $("repeatSummary").textContent = "SEND FAILED";
  } finally {
    repeatSending = false;
    repeatClient = "";
    $("repeatSend").disabled = false;
    $("repeatCancel").hidden = true;
  }
};
$("repeatCancel").onclick = async () => {
  try {
    await api("repeater/cancel", { clientId: repeatClient });
  } catch (e) {
    toast(e.message);
  }
};
$("repeatDownload").onclick = () => {
  if (repeatResult)
    location.href =
      "/api/repeater/" + repeatResult.id + "/body?token=" + CAPTURE_TOKEN;
};

// Groups and open tabs are local to this browser; server send history is retained.
let workspace;
try {
  workspace = JSON.parse(localStorage.getItem("traceglass-workspace-v1"));
} catch {}
workspace = workspace || {
  captures: [],
  tabs: [],
  groups: [],
  active: "",
  collecting: "",
};
function persistWorkspace() {
  try {
    localStorage.setItem("traceglass-workspace-v1", JSON.stringify(workspace));
  } catch {
    toast("Workspace storage is full. Keep this page open to retain its tabs.");
  }
}
function saveRepeatTab() {
  const item = workspace.tabs.find((t) => t.id === workspace.active);
  if (!item) return;
  // Preserve even incomplete header edits while switching tabs.
  item.fields = Object.fromEntries(
    ["Method", "Url", "Headers", "Body", "Encoding", "Name", "Timeout"].map(
      (k) => [k, $("repeat" + k).value],
    ),
  );
  item.verifyTLS = $("repeatTLS").checked;
  item.result = repeatResult;
  item.previous = previousRepeat;
  item.session = repeatSession;
  persistWorkspace();
}
function createRepeatTab(group = "") {
  const item = { id: crypto.randomUUID(), group, session: repeatSession };
  workspace.tabs.push(item);
  workspace.active = item.id;
  saveRepeatTab();
  renderWorkspace();
}
function activateRepeatTab(id, restoring = false) {
  if (repeatSending)
    return toast("Wait for the current send or cancel it first.");
  if (!restoring) saveRepeatTab();
  workspace.active = id;
  const item = workspace.tabs.find((t) => t.id === id);
  repeatResult = item?.result || null;
  previousRepeat = item?.previous || null;
  repeatSession = item?.session || session;
  if (item?.fields) {
    for (const [k, v] of Object.entries(item.fields)) $("repeat" + k).value = v;
    $("repeatTLS").checked = item.verifyTLS;
  } else {
    fillRequest("repeat", {});
    $("repeatName").value = "";
  }
  $("repeatSummary").textContent = "NOT SENT";
  $("repeatError").textContent = "";
  $("repeatDownload").disabled = !repeatResult;
  renderRepeatResponse();
  if (repeatResult) showRepeatResult();
  renderWorkspace();
  persistWorkspace();
}
function renderWorkspace() {
  const active = workspace.tabs.find((t) => t.id === workspace.active);
  const options =
    '<option value="">Ungrouped</option>' +
    workspace.groups
      .filter((g) => g.session === session)
      .map((g) => `<option value="${g.id}">${esc(g.name)}</option>`)
      .join("");
  $("repeatGroup").innerHTML = options;
  $("repeatGroup").value = active?.group || "";
  const visible = workspace.tabs.filter((t) => t.session === session);
  $("repeatTabs").innerHTML = [
    "",
    ...workspace.groups.filter((g) => g.session === session).map((g) => g.id),
  ]
    .map((group) => {
      const items = visible.filter((t) => t.group === group);
      if (!items.length) return "";
      const name =
        workspace.groups.find((g) => g.id === group)?.name || "Ungrouped";
      return `<div class="tabGroup"><strong>${esc(name)}</strong>${items.map((t) => `<span class="requestTab"><button role="tab" aria-selected="${t.id === workspace.active}" data-open-tab="${t.id}">${esc(t.fields?.Name || t.fields?.Url || "Blank request")}</button><button data-close-tab="${t.id}" aria-label="Close request tab">&times;</button></span>`).join("")}</div>`;
    })
    .join("");
  renderCaptureGroups();
}
$("repeatTabs").onclick = (e) => {
  const close = e.target.closest("[data-close-tab]");
  if (close) {
    if (repeatSending)
      return toast("Wait for the current send or cancel it first.");
    saveRepeatTab();
    workspace.tabs = workspace.tabs.filter(
      (t) => t.id !== close.dataset.closeTab,
    );
    if (workspace.active === close.dataset.closeTab)
      activateRepeatTab(
        workspace.tabs.filter((t) => t.session === session).at(-1)?.id || "",
      );
    renderWorkspace();
    persistWorkspace();
    return;
  }
  const open = e.target.closest("[data-open-tab]");
  if (open) activateRepeatTab(open.dataset.openTab);
};
$("repeatGroupCreate").onclick = () => {
  const name = $("repeatGroupName").value.trim();
  if (!name) return toast("Enter a group name.");
  if (!workspace.active) createRepeatTab();
  const group = { id: crypto.randomUUID(), name, session };
  workspace.groups.push(group);
  workspace.tabs.find((t) => t.id === workspace.active).group = group.id;
  $("repeatGroupName").value = "";
  renderWorkspace();
  persistWorkspace();
};
$("repeatGroup").onchange = () => {
  const item = workspace.tabs.find((t) => t.id === workspace.active);
  if (item) {
    item.group = $("repeatGroup").value;
    persistWorkspace();
    renderWorkspace();
  }
};
function renderCaptureGroups() {
  const groups = workspace.captures.filter((g) => g.session === session);
  $("captureGroup").innerHTML =
    '<option value="">No automatic collection</option>' +
    groups
      .map(
        (g) =>
          `<option value="${g.id}">${esc(g.name)} (${g.requests.length})</option>`,
      )
      .join("");
  $("captureGroup").value = workspace.collecting;
  const group = groups.find((g) => g.id === workspace.collecting);
  $("captureGroupCount").textContent = group
    ? `${group.requests.length} collected. New held requests join this group; forwarding keeps the collected copy.`
    : "Select a group to collect new held requests automatically.";
}
function collectHeldRequests() {
  const group = workspace.captures.find(
    (g) => g.id === workspace.collecting && g.session === session,
  );
  if (group) {
    for (const r of interceptSnapshot.queue.filter(
      (r) => r.session === session,
    )) {
      if (!group.requests.some((i) => i.id === r.id))
        group.requests.push(structuredClone(r));
    }
    persistWorkspace();
  }
  renderCaptureGroups();
}
$("captureGroupCreate").onclick = () => {
  const name = $("captureGroupName").value.trim();
  if (!name || !session)
    return toast("Select a session and enter a group name.");
  const group = { id: crypto.randomUUID(), name, session, requests: [] };
  workspace.captures.push(group);
  workspace.collecting = group.id;
  $("captureGroupName").value = "";
  collectHeldRequests();
};
$("captureGroup").onchange = () => {
  workspace.collecting = $("captureGroup").value;
  collectHeldRequests();
  persistWorkspace();
};
function updateCollectedHeld() {
  if (!heldId) return;
  const group = workspace.captures.find(
    (g) => g.id === workspace.collecting && g.session === session,
  );
  if (!group) return;
  const request = { ...heldData, ...editorRequest("held") };
  const index = group.requests.findIndex((r) => r.id === heldId);
  if (index < 0) group.requests.push(request);
  else group.requests[index] = request;
  persistWorkspace();
  renderCaptureGroups();
}
$("captureGroupAdd").onclick = () => {
  try {
    updateCollectedHeld();
  } catch (e) {
    toast(e.message);
  }
};
$("captureGroupSend").onclick = () => {
  if (repeatSending)
    return toast("Wait for the current send or cancel it first.");
  try {
    updateCollectedHeld();
    const group = workspace.captures.find(
      (g) => g.id === workspace.collecting && g.session === session,
    );
    if (!group?.requests.length)
      return toast("Collect requests in a group first.");
    const target = { id: crypto.randomUUID(), name: group.name, session };
    workspace.groups.push(target);
    for (const request of group.requests) {
      openRepeater(request, group.session);
      workspace.tabs.find((t) => t.id === workspace.active).group = target.id;
    }
    renderWorkspace();
    persistWorkspace();
  } catch (e) {
    toast(e.message);
  }
};
function tabContext(item) {
  const f = item.fields || {};
  return {
    name: f.Name,
    session: item.session,
    request: {
      method: f.Method,
      url: f.Url,
      headers: f.Headers,
      body: f.Body,
      encoding: f.Encoding,
    },
    settings: { timeout: f.Timeout, verifyTLS: item.verifyTLS },
    lastExchange: item.result || null,
  };
}
async function copyContext(group) {
  try {
    saveRepeatTab();
    const active = workspace.tabs.find((t) => t.id === workspace.active);
    if (!active) return toast("Open a request first.");
    const items = group
      ? workspace.tabs.filter(
          (t) => t.session === active.session && t.group === active.group,
        )
      : [active];
    const context = {
      group: group
        ? workspace.groups.find((g) => g.id === active.group)?.name ||
          "Ungrouped"
        : undefined,
      requests: items.map(tabContext),
    };
    await navigator.clipboard.writeText(JSON.stringify(context, null, 2));
    toast(`Copied context for ${items.length} request(s).`);
  } catch (e) {
    toast("Could not copy context: " + e.message);
  }
}
$("repeatCopy").onclick = () => copyContext(false);
$("repeatGroupCopy").onclick = () => copyContext(true);
window.addEventListener("beforeunload", saveRepeatTab);
renderWorkspace();
if (workspace.active) activateRepeatTab(workspace.active, true);
