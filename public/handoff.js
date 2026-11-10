let handoffId = "",
  handoffCurrent = null,
  handoffMode = "summary",
  handoffOffset = 0,
  handoffRows = [],
  handoffAuth = null,
  handoffSession = "",
  handoffJobs = [];
const handoffFiles = {
  summary: "summary.md",
  diff: "diff_from_last_run.md",
  assets: "assets.json",
  endpoints: "endpoints.json",
  js_findings: "js_findings.json",
  auth_map: "auth_map.json",
};
async function refreshHandoff() {
  if (typeof resumeHandoffBuild === "function") await resumeHandoffBuild();
  const labels = document.querySelectorAll(".stats small");
  labels[0].textContent = "PACKAGE HOSTS";
  labels[1].textContent = "ENDPOINTS";
  labels[3].textContent = "ANALYSIS";
  document.querySelector(".stats .engine").textContent = "Local · no AI";
  const list = await api(
    "handoff/packages?session=" + encodeURIComponent(session),
  );
  if (handoffSession !== session) {
    handoffSession = session;
    handoffId = "";
    handoffCurrent = null;
  }
  if (!list.some((p) => p.id === handoffId)) handoffId = list[0]?.id || "";
  $("handoffPackages").innerHTML = list.length
    ? list
        .map(
          (p) =>
            `<option value="${p.id}">${esc(p.name)} · ${new Date(p.created).toLocaleString()}</option>`,
        )
        .join("")
    : "<option>No packages yet</option>";
  $("handoffPackages").value = handoffId;
  $("handoffEmpty").hidden = !!handoffId;
  $("handoffDownload").disabled = $("handoffCopy").disabled = !handoffId;
  if (!handoffId) {
    $("totalCount").textContent =
      $("visibleCount").textContent =
      $("jsCount").textContent =
        "0";
    $("handoffReadView").hidden = $("handoffInventoryView").hidden = true;
    $("handoffMetrics").innerHTML = "";
    $("handoffInfo").textContent = "";
    return;
  }
  handoffCurrent = await api("handoff/packages/" + handoffId);
  $("totalCount").textContent = handoffCurrent.counts.assets;
  $("visibleCount").textContent = handoffCurrent.counts.endpoints;
  $("jsCount").textContent = handoffCurrent.counts.js_findings;
  $("handoffInfo").textContent =
    `${handoffCurrent.target} · ${handoffCurrent.selected_runs.length} selected runs · ${handoffCurrent.diff.initial_baseline ? "Initial baseline" : "Baseline " + handoffCurrent.diff.baseline_id.slice(0, 8)} · Updated ${new Date(handoffCurrent.updated).toLocaleString()}`;
  $("handoffMetrics").innerHTML = [
    ["Live hosts", handoffCurrent.counts.live_assets],
    ["Endpoints", handoffCurrent.counts.endpoints],
    ["JavaScript files", handoffCurrent.counts.js_findings],
    ["ID review checklists", handoffCurrent.counts.auth_map],
    ["Traffic samples", handoffCurrent.counts.samples],
  ]
    .map(
      ([name, value]) =>
        `<div class="reconStage complete"><span>${value} ${name}</span></div>`,
    )
    .join("");
  await renderHandoff();
}
async function renderHandoff() {
  if (!handoffCurrent) return;
  const textMode = ["summary", "diff"].includes(handoffMode);
  $("handoffReadView").hidden = !textMode;
  $("handoffInventoryView").hidden = textMode;
  if (textMode) {
    $("handoffFilename").textContent = handoffFiles[handoffMode];
    $("handoffPreview").textContent =
      handoffMode === "summary"
        ? handoffCurrent.summary
        : handoffCurrent.diff_markdown;
    return;
  }
  const q = new URLSearchParams({
    category: handoffMode,
    q: $("handoffSearch").value,
    offset: handoffOffset,
  });
  const results = await api(
    "handoff/packages/" + handoffId + "/inventory?" + q,
  );
  handoffRows = results.rows;
  $("handoffRows").innerHTML = results.rows
    .map((r, index) => {
      let title, detail, review;
      if (handoffMode === "assets") {
        title = r.host;
        detail = `${r.status_code || "not live"} · ${r.tech_stack.join(", ") || "No fingerprint"}${r.environment_tags.length ? " · " + r.environment_tags.join(", ") : ""}`;
        review = r.is_non_production_candidate
          ? "Non-production name"
          : "Inspect";
      } else if (handoffMode === "endpoints") {
        title = r.method + " " + r.url;
        detail = "Params: " + (r.params.join(", ") || "none observed");
        review = r.looks_like_object_id ? "Object-ID candidate" : "Inspect";
      } else if (handoffMode === "js_findings") {
        title = r.file;
        detail = `${r.endpoints_found.length} routes · ${r.potential_secrets.length} secret candidates · ${r.feature_flags.length} flags`;
        review = "Locations & confidence";
      } else {
        title = r.method + " " + r.endpoint;
        detail = `${r.observations.length} observations · ${r.account_a_label || "A not set"} / ${r.account_b_label || "B not set"}`;
        review = r.review_status + " · " + r.flag;
      }
      return `<tr data-handoff-row="${index}"><td title="${esc(title)}">${esc(title)}</td><td title="${esc(detail)}">${esc(detail)}</td><td>${esc(review)}</td></tr>`;
    })
    .join("");
  $("handoffPageInfo").textContent = results.total
    ? `${handoffOffset + 1}–${Math.min(handoffOffset + 100, results.total)} of ${results.total}`
    : "No entries match this view.";
  $("handoffPrev").disabled = !handoffOffset;
  $("handoffNext").disabled = handoffOffset + 100 >= results.total;
}
document.querySelectorAll("[data-handoff-view]").forEach(
  (b) =>
    (b.onclick = () => {
      handoffMode = b.dataset.handoffView;
      handoffOffset = 0;
      document
        .querySelectorAll("[data-handoff-view]")
        .forEach((x) => x.classList.toggle("active", x === b));
      renderHandoff().catch((e) => toast(e.message));
    }),
);
$("handoffPackages").onchange = () => {
  handoffId = $("handoffPackages").value;
  handoffOffset = 0;
  refreshHandoff().catch((e) => toast(e.message));
};
$("handoffBuildOpen").onclick = async () => {
  try {
    if (!session) throw Error("Collect recon evidence in a session first.");
    handoffJobs = (await api("handoff/runs")).filter(
      (j) => !["running", "queued"].includes(j.status),
    );
    if (!handoffJobs.length)
      throw Error("Finish a recon run or import evidence first.");
    const currentJobs = handoffJobs.filter((j) => j.session === session);
    $("handoffPrimary").innerHTML = (
      currentJobs.length ? currentJobs : handoffJobs
    )
      .map(
        (j) =>
          `<option value="${j.id}">${esc(j.name)} · ${new Date(j.created).toLocaleString()} · ${esc(j.status)}</option>`,
      )
      .join("");
    $("handoffName").value = "";
    $("handoffBuildError").textContent = "";
    const packages = await api(
      "handoff/packages?session=" + encodeURIComponent(session),
    );
    $("handoffBaseline").innerHTML =
      '<option value="auto">Latest package with matching target scope</option><option value="none">No baseline</option>' +
      packages
        .map(
          (p) =>
            `<option value="${p.id}">${esc(p.name)} · ${new Date(p.created).toLocaleString()}</option>`,
        )
        .join("");
    renderHandoffRunChoices();
    $("handoffBuildDialog").showModal();
  } catch (e) {
    toast(e.message);
  }
};
function renderHandoffRunChoices() {
  const primary = $("handoffPrimary").value;
  const scope = handoffJobs.find((j) => j.id === primary)?.scope_key;
  $("handoffRunChoices").innerHTML =
    handoffJobs
      .filter((j) => j.id !== primary && j.scope_key === scope)
      .map(
        (j) =>
          `<label><input type="checkbox" value="${j.id}">${esc(j.name)}<small>${esc(j.session_name || "")} · ${esc(j.role)} · ${new Date(j.created).toLocaleString()} · ${esc(j.status)}</small></label>`,
      )
      .join("") || "<p>No additional runs.</p>";
}
$("handoffPrimary").onchange = renderHandoffRunChoices;
$("handoffBuildForm").onsubmit = async (e) => {
  e.preventDefault();
  $("handoffBuild").disabled = true;
  $("handoffBuild").textContent = "Analyzing and consolidating…";
  $("handoffBuildError").textContent = "";
  try {
    const started = await api("handoff/build-jobs", {
      primary: $("handoffPrimary").value,
      analysisProfile: $("handoffProfile").value,
      jobs: [
        $("handoffPrimary").value,
        ...[...$("handoffRunChoices").querySelectorAll("input:checked")].map(
          (i) => i.value,
        ),
      ],
      name: $("handoffName").value,
      baseline: $("handoffBaseline").value,
    });
    $("handoffBuildDialog").close();
    const result = await trackHandoffBuild(started.id);
    handoffId = result.id;
    session = result.session;
    handoffCurrent = result;
    handoffSession = session;
    handoffMode = "summary";
    handoffOffset = 0;
    document
      .querySelectorAll("[data-handoff-view]")
      .forEach((b) =>
        b.classList.toggle("active", b.dataset.handoffView === "summary"),
      );
    $("handoffBuildDialog").close();
    await refreshHandoff();
    toast("Package built. Read summary.md, then complete the auth checklist.");
  } catch (e) {
    $("handoffBuildError").textContent = e.message;
    if (!$("handoffBuildDialog").open) toast(e.message);
  } finally {
    $("handoffBuild").disabled = false;
    $("handoffBuild").textContent = "Build package →";
  }
};
function downloadHandoff(suffix) {
  if (handoffId) {
    const a = document.createElement("a");
    a.href =
      "/api/handoff/packages/" +
      handoffId +
      "/" +
      suffix +
      "?token=" +
      CAPTURE_TOKEN;
    a.download = "";
    a.click();
  }
}
$("handoffDownload").onclick = () => downloadHandoff("download");
$("handoffDownloadText").onclick = () =>
  downloadHandoff("file/" + handoffFiles[handoffMode]);
$("handoffInventoryDownload").onclick = () =>
  downloadHandoff("file/" + handoffFiles[handoffMode]);
$("handoffCopy").onclick = async () => {
  try {
    await navigator.clipboard.writeText(handoffCurrent.summary);
    toast("summary.md copied.");
  } catch (e) {
    toast(e.message);
  }
};
let handoffSearchTimer;
$("handoffSearch").oninput = () => {
  clearTimeout(handoffSearchTimer);
  handoffOffset = 0;
  handoffSearchTimer = setTimeout(
    () => renderHandoff().catch((e) => toast(e.message)),
    200,
  );
};
$("handoffPrev").onclick = () => {
  handoffOffset = Math.max(0, handoffOffset - 100);
  renderHandoff().catch((e) => toast(e.message));
};
$("handoffNext").onclick = () => {
  handoffOffset += 100;
  renderHandoff().catch((e) => toast(e.message));
};
