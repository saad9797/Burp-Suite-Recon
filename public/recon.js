const reconNames = {
  subdomains: "Subdomains",
  hosts: "Live hosts",
  archives: "Archived URLs",
  infrastructure: "IP / ASN / registration",
  dns: "DNS records",
  headers: "HTTP headers",
  technologies: "Technologies",
  javascript: "JavaScript files",
  endpoints: "Endpoints & paths",
  api: "API documentation",
  traffic: "Request / response traffic",
  authorization: "Account-role observations",
  mobile: "Mobile HAR evidence",
  integrations: "Third-party integrations",
  source: "Source repository",
  dependencies: "Dependencies",
  configuration: "Configuration",
  schema: "Schema / migrations",
  authcode: "Authorization code",
  routes: "API route definitions",
  git: "Git history",
  tests: "Tests",
  cicd: "CI/CD",
  secrets: "Potential secret patterns",
};
let reconJob = "",
  reconCategory = "",
  reconOffset = 0,
  reconCurrent = null,
  reconData = [],
  reconDetail = null,
  reconPreview = "";
let reconFetchGeneration = 0,
  reconSession = "";
async function refreshRecon() {
  const statLabels = document.querySelectorAll(".stats small");
  statLabels[0].textContent = "EVIDENCE RECORDS";
  statLabels[1].textContent = "MATCHING RECORDS";
  statLabels[3].textContent = "RECON ENGINE";
  document.querySelector(".stats .engine").textContent = "No API key";
  const generation = ++reconFetchGeneration;
  const jobs = await api("recon/jobs?session=" + encodeURIComponent(session));
  if (reconSession !== session) {
    reconSession = session;
    reconJob = "";
    reconOffset = 0;
  }
  if (!jobs.some((j) => j.id === reconJob)) reconJob = jobs[0]?.id || "";
  $("reconRuns").innerHTML = jobs.length
    ? jobs
        .map(
          (j) =>
            `<option value="${j.id}">${esc(j.name)} · ${new Date(j.created).toLocaleString()} · ${esc(j.status)}</option>`,
        )
        .join("")
    : "<option>No recon runs yet</option>";
  $("reconRuns").value = reconJob;
  if (!reconJob) {
    reconCurrent = null;
    $("totalCount").textContent =
      $("visibleCount").textContent =
      $("jsCount").textContent =
        "0";
    $("reconLog").textContent = "";
    $("reconPageInfo").textContent = "";
    $("reconRequests").textContent = "";
    $("reconRunStatus").textContent = "NO RUNS";
    $("reconRecords").innerHTML = "";
    $("reconStages").innerHTML = "";
    $("reconCategories").innerHTML = "";
    $("reconEmpty").hidden = false;
    $("reconCancel").hidden = true;
    $("reconPrev").disabled = $("reconNext").disabled = true;
    return;
  }
  const detail = await api("recon/jobs/" + reconJob);
  if (generation !== reconFetchGeneration) return;
  reconCurrent = detail;
  $("reconRunStatus").textContent = detail.status.toUpperCase();
  $("reconCancel").hidden = !["running", "queued"].includes(detail.status);
  $("reconRequests").textContent = `${detail.requests} active target requests`;
  const total = Object.values(detail.counts).reduce((n, v) => n + v, 0);
  $("totalCount").textContent = total;
  $("jsCount").textContent = detail.counts.javascript || 0;
  $("reconCategories").innerHTML =
    `<button class="reconCategory ${!reconCategory ? "active" : ""}" data-category="">All evidence <span>${total}</span></button>` +
    Object.entries(reconNames)
      .map(
        ([key, name]) =>
          `<button class="reconCategory ${reconCategory === key ? "active" : ""}" data-category="${key}">${esc(name)} <span>${detail.counts[key] || 0}</span></button>`,
      )
      .join("");
  $("reconStages").innerHTML = Object.entries(detail.stages)
    .map(
      ([name, s]) =>
        `<div class="reconStage ${esc(s.status)}" title="${esc(s.detail)}"><span>${s.status === "complete" ? "✓" : s.status === "running" ? "◌" : "!"} ${esc(name)}</span><small>${esc(s.status)}${s.detail ? " · " + esc(s.detail) : ""}</small></div>`,
    )
    .join("");
  $("reconLog").textContent =
    `Target: ${detail.options.target}\nScope: ${detail.options.subdomains ? "target + subdomains" : "exact target host"}\nRole: ${detail.options.role}\n\n` +
    detail.logs
      .map((l) => `${new Date(l.time).toLocaleTimeString()}  ${l.message}`)
      .join("\n");
  const q = new URLSearchParams({
    job: reconJob,
    category: reconCategory,
    q: $("reconSearch").value,
    offset: reconOffset,
    limit: 100,
  });
  const results = await api("recon/results?" + q);
  if (generation !== reconFetchGeneration) return;
  reconData = results.rows;
  $("visibleCount").textContent = results.total;
  $("reconRecords").innerHTML = results.rows
    .map(
      (r) =>
        `<tr data-recon-record="${r.id}"><td>${esc(reconNames[r.category] || r.category)}</td><td title="${esc(r.title)}">${esc(r.title)}${r.data.possibleSoft404 ? ' <span class="badge">SOFT-404?</span>' : ""}</td><td>${esc(r.data.source || r.data.sources?.join(", ") || "import")}${r.artifact ? " · file" : ""}</td></tr>`,
    )
    .join("");
  $("reconEmpty").hidden = results.total > 0;
  $("reconPageInfo").textContent = results.total
    ? `${reconOffset + 1}–${Math.min(reconOffset + 100, results.total)} of ${results.total} matching records`
    : "No evidence observed in this view. Check scope, filters, and collector statuses.";
  $("reconPrev").disabled = reconOffset === 0;
  $("reconNext").disabled = reconOffset + 100 >= results.total;
}
$("reconNew").onclick = () => {
  $("reconError").textContent = "";
  $("reconSourceSession").innerHTML = (state.sessions || [])
    .map((s) => `<option value="${s.id}">${esc(s.name)}</option>`)
    .join("");
  $("reconSourceSession").value = session;
  if (reconCurrent) $("reconTarget").value = reconCurrent.options.target;
  $("reconDialog").showModal();
};
$("reconForm").onsubmit = async (e) => {
  e.preventDefault();
  $("reconError").textContent = "";
  $("reconStart").disabled = true;
  try {
    const result = await api("recon/start", {
      session: session || undefined,
      target: $("reconTarget").value,
      subdomains: $("reconSubdomains").checked,
      exclude: $("reconExclude").value,
      modules: [...$("reconModules").querySelectorAll("input:checked")].map(
        (i) => i.value,
      ),
      role: $("reconRole").value,
      sourceSession: $("reconSourceSession").value || undefined,
      maxRequests: Number($("reconMaxRequests").value),
      maxPages: Number($("reconMaxPages").value),
      maxHosts: Number($("reconMaxHosts").value),
      delay: Number($("reconDelay").value),
      maxBody: Number($("reconMaxBody").value),
      paths: $("reconPaths").value,
    });
    session = result.session;
    reconSession = session;
    reconJob = result.id;
    reconOffset = 0;
    $("reconDialog").close();
    await refresh();
    toast("Recon started. Evidence appears as collectors finish.");
  } catch (e) {
    $("reconError").textContent = e.message;
  } finally {
    $("reconStart").disabled = false;
  }
};
$("reconRuns").onchange = () => {
  reconJob = $("reconRuns").value;
  reconOffset = 0;
  refreshRecon().catch((e) => toast(e.message));
};
$("reconCategories").onclick = (e) => {
  const b = e.target.closest("[data-category]");
  if (b) {
    reconCategory = b.dataset.category;
    reconOffset = 0;
    refreshRecon().catch((e) => toast(e.message));
  }
};
let reconDebounce;
$("reconSearch").oninput = () => {
  clearTimeout(reconDebounce);
  reconOffset = 0;
  reconDebounce = setTimeout(
    () => refreshRecon().catch((e) => toast(e.message)),
    220,
  );
};
$("reconPrev").onclick = () => {
  reconOffset = Math.max(0, reconOffset - 100);
  refreshRecon().catch((e) => toast(e.message));
};
$("reconNext").onclick = () => {
  reconOffset += 100;
  refreshRecon().catch((e) => toast(e.message));
};
$("reconCancel").onclick = async () => {
  try {
    await api("recon/jobs/" + reconJob + "/cancel", {});
    toast("Stopping collection; completed evidence will be kept.");
    await refreshRecon();
  } catch (e) {
    toast(e.message);
  }
};
function reconExport(filtered) {
  if (!reconJob) return toast("Select a recon run first.");
  const q = new URLSearchParams({
    job: reconJob,
    format: $("reconExportFormat").value,
    token: CAPTURE_TOKEN,
  });
  if (filtered) {
    q.set("category", reconCategory);
    q.set("q", $("reconSearch").value);
  }
  const a = document.createElement("a");
  a.href = "/api/recon/export?" + q;
  a.download = "";
  a.click();
}
$("reconExportFiltered").onclick = () => reconExport(true);
$("reconExportAll").onclick = () => reconExport(false);
$("reconRecords").onclick = async (e) => {
  const tr = e.target.closest("[data-recon-record]");
  if (!tr) return;
  const row = reconData.find((r) => r.id === Number(tr.dataset.reconRecord));
  if (!row) return;
  reconDetail = row;
  $("reconDetailTitle").textContent = row.title;
  $("reconDetailMeta").textContent = JSON.stringify(row.data, null, 2);
  $("reconDownloadArtifact").hidden = !row.artifact;
  $("reconDetailFind").value = "";
  reconPreview = "";
  $("reconDetailBody").textContent = row.artifact
    ? "Loading attached content…"
    : "No attached content.";
  $("reconPreviewNote").textContent = "";
  $("reconDetailDialog").showModal();
  if (row.artifact)
    try {
      const result = await api("recon/preview/" + row.id);
      if (reconDetail?.id !== row.id) return;
      reconPreview = result.text;
      $("reconPreviewNote").textContent =
        `${size(result.bytes)} original${result.truncated ? " · Preview limited to 512 KiB; download the original for full content." : ""}`;
      renderReconPreview();
    } catch (e) {
      $("reconDetailBody").textContent = e.message;
    }
};
function renderReconPreview() {
  const term = $("reconDetailFind").value;
  if (!term) {
    $("reconDetailBody").textContent = reconPreview;
    return;
  }
  const re = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
  let html = "",
    end = 0;
  for (const match of reconPreview.matchAll(re)) {
    html +=
      esc(reconPreview.slice(end, match.index)) +
      "<mark>" +
      esc(match[0]) +
      "</mark>";
    end = match.index + match[0].length;
  }
  html += esc(reconPreview.slice(end));
  $("reconDetailBody").innerHTML = html;
}
$("reconDetailFind").oninput = renderReconPreview;
$("reconDownloadArtifact").onclick = () => {
  if (reconDetail)
    location.href =
      "/api/recon/artifact/" + reconDetail.id + "?token=" + CAPTURE_TOKEN;
};
document
  .querySelectorAll("[data-close]")
  .forEach((b) => (b.onclick = () => $(b.dataset.close).close()));
$("reconWordlist").onchange = async () => {
  const file = $("reconWordlist").files[0];
  if (file) {
    if (file.size > 1048576) return toast("Wordlist must be under 1 MiB.");
    $("reconPaths").value = await file.text();
  }
};
$("reconSourceOpen").onclick = () => {
  $("sourceError").textContent = "";
  $("sourceTarget").value =
    reconCurrent?.options.target || $("reconTarget").value;
  $("reconSourceDialog").showModal();
};
$("reconSourceForm").onsubmit = async (e) => {
  e.preventDefault();
  $("sourceStart").disabled = true;
  $("sourceError").textContent = "";
  try {
    const result = await api("recon/import-source", {
      session: session || undefined,
      target: $("sourceTarget").value,
      location: $("sourceLocation").value,
      maxFiles: Number($("sourceMaxFiles").value),
      maxMB: Number($("sourceMaxMB").value),
      maxFileMB: Number($("sourceMaxFileMB").value),
    });
    session = result.session;
    reconSession = session;
    reconJob = result.id;
    reconOffset = 0;
    $("reconSourceDialog").close();
    await refresh();
  } catch (e) {
    $("sourceError").textContent = e.message;
  } finally {
    $("sourceStart").disabled = false;
  }
};
$("reconHarOpen").onclick = () => {
  $("harError").textContent = "";
  $("harTarget").value = reconCurrent?.options.target || $("reconTarget").value;
  $("reconHarDialog").showModal();
};
$("reconHarForm").onsubmit = async (e) => {
  e.preventDefault();
  $("harStart").disabled = true;
  $("harError").textContent = "";
  try {
    const file = $("harFile").files[0];
    if (!file || file.size > 15 * 1048576)
      throw Error("Choose a HAR file under 15 MiB.");
    const har = JSON.parse(await file.text());
    const result = await api("recon/import-har", {
      session: session || undefined,
      target: $("harTarget").value,
      subdomains: $("harSubdomains").checked,
      role: $("harRole").value,
      mobile: $("harMobile").checked,
      name: file.name,
      har,
    });
    session = result.session;
    reconSession = session;
    reconJob = result.id;
    reconOffset = 0;
    $("reconHarDialog").close();
    await refresh();
    toast(`${result.imported} in-scope requests imported.`);
  } catch (e) {
    $("harError").textContent = e.message;
  } finally {
    $("harStart").disabled = false;
  }
};
$("reconRoles").onclick = async () => {
  try {
    const matrix = await api(
      "recon/roles?session=" + encodeURIComponent(session),
    );
    const roles = [...new Set(matrix.flatMap((r) => Object.keys(r.roles)))];
    $("reconRoleMatrix").innerHTML = matrix.length
      ? `<table><thead><tr><th>Endpoint</th>${roles.map((r) => `<th>${esc(r)}</th>`).join("")}</tr></thead><tbody>${matrix
          .map(
            (row) =>
              `<tr><td title="${esc(row.endpoint)}">${esc(row.endpoint)}</td>${roles
                .map((role) => {
                  const d = row.roles[role];
                  return `<td>${d ? `${d.status} · ${size(d.size)}<br><small>${esc(d.bodyHash.slice(0, 12))}</small>` : "Not observed"}</td>`;
                })
                .join("")}</tr>`,
          )
          .join("")}</tbody></table>`
      : "<p>No account-role snapshots yet. Collect browser evidence or import a HAR with a role label.</p>";
    $("reconRolesDialog").showModal();
  } catch (e) {
    toast(e.message);
  }
};
