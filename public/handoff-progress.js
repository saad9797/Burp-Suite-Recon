let handoffBuildJob = "",
  handoffTracking = false;
let handoffTrackingPromise = null;
function trackHandoffBuild(id) {
  if (handoffTrackingPromise && handoffBuildJob === id)
    return handoffTrackingPromise;
  handoffTrackingPromise = runHandoffTracking(id);
  return handoffTrackingPromise.finally(() => {
    handoffTrackingPromise = null;
  });
}
async function runHandoffTracking(id) {
  handoffBuildJob = id;
  handoffTracking = true;
  $("handoffBuildStatus").hidden = false;
  $("handoffBuildOpen").disabled = true;
  $("handoffBuildCancel").disabled = false;
  try {
    for (;;) {
      const job = await api("handoff/build-jobs/" + id);
      const p = job.progress || {};
      $("handoffBuildStatus").dataset.state = job.status;
      $("handoffBuildStatusText").textContent =
        `${String(job.status === "running" ? p.phase || job.status : job.status).replaceAll("_", " ")}${p.total ? " · " + p.completed + "/" + p.total + " files" : ""}`;
      $("handoffBuildStatusFile").textContent =
        job.error || p.current_file || "";
      if (p.total) {
        $("handoffBuildBar").max = p.total;
        $("handoffBuildBar").value = p.completed;
      } else $("handoffBuildBar").removeAttribute("value");
      if (job.status === "complete") {
        $("handoffBuildStatus").hidden = true;
        return job.result;
      }
      if (job.status !== "running")
        throw Error(job.error || "Build " + job.status);
      await new Promise((r) => setTimeout(r, 500));
    }
  } finally {
    handoffTracking = false;
    handoffBuildJob = "";
    $("handoffBuildOpen").disabled = false;
    $("handoffBuildCancel").disabled = true;
  }
}
$("handoffBuildCancel").onclick = async () => {
  try {
    $("handoffBuildCancel").disabled = true;
    await api("handoff/build-jobs/" + handoffBuildJob + "/cancel", {});
  } catch (e) {
    toast(e.message);
  }
};
async function resumeHandoffBuild() {
  if (handoffTracking) return;
  const jobs = await api(
    "handoff/build-jobs?session=" + encodeURIComponent(session),
  );
  const running = jobs.find((j) => j.status === "running");
  if (!running) {
    const last = jobs[0];
    if (
      last &&
      ["failed", "cancelled", "timed_out", "interrupted"].includes(last.status)
    ) {
      $("handoffBuildStatus").hidden = false;
      $("handoffBuildStatusText").textContent =
        "Previous build: " + last.status.replaceAll("_", " ");
      $("handoffBuildStatusFile").textContent = last.error || "";
      $("handoffBuildCancel").disabled = true;
    }
    return;
  }
  trackHandoffBuild(running.id)
    .then(async (result) => {
      handoffId = result.id;
      handoffSession = result.session;
      await refreshHandoff();
      toast(
        "Handoff finished. Coverage notes explain any bounded or skipped analysis.",
      );
    })
    .catch((e) => toast(e.message));
}
