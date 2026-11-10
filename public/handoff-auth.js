const authFields = [
  ["authAccountA", "account_a_label"],
  ["authAccountB", "account_b_label"],
  ["authResultA", "account_a_result"],
  ["authResultB", "account_b_result"],
  ["authOwnership", "ownership_notes"],
  ["authNotes", "notes"],
  ["authExpected", "expected_account_b_access"],
  ["authRequired", "auth_required"],
  ["authReviewStatus", "review_status"],
  ["authFlag", "flag"],
];
$("handoffRows").onclick = (e) => {
  const row = e.target.closest("[data-handoff-row]");
  if (!row) return;
  const item = handoffRows[Number(row.dataset.handoffRow)];
  if (handoffMode === "auth_map") {
    handoffAuth = item;
    $("handoffAuthEndpoint").textContent = item.method + " " + item.endpoint;
    $("handoffAuthObservations").textContent = JSON.stringify(
      { params: item.params, observations: item.observations },
      null,
      2,
    );
    for (const [id, key] of authFields) $(id).value = item[key] || "";
    $("authChecklist").innerHTML = item.checklist
      .map(
        (c) =>
          `<label><input type="checkbox" data-auth-check="${esc(c.id)}" ${c.done ? "checked" : ""}>${esc(c.label)}</label>`,
      )
      .join("");
    $("handoffAuthError").textContent = "";
    $("handoffAuthDialog").showModal();
  } else {
    $("handoffOriginal").hidden = !item.original_file;
    $("handoffOriginal").onclick = () =>
      downloadHandoff("artifact/" + item.original_file.split("/").pop());
    $("handoffDetail").textContent = JSON.stringify(item, null, 2);
    $("handoffDetailDialog").showModal();
  }
};
$("handoffAuthForm").onsubmit = async (e) => {
  e.preventDefault();
  $("handoffAuthSave").disabled = true;
  $("handoffAuthError").textContent = "";
  try {
    const review = {};
    for (const [id, key] of authFields) review[key] = $(id).value;
    review.checklist = [
      ...$("authChecklist").querySelectorAll("[data-auth-check]"),
    ].map((c) => ({ id: c.dataset.authCheck, done: c.checked }));
    await api(
      "handoff/packages/" + handoffId + "/auth/" + handoffAuth.id,
      review,
    );
    $("handoffAuthDialog").close();
    await refreshHandoff();
    toast("Manual review saved in the package and summary.");
  } catch (e) {
    $("handoffAuthError").textContent = e.message;
  } finally {
    $("handoffAuthSave").disabled = false;
  }
};
document
  .querySelectorAll(
    "#handoffBuildDialog [data-close],#handoffDetailDialog [data-close],#handoffAuthDialog [data-close]",
  )
  .forEach((b) => (b.onclick = () => $(b.dataset.close).close()));
