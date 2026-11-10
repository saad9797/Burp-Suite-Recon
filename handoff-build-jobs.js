const { Worker } = require("node:worker_threads");
const path = require("node:path");
const crypto = require("node:crypto");
const { profile } = require("./handoff-budget");
function mountBuildJobs(app, { db, build, readPackage, publicPackage }) {
  db.exec(
    "CREATE TABLE IF NOT EXISTS handoff_build_jobs(id TEXT PRIMARY KEY,session TEXT,status TEXT,created TEXT,updated TEXT,input TEXT,progress TEXT,package_id TEXT,error TEXT);",
  );
  db.prepare(
    "UPDATE handoff_build_jobs SET status='interrupted',error='Server restarted before this build completed.' WHERE status='running'",
  ).run();
  const active = new Map();
  const update = (id, changes) => {
    const row = db
      .prepare("SELECT * FROM handoff_build_jobs WHERE id=?")
      .get(id);
    if (!row) return;
    const next = { ...row, ...changes, updated: new Date().toISOString() };
    db.prepare(
      "UPDATE handoff_build_jobs SET status=?,updated=?,progress=?,package_id=?,error=? WHERE id=?",
    ).run(
      next.status,
      next.updated,
      next.progress,
      next.package_id,
      next.error,
      id,
    );
  };
  const get = (id) => {
    const row = db
      .prepare(
        "SELECT id,session,status,created,updated,progress,package_id,error FROM handoff_build_jobs WHERE id=?",
      )
      .get(id);
    if (!row) throw Error("Unknown handoff build.");
    return { ...row, progress: JSON.parse(row.progress) };
  };
  function start(input) {
    if (active.size)
      throw Error(
        "A handoff is already building. Wait for it or cancel it first.",
      );
    if (
      !Array.isArray(input.jobs) ||
      !input.jobs.length ||
      input.jobs.length > 100
    )
      throw Error("Select 1–100 finished recon runs.");
    const anchor = db
      .prepare("SELECT session,status FROM recon_jobs WHERE id=?")
      .get(input.primary || input.jobs[0]);
    if (!anchor) throw Error("Unknown primary recon run.");
    const id = crypto.randomUUID(),
      now = new Date().toISOString();
    db.prepare("INSERT INTO handoff_build_jobs VALUES(?,?,?,?,?,?,?,?,?)").run(
      id,
      anchor.session,
      "running",
      now,
      now,
      JSON.stringify(input),
      JSON.stringify({ phase: "starting", completed: 0, total: 0 }),
      null,
      null,
    );
    let worker = null,
      settled = false,
      timer;
    const budget = profile(input.analysisProfile);
    let resolveDone, rejectDone;
    const done = new Promise((r, j) => {
      resolveDone = r;
      rejectDone = j;
    });
    done.catch(() => {});
    const finish = (error, pkgId) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (worker) worker.terminate().catch(() => {});
      active.delete(id);
      if (error) {
        update(id, {
          status: error.cancelled
            ? "cancelled"
            : error.timedOut
              ? "timed_out"
              : "failed",
          error: error.message,
        });
        rejectDone(error);
      } else {
        update(id, {
          status: "complete",
          package_id: pkgId,
          progress: JSON.stringify({ ...get(id).progress, phase: "complete" }),
        });
        resolveDone(readPackage(pkgId));
      }
    };
    const progress = (p) => update(id, { progress: JSON.stringify(p) });
    active.set(id, {
      done,
      cancel: () =>
        finish(
          Object.assign(
            Error(
              "Build cancelled. Saved recon evidence and previous packages are unchanged.",
            ),
            { cancelled: true },
          ),
        ),
    });
    timer = setTimeout(
      () =>
        finish(
          Object.assign(
            Error(
              `Build reached its ${budget.packageMs / 1000}s hard deadline. Try the quick or inventory-only profile; no existing evidence was removed.`,
            ),
            { timedOut: true },
          ),
        ),
      budget.packageMs,
    );
    if (db.name !== ":memory:" && db.name !== "") {
      worker = new Worker(path.join(__dirname, "handoff-build-worker.js"), {
        workerData: { database: path.resolve(db.name), input },
        resourceLimits: { maxOldGenerationSizeMb: 512, stackSizeMb: 8 },
      });
      worker.on("message", (m) => {
        if (settled) return;
        if (m.progress) progress(m.progress);
        else if (m.error) finish(Error(m.error));
        else if (m.packageId) finish(null, m.packageId);
      });
      worker.on("error", finish);
      worker.on("exit", (code) => {
        if (!settled)
          finish(
            Error("Build worker exited without completing (" + code + ")."),
          );
      });
    } else {
      Promise.resolve()
        .then(() => build(input, progress))
        .then((row) => finish(null, row.id), finish);
    }
    return { id, done };
  }
  app.post("/api/handoff/build-jobs", (req, res, next) => {
    try {
      res.json({ id: start(req.body).id });
    } catch (e) {
      next(e);
    }
  });
  app.get("/api/handoff/build-jobs", (req, res) =>
    res.json(
      db
        .prepare(
          "SELECT id,session,status,created,updated,progress,package_id,error FROM handoff_build_jobs WHERE session=? ORDER BY created DESC,rowid DESC LIMIT 10",
        )
        .all(req.query.session || "")
        .map((r) => ({ ...r, progress: JSON.parse(r.progress) })),
    ),
  );
  app.get("/api/handoff/build-jobs/:id", (req, res, next) => {
    try {
      const row = get(req.params.id);
      res.json({
        ...row,
        result: row.package_id
          ? publicPackage(readPackage(row.package_id))
          : null,
      });
    } catch (e) {
      next(e);
    }
  });
  app.post("/api/handoff/build-jobs/:id/cancel", (req, res, next) => {
    try {
      get(req.params.id);
      active.get(req.params.id)?.cancel();
      res.json(get(req.params.id));
    } catch (e) {
      next(e);
    }
  });
  app.post("/api/handoff/build", async (req, res, next) => {
    try {
      const job = start(req.body);
      res.json(publicPackage(await job.done));
    } catch (e) {
      next(e);
    }
  });
  return { start, get, active };
}
module.exports = { mountBuildJobs };
