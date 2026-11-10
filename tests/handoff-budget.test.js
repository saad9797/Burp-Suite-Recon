const { test } = require("node:test");
const assert = require("node:assert/strict");
const Database = require("better-sqlite3");
const crypto = require("node:crypto");
const path = require("node:path");
const fs = require("node:fs/promises");
const os = require("node:os");
const express = require("express");
const { analyzeScripts, workerAnalysis } = require("../handoff-budget");
const { binaryKind, isJavaScript } = require("../media-kind");
const { mountRecon } = require("../recon");
const { mountHandoff } = require("../handoff");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
test("binary WebAssembly is never classified or parsed as JavaScript", async () => {
  assert.equal(
    isJavaScript(
      "https://target.test/app.js",
      "text/html",
      "script",
      Buffer.from("<!DOCTYPE html><html>Access denied</html>"),
    ),
    false,
  );
  assert.equal(
    isJavaScript("https://target.test/lib.wasm", "application/wasm", "script"),
    false,
  );
  assert.equal(
    binaryKind("unknown", "", Buffer.from([0, 97, 115, 109])),
    "webassembly",
  );
  const db = new Database(":memory:");
  db.exec("CREATE TABLE recon_blobs(hash TEXT PRIMARY KEY,body BLOB)");
  const bytes = Buffer.alloc(36 * 1048576);
  Buffer.from([0, 97, 115, 109]).copy(bytes);
  const hash = sha(bytes);
  db.prepare("INSERT INTO recon_blobs VALUES(?,?)").run(hash, bytes);
  const begin = Date.now();
  const { results, stats } = await analyzeScripts({
    db,
    scripts: [{ file: "https://target.test/lib.wasm", artifact: hash }],
    target: "https://target.test",
  });
  assert.equal(stats.non_javascript, 1);
  assert.equal(stats.ast_bytes, 0);
  assert.equal(stats.pattern_bytes, 0);
  assert.equal(results[0].finding.analysis_status, "not_javascript");
  assert.ok(Date.now() - begin < 5000);
  assert.equal(
    db.prepare("SELECT length(body) bytes FROM recon_blobs").get().bytes,
    bytes.length,
  );
  db.close();
});
test("oversized scripts use bounded patterns, hashes deduplicate and persist cache", async () => {
  const db = new Database(":memory:");
  db.exec("CREATE TABLE recon_blobs(hash TEXT PRIMARY KEY,body BLOB)");
  const bytes = Buffer.from(
    'fetch("/api/bounded-route");\n' + " ".repeat(3 * 1048576),
  );
  const hash = sha(bytes);
  db.prepare("INSERT INTO recon_blobs VALUES(?,?)").run(hash, bytes);
  const input = {
    db,
    scripts: [
      { file: "https://target.test/app.js", artifact: hash },
      { file: "https://target.test/app-copy.js", artifact: hash },
    ],
    target: "https://target.test",
  };
  const first = await analyzeScripts(input);
  assert.equal(first.stats.ast_bytes, 0);
  assert.ok(first.stats.pattern_bytes <= 256 * 1024);
  assert.equal(first.stats.deduplicated, 1);
  for (const { script, finding } of first.results) {
    assert.ok(finding.endpoints_found.includes("/api/bounded-route"));
    assert.equal(finding.endpoint_evidence[0].file, script.file);
    assert.equal(finding.bytes, bytes.length);
    assert.ok(finding.analysis_notes.some((n) => n.includes("Only the first")));
  }
  const second = await analyzeScripts(input);
  assert.equal(second.stats.cache_hits, 1);
  assert.equal(second.stats.pattern_bytes, 0);
  assert.equal(second.stats.ast_bytes, 0);
  const inventory = await analyzeScripts({
    ...input,
    scripts: [{ file: "https://target.test/new.js", artifact: hash }],
    analysisProfile: "inventory",
  });
  assert.equal(inventory.stats.cache_hits, 1);
  db.close();
});
test("a non-cooperative parser worker is terminated while the event loop stays responsive", async () => {
  let ticks = 0;
  const interval = setInterval(() => ticks++, 20);
  try {
    await assert.rejects(
      workerAnalysis(
        Buffer.from(""),
        {},
        150,
        path.join(__dirname, "fixtures/slow-js-worker.js"),
      ),
      /hard time limit/,
    );
    assert.ok(ticks >= 2);
  } finally {
    clearInterval(interval);
  }
});
test(
  "production background builds stay responsive, expose progress and cancel safely",
  { timeout: 60000 },
  async () => {
    const filename = path.join(
      os.tmpdir(),
      "traceglass-budget-" + crypto.randomUUID() + ".sqlite",
    );
    const db = new Database(filename);
    db.pragma("journal_mode = WAL");
    db.exec(
      "CREATE TABLE sessions(id TEXT PRIMARY KEY,name TEXT,created TEXT);CREATE TABLE traffic(id INTEGER PRIMARY KEY,session TEXT,url TEXT,method TEXT);CREATE TABLE technologies(session TEXT,origin TEXT,engine TEXT,result TEXT);",
    );
    db.prepare("INSERT INTO sessions VALUES(?,?,?)").run(
      "budget-test",
      "Budget test",
      new Date().toISOString(),
    );
    const app = express();
    app.use(express.json());
    const recon = mountRecon(app, {
      db,
      W: { analyze: () => [], resolve: () => [] },
    });
    const engine = mountHandoff(app, { db });
    app.get("/ping", (req, res) => res.json({ ok: true }));
    app.use((e, req, res, next) => res.status(400).json({ error: e.message }));
    const job = recon.newJob(
      {
        target: "https://target.test/",
        subdomains: false,
        exclude: [],
        modules: [],
      },
      "budget-test",
      "Large saved inputs",
    );
    db.prepare("UPDATE recon_jobs SET status='complete' WHERE id=?").run(job);
    const wasm = Buffer.alloc(36 * 1048576);
    Buffer.from([0, 97, 115, 109]).copy(wasm);
    recon.add(
      job,
      "javascript",
      "https://target.test/crypto.wasm",
      "crypto.wasm",
      {},
      wasm,
    );
    for (let i = 0; i < 12; i++)
      recon.add(
        job,
        "javascript",
        "https://target.test/app-" + i + ".js",
        "app-" + i + ".js",
        {},
        Buffer.from(`fetch('/api/items/${i + 100}');\n` + " ".repeat(100000)),
      );
    const server = app.listen(0, "127.0.0.1");
    await new Promise((r) => server.once("listening", r));
    const base = "http://127.0.0.1:" + server.address().port;
    const api = async (url, body) => {
      const r = await fetch(base + "/api/" + url, {
        method: body ? "POST" : "GET",
        headers: { "content-type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
      assert.equal(r.status, 200, await r.clone().text());
      return r.json();
    };
    try {
      const started = await api("handoff/build-jobs", {
        primary: job,
        jobs: [job],
      });
      let result;
      let heartbeats = 0;
      for (let i = 0; i < 500; i++) {
        const tick = Date.now();
        assert.equal((await fetch(base + "/ping")).status, 200);
        assert.ok(Date.now() - tick < 2000);
        heartbeats++;
        result = await api("handoff/build-jobs/" + started.id);
        if (result.status !== "running") break;
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(result.status, "complete", result.error);
      assert.ok(heartbeats > 1);
      assert.equal(result.result.analysis.non_javascript, 1);
      assert.equal(result.result.counts.js_findings, 12);
      const cancelled = await api("handoff/build-jobs", {
        primary: job,
        jobs: [job],
      });
      await api("handoff/build-jobs/" + cancelled.id + "/cancel", {});
      assert.equal(
        (await api("handoff/build-jobs/" + cancelled.id)).status,
        "cancelled",
      );
      assert.ok(engine.readPackage(result.package_id));
    } finally {
      for (const task of engine.buildJobs.active.values()) task.cancel();
      await new Promise((r) => server.close(r));
      db.close();
      for (const ext of ["", "-wal", "-shm"])
        await fs.rm(filename + ext, { force: true });
    }
  },
);
