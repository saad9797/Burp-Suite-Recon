const { test } = require("node:test");
const assert = require("node:assert/strict");
const express = require("express");
const Database = require("better-sqlite3");
const http = require("node:http");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");
const { mountRecon, inScope, optionsFrom } = require("../recon");

test("scope normalization is precise, including ports and exclusions", () => {
  const o = optionsFrom({
    target: "https://example.com:8443",
    subdomains: true,
    exclude: "admin.example.com\n/logout",
  });
  assert.equal(inScope("https://api.example.com:8443/a", o), true);
  assert.equal(inScope("https://evil-example.com:8443", o), false);
  assert.equal(inScope("https://example.com.evil.test:8443", o), false);
  assert.equal(inScope("https://example.com:9000", o), false);
  assert.equal(inScope("https://admin.example.com:8443", o), false);
  assert.equal(inScope("https://example.com:8443/logout", o), false);
});

test("recon pipeline, evidence search, HAR, source, cancellation and UI", async () => {
  const app = express();
  app.use(express.json({ limit: "20mb" }));
  app.get("/bootstrap.js", (req, res) =>
    res.type("js").send('window.CAPTURE_TOKEN="test"'),
  );
  app.use(express.static("public"));
  const db = new Database(":memory:");
  db.exec(
    "CREATE TABLE sessions(id TEXT PRIMARY KEY,name TEXT,created TEXT); CREATE TABLE traffic(id INTEGER PRIMARY KEY,session TEXT,url TEXT,method TEXT,status INTEGER,type TEXT,started TEXT,duration REAL,requestHeaders TEXT,requestBody TEXT,responseHeaders TEXT,body BLOB,text TEXT,error TEXT,isjs INTEGER); CREATE TABLE technologies(session TEXT,origin TEXT,engine TEXT,result TEXT);",
  );
  db.prepare("INSERT INTO sessions VALUES(?,?,?)").run(
    "recon-test",
    "Recon test",
    new Date().toISOString(),
  );
  const requested = [];
  db.prepare(
    "INSERT INTO traffic(session,url,method,status,type,requestHeaders,requestBody,responseHeaders,body,text,isjs) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
  ).run(
    "recon-test",
    "http://example.test/browser-captured.js",
    "GET",
    200,
    "script",
    "{}",
    "",
    JSON.stringify({ "content-type": "application/javascript" }),
    Buffer.from('window.snapshot="snapshot-needle";'),
    'window.snapshot="snapshot-needle";',
    1,
  );
  const fixture = http.createServer((req, res) => {
    requested.push(req.url);
    res.setHeader("content-type", "text/html");
    if (req.url === "/") {
      res.end(
        '<html><title>Recon fixture</title><meta name="generator" content="WordPress 6.0"><a href="/next">next</a><a href="http://outside.test/leak">external</a><script src="/app.js"></script><form action="/submit" method="POST"></form></html>',
      );
    } else if (req.url === "/app.js") {
      res.setHeader("content-type", "application/javascript");
      res.end('fetch("/api/hidden"); const secretKey="js-search-needle";');
    } else if (req.url === "/swagger.json") {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          openapi: "3.0.0",
          info: { title: "Fixture" },
          paths: { "/api/items": { get: {} } },
        }),
      );
    } else if (req.url === "/next") {
      res.writeHead(302, { location: "http://outside.test/redirect" });
      res.end();
    } else if (req.url === "/graphql") {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({ data: { __schema: { types: [{ name: "Query" }] } } }),
      );
    } else {
      res.statusCode = 404;
      res.end("not found");
    }
  });
  await new Promise((r) => fixture.listen(0, "127.0.0.1", r));
  for (const [url, referrer, body] of [
    [
      "https://cdn.vendor.test/dep.js",
      "http://example.test/",
      'window.dep="passive-dependency-needle";',
    ],
    [
      "https://unrelated.test/other.js",
      "https://unrelated.test/",
      'window.unrelated="unrelated-js-needle";',
    ],
  ])
    db.prepare(
      "INSERT INTO traffic(session,url,method,status,type,requestHeaders,requestBody,responseHeaders,body,text,isjs) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
    ).run(
      "recon-test",
      url,
      "GET",
      200,
      "script",
      JSON.stringify({ referer: referrer }),
      "",
      JSON.stringify({ "content-type": "application/javascript" }),
      Buffer.from(body),
      body,
      1,
    );
  const baseFixture = "http://127.0.0.1:" + fixture.address().port;
  let outsideRequests = 0;
  const fetcher = async (url, init) => {
    const u = new URL(url);
    if (u.hostname.endsWith("example.test"))
      return fetch(baseFixture + u.pathname + u.search, init);
    if (u.hostname === "crt.sh")
      return new Response(
        JSON.stringify([{ name_value: "api.example.test\n*.example.test" }]),
      );
    if (u.hostname === "web.archive.org")
      return new Response(
        JSON.stringify([
          ["original", "timestamp", "statuscode", "mimetype"],
          ["http://example.test/old", "20200101", "200", "text/html"],
        ]),
      );
    if (
      u.hostname === "index.commoncrawl.org" &&
      u.pathname === "/collinfo.json"
    )
      return new Response(
        JSON.stringify([
          { "cdx-api": "https://index.commoncrawl.org/test-index" },
        ]),
      );
    if (u.hostname === "index.commoncrawl.org")
      return new Response(
        JSON.stringify({
          url: "http://example.test/ancient",
          status: "200",
          timestamp: "20200101",
        }),
      );
    if (u.hostname === "stat.ripe.net")
      return new Response(
        JSON.stringify({ data: { prefixes: [{ prefix: "192.0.2.0/24" }] } }),
      );
    if (u.hostname === "rdap.org")
      return new Response("unavailable", { status: 403 });
    if (u.hostname === "rdap.net")
      return new Response(
        JSON.stringify({
          name: "TEST-NET",
          startAddress: "192.0.2.0",
          endAddress: "192.0.2.255",
        }),
      );
    outsideRequests++;
    throw Error("Unexpected outside-scope fetch " + u);
  };
  const resolver = {
    resolve: async (host, type) => {
      if (type === "A") return ["192.0.2.1"];
      if (host.endsWith("cymru.com"))
        return [["64496 | 192.0.2.0/24 | ZZ | test"]];
      const e = Error("No data");
      e.code = "ENODATA";
      throw e;
    },
  };
  const W = require("../vendor/wappalyzer/src/wappalyzer");
  const syncFS = require("node:fs");
  W.setTechnologies(
    Object.assign(
      {},
      ...syncFS
        .readdirSync("vendor/wappalyzer/src/technologies")
        .filter((f) => f.endsWith(".json"))
        .map((f) =>
          JSON.parse(
            syncFS.readFileSync("vendor/wappalyzer/src/technologies/" + f),
          ),
        ),
    ),
  );
  W.setCategories(require("../vendor/wappalyzer/src/categories.json"));
  const recon = mountRecon(app, {
    db,
    W,
    externalFetch: fetcher,
    dnsResolver: resolver,
  });
  app.get("/api/state", (req, res) =>
    res.json({
      active: null,
      paused: false,
      sessions: db.prepare("SELECT *,0 count FROM sessions").all(),
    }),
  );
  app.get("/api/intercept", (req, res) =>
    res.json({ enabled: false, queue: [] }),
  );
  app.get("/api/traffic", (req, res) => res.json({ rows: [], total: 0 }));
  app.use((err, req, res, next) =>
    res.status(400).json({ error: err.message }),
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
  const waitJob = async (id) => {
    for (let n = 0; n < 500; n++) {
      const job = await api("recon/jobs/" + id);
      if (!["queued", "running"].includes(job.status)) return job;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw Error("Recon did not complete");
  };
  let browser, temp;
  try {
    const started = await api("recon/start", {
      session: "recon-test",
      target: "http://example.test",
      subdomains: true,
      modules: [
        "browser",
        "ct",
        "archives",
        "dns",
        "rdap",
        "probe",
        "crawl",
        "paths",
        "graphql",
      ],
      paths: "swagger.json\nadmin",
      maxRequests: 25,
      maxHosts: 3,
      delay: 50,
    });
    const job = await waitJob(started.id);
    assert.equal(job.status, "complete", JSON.stringify(job.stages));
    for (const category of [
      "subdomains",
      "hosts",
      "archives",
      "infrastructure",
      "dns",
      "headers",
      "technologies",
      "javascript",
      "endpoints",
      "api",
      "traffic",
      "integrations",
    ])
      assert.ok(job.counts[category] > 0, category);
    assert.equal(outsideRequests, 0);
    assert.equal(job.stages["Browser evidence"].status, "complete");
    assert.equal(
      (
        await api(
          "recon/results?job=" +
            job.id +
            "&category=javascript&q=passive-dependency-needle",
        )
      ).total,
      1,
    );
    assert.equal(
      (
        await api(
          "recon/results?job=" +
            job.id +
            "&category=javascript&q=unrelated-js-needle",
        )
      ).total,
      0,
    );
    assert.equal(
      (
        await api(
          "recon/results?job=" +
            job.id +
            "&category=javascript&q=snapshot-needle",
        )
      ).total,
      1,
    );
    assert.ok(!requested.includes("/submit"));
    assert.ok(!requested.includes("/old"));
    const js = await api(
      "recon/results?job=" + job.id + "&category=javascript&q=js-search-needle",
    );
    assert.equal(js.total, 1);
    assert.equal(
      (await api("recon/results?job=" + job.id + "&q=%25")).total,
      0,
    );
    const preview = await api("recon/preview/" + js.rows[0].id);
    assert.match(preview.text, /js-search-needle/);
    const exportJSON = await api(
      "recon/export?job=" + job.id + "&category=javascript&q=js-search-needle",
    );
    assert.equal(exportJSON.records.length, 1);
    assert.match(
      Buffer.from(exportJSON.records[0].bodyBase64, "base64").toString(),
      /js-search-needle/,
    );
    const zip = await fetch(
      base + "/api/recon/export?job=" + job.id + "&format=zip",
    );
    assert.equal(
      Buffer.from(await zip.arrayBuffer()).readUInt32LE(),
      0x04034b50,
    );
    const har = {
      log: {
        entries: [
          {
            request: {
              url: "http://example.test/account",
              method: "GET",
              headers: [],
            },
            response: {
              status: 200,
              headers: [{ name: "Content-Type", value: "application/json" }],
              content: { text: '{"user":123}' },
            },
            time: 10,
          },
          {
            request: { url: "http://outside.test/private", method: "GET" },
            response: {},
          },
        ],
      },
    };
    const imported = await api("recon/import-har", {
      session: "recon-test",
      target: "http://example.test",
      role: "member",
      mobile: true,
      har,
    });
    assert.equal(imported.imported, 1);
    await api("recon/import-har", {
      session: "recon-test",
      target: "http://example.test",
      role: "admin",
      har,
    });
    const matrix = await api("recon/roles?session=recon-test");
    assert.equal(
      Object.keys(matrix.find((r) => r.endpoint.includes("/account")).roles)
        .length,
      2,
    );
    assert.equal((await api("recon/jobs/" + imported.id)).counts.mobile, 1);
    temp = await fs.mkdtemp(path.join(os.tmpdir(), "traceglass-recon-test-"));
    await fs.mkdir(path.join(temp, "src"));
    await fs.mkdir(path.join(temp, ".github", "workflows"), {
      recursive: true,
    });
    await fs.mkdir(path.join(temp, "migrations"));
    await fs.mkdir(path.join(temp, "tests"));
    await fs.writeFile(
      path.join(temp, "package.json"),
      JSON.stringify({ dependencies: { express: "5.0.0" } }),
    );
    await fs.writeFile(
      path.join(temp, "src", "auth.js"),
      'app.get("/api/private", requireAuth); const password="fixture-secret-password";',
    );
    await fs.writeFile(
      path.join(temp, ".env.example"),
      'API_KEY="fixture-secret-123456"',
    );
    await fs.writeFile(
      path.join(temp, "migrations", "001.sql"),
      "CREATE TABLE users(id integer);",
    );
    await fs.writeFile(
      path.join(temp, "tests", "auth.test.js"),
      'test("permissions",()=>{});',
    );
    await fs.writeFile(
      path.join(temp, ".github", "workflows", "build.yml"),
      "name: build",
    );
    const execute = require("node:util").promisify(
      require("node:child_process").execFile,
    );
    await execute("git", ["-C", temp, "init"]);
    await execute("git", ["-C", temp, "add", "."]);
    await execute("git", [
      "-C",
      temp,
      "-c",
      "core.hooksPath=" + path.join(temp, "no-hooks"),
      "-c",
      "user.name=Traceglass Test",
      "-c",
      "user.email=test@example.invalid",
      "commit",
      "-m",
      "Fixture source",
    ]);
    const source = await api("recon/import-source", {
      session: "recon-test",
      target: "http://example.test",
      location: temp,
    });
    const sourceJob = await waitJob(source.id);
    assert.equal(sourceJob.status, "partial");
    for (const category of [
      "source",
      "dependencies",
      "configuration",
      "schema",
      "authcode",
      "routes",
      "tests",
      "cicd",
      "secrets",
      "git",
    ])
      assert.ok(sourceJob.counts[category] > 0, category);
    assert.equal(sourceJob.stages["Git history"].status, "complete");
    const bundle = await api(
      "recon/results?job=" + source.id + "&category=git&q=bundle",
    );
    assert.ok(bundle.rows.some((r) => r.key === "bundle"));
    const secret = await api(
      "recon/results?job=" + source.id + "&category=secrets",
    );
    assert.ok(!JSON.stringify(secret).includes("fixture-secret-password"));
    const cancelled = await api("recon/start", {
      session: "recon-test",
      target: "http://example.test",
      modules: ["paths"],
      paths: Array.from({ length: 100 }, (_, i) => "path-" + i).join("\n"),
      delay: 500,
    });
    await api("recon/jobs/" + cancelled.id + "/cancel", {});
    assert.equal((await waitJob(cancelled.id)).status, "cancelled");
    browser = await chromium.launch({ headless: true });
    const view = await browser.newPage({
      viewport: { width: 1550, height: 1100 },
    });
    const errors = [];
    view.on("pageerror", (e) => errors.push(e.message));
    await view.goto(base);
    await view.locator('[data-tab="recon"]').click();
    await view.waitForFunction(
      () => document.querySelectorAll("#reconRuns option").length > 1,
    );
    await view.locator("#reconRuns").selectOption(job.id);
    await view.waitForTimeout(300);
    await view.locator('[data-category="javascript"]').click();
    await view.locator("#reconSearch").fill("js-search-needle");
    await view.waitForTimeout(400);
    await view.locator("#reconRecords tr").first().click();
    await view.waitForFunction(() =>
      document
        .getElementById("reconDetailBody")
        .textContent.includes("js-search-needle"),
    );
    await view.locator('[data-close="reconDetailDialog"]').click();
    await view.screenshot({ path: "test-results/recon.png" });
    assert.deepEqual(errors, []);
  } finally {
    if (browser) await browser.close();
    for (const task of recon.running.values()) task.controller.abort();
    await Promise.allSettled([...recon.running.values()].map((t) => t.promise));
    await new Promise((r) => server.close(r));
    await new Promise((r) => fixture.close(r));
    db.close();
    if (temp) {
      const resolved = path.resolve(temp);
      assert.equal(path.dirname(resolved), path.resolve(os.tmpdir()));
      assert.ok(path.basename(resolved).startsWith("traceglass-recon-test-"));
      await fs.rm(resolved, { recursive: true, force: true });
    }
  }
});
