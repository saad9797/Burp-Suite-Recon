const express = require("express");
const { parsePort, httpxBinary } = require("./runtime");
const port = parsePort(process.env.PORT);
const { chromium } = require("playwright");
const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFile } = require("child_process");
const archiver = require("archiver");
const { isJavaScript } = require("./media-kind");
const W = require("./vendor/wappalyzer/src/wappalyzer");
W.setTechnologies(
  Object.assign(
    {},
    ...fs
      .readdirSync("vendor/wappalyzer/src/technologies")
      .filter((f) => f.endsWith(".json"))
      .map((f) =>
        JSON.parse(fs.readFileSync("vendor/wappalyzer/src/technologies/" + f)),
      ),
  ),
);
W.setCategories(require("./vendor/wappalyzer/src/categories.json"));
fs.mkdirSync("data", { recursive: true });
const db = new Database(process.env.TRACEGLASS_DB || "data/capture.sqlite");
db.pragma("journal_mode = WAL");
db.exec(
  `CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,name TEXT,created TEXT); CREATE TABLE IF NOT EXISTS traffic(id INTEGER PRIMARY KEY,session TEXT,url TEXT,method TEXT,status INTEGER,type TEXT,started TEXT,duration REAL,requestHeaders TEXT,requestBody TEXT,responseHeaders TEXT,body BLOB,text TEXT,error TEXT,isjs INTEGER DEFAULT 0); CREATE TABLE IF NOT EXISTS technologies(session TEXT,origin TEXT,engine TEXT,result TEXT,PRIMARY KEY(session,origin,engine));`,
);
const trafficColumns = db
  .prepare("PRAGMA table_info(traffic)")
  .all()
  .map((c) => c.name);
if (!trafficColumns.includes("requestBase64"))
  db.exec(
    "ALTER TABLE traffic ADD COLUMN requestBase64 TEXT; ALTER TABLE traffic ADD COLUMN requestEncoding TEXT DEFAULT 'utf8';",
  );
const app = express();
db.prepare(
  "UPDATE traffic SET isjs=0 WHERE isjs=1 AND lower(coalesce(json_extract(responseHeaders,'$.\"content-type\"'),'')) LIKE 'application/wasm%'",
).run();
const token = crypto.randomBytes(24).toString("hex");
app.use((req, res, next) => {
  if (
    req.headers.host !== `127.0.0.1:${server.address()?.port}` ||
    req.headers["sec-fetch-site"] === "cross-site"
  )
    return res.sendStatus(403);
  if (
    req.headers.origin &&
    req.headers.origin !== `http://127.0.0.1:${server.address()?.port}`
  )
    return res.sendStatus(403);
  if (
    req.path.startsWith("/api") &&
    req.headers["x-capture-token"] !== token &&
    req.query.token !== token
  )
    return res.sendStatus(403);
  next();
});
app.use(express.json({ limit: "20mb" }));
app.get("/bootstrap.js", (req, res) =>
  res.type("js").send(`window.CAPTURE_TOKEN=${JSON.stringify(token)}`),
);
app.use(express.static("public"));
let active = null,
  context = null,
  paused = false;
const pending = new Set();
const requestIds = new WeakMap();
const requestOverrides = new WeakMap();
const run = (sql, ...args) => db.prepare(sql).run(...args);
const interceptor = require("./workbench").mountWorkbench(app, {
  db,
  getContext: () => context,
  getActive: () => active,
  onForward: (req, spec) => {
    const managed = Object.fromEntries(
      Object.entries(req.headers()).filter(([name]) =>
        ["cookie", "host"].includes(name),
      ),
    );
    const headers = { ...managed, ...spec.headers };
    if (spec.body.length) headers["content-length"] = String(spec.body.length);
    requestOverrides.set(req, headers);
    const id = requestIds.get(req);
    if (id)
      run(
        "UPDATE traffic SET url=?,method=?,requestHeaders=?,requestBody=?,requestBase64=?,requestEncoding=? WHERE id=?",
        spec.url,
        spec.method,
        JSON.stringify(headers),
        spec.body.toString("utf8"),
        spec.body.toString("base64"),
        Buffer.from(spec.body.toString("utf8")).equals(spec.body)
          ? "utf8"
          : "base64",
        id,
      );
  },
});
function filter(q) {
  const clauses = ["session = ?"];
  const args = [q.session || ""];
  for (const [key, col] of [
    ["method", "method"],
    ["host", "url"],
    ["status", "status"],
  ])
    if (q[key]) {
      clauses.push(key === "host" ? "url LIKE ? ESCAPE '\\'" : `${col} = ?`);
      args.push(key === "host" ? "%" + escapeLike(q[key]) + "%" : q[key]);
    }
  if (q.js === "1") clauses.push("isjs = 1");
  if (q.q) {
    clauses.push(
      "(url LIKE ? ESCAPE '\\' OR requestHeaders LIKE ? ESCAPE '\\' OR requestBody LIKE ? ESCAPE '\\' OR responseHeaders LIKE ? ESCAPE '\\' OR text LIKE ? ESCAPE '\\')",
    );
    args.push(...Array(5).fill("%" + escapeLike(q.q) + "%"));
  }
  return { where: clauses.join(" AND "), args };
}
function escapeLike(s) {
  return s.replace(/[\\%_]/g, "\\$&");
}
function rows(q, all = false) {
  const { where, args } = filter(q);
  return db
    .prepare(
      `SELECT ${all ? "*" : "id,url,method,status,type,started,duration,error,isjs,length(body) AS size"} FROM traffic WHERE ${where} ORDER BY id DESC ${all ? "" : "LIMIT ? OFFSET ?"}`,
    )
    .all(
      ...args,
      ...(all
        ? []
        : [
            Math.min(500, Number(q.limit) || 200),
            Math.max(0, Number(q.offset) || 0),
          ]),
    );
}
function track(p) {
  pending.add(p);
  p.catch(console.error).finally(() => pending.delete(p));
}
function detect(session, origin, items) {
  try {
    const prev = db
      .prepare(
        "SELECT result FROM technologies WHERE session=? AND origin=? AND engine=?",
      )
      .get(session, origin, "Wappalyzer");
    const found = W.resolve(W.analyze(items)).map((x) => ({
      name: x.name,
      version: x.version,
      confidence: x.confidence,
      categories: x.categories.map((c) => c.name),
    }));
    const merged = new Map(
      JSON.parse(prev?.result || "[]").map((x) => [x.name, x]),
    );
    for (const x of found) merged.set(x.name, x);
    run(
      "INSERT OR REPLACE INTO technologies VALUES(?,?,?,?)",
      session,
      origin,
      "Wappalyzer",
      JSON.stringify([...merged.values()]),
    );
  } catch (e) {
    console.error("Fingerprint:", e.message);
  }
}
async function launch(id, channel, headless = false) {
  if (context)
    throw Error("Close the current browser before launching another session.");
  paused = false;
  context = await chromium.launchPersistentContext(
    path.resolve("data/profiles", id),
    {
      headless,
      channel: channel === "chrome" ? "chrome" : undefined,
      serviceWorkers: "block",
    },
  );
  active = id;
  const ctx = context;
  await interceptor.attach(ctx, id);
  ctx.on("request", (req) => {
    if (paused) return;
    const result = run(
      "INSERT INTO traffic(session,url,method,type,started,requestHeaders,requestBody) VALUES(?,?,?,?,?,?,?)",
      id,
      req.url(),
      req.method(),
      req.resourceType(),
      new Date().toISOString(),
      JSON.stringify(req.headers()),
      req.postData() || "",
    );
    requestIds.set(req, Number(result.lastInsertRowid));
    const bytes = req.postDataBuffer() || Buffer.alloc(0);
    run(
      "UPDATE traffic SET requestBase64=?,requestEncoding=? WHERE id=?",
      bytes.toString("base64"),
      Buffer.from(bytes.toString("utf8")).equals(bytes) ? "utf8" : "base64",
      Number(result.lastInsertRowid),
    );
    track(
      req
        .allHeaders()
        .then((h) =>
          run(
            "UPDATE traffic SET requestHeaders=? WHERE id=?",
            JSON.stringify(requestOverrides.get(req) || h),
            requestIds.get(req),
          ),
        ),
    );
  });
  ctx.on("response", (response) => {
    const req = response.request(),
      rid = requestIds.get(req);
    if (!rid) return;
    track(
      (async () => {
        const headers = await response.allHeaders();
        let isjs = isJavaScript(
          req.url(),
          headers["content-type"] || "",
          req.resourceType(),
        );
        run(
          "UPDATE traffic SET status=?,responseHeaders=?,isjs=? WHERE id=?",
          response.status(),
          JSON.stringify(headers),
          +isjs,
          rid,
        );
        let body,
          text = "",
          error = "";
        try {
          body = await response.body();
          if (
            isjs &&
            !isJavaScript(
              req.url(),
              headers["content-type"] || "",
              req.resourceType(),
              body.subarray(0, 160),
            )
          ) {
            isjs = false;
            run("UPDATE traffic SET isjs=0 WHERE id=?", rid);
          }
          if (
            isjs ||
            /text|json|xml|html|svg|form|graphql/i.test(
              headers["content-type"] || "",
            )
          )
            text = body.toString("utf8");
        } catch (e) {
          error = "Body unavailable: " + e.message;
        }
        run(
          "UPDATE traffic SET body=?,text=?,error=?,duration=? WHERE id=?",
          body || null,
          text,
          error,
          Math.max(
            0,
            Date.now() -
              Date.parse(
                db.prepare("SELECT started FROM traffic WHERE id=?").get(rid)
                  .started,
              ),
          ),
          rid,
        );
        if (req.resourceType() === "document" || isjs)
          detect(id, new URL(req.url()).origin, {
            url: req.url(),
            headers: Object.fromEntries(
              Object.entries(headers).map(([k, v]) => [k, [v]]),
            ),
            html: req.resourceType() === "document" ? text : "",
            scripts: isjs ? text : "",
            scriptSrc: isjs ? [req.url()] : [],
          });
      })(),
    );
  });
  ctx.on("requestfailed", (req) => {
    const rid = requestIds.get(req);
    if (rid)
      run(
        "UPDATE traffic SET error=? WHERE id=?",
        req.failure()?.errorText || "Request failed",
        rid,
      );
  });
  const observePage = (page) =>
    page.on("domcontentloaded", () =>
      track(
        (async () => {
          try {
            const items = await page.evaluate(() => ({
              url: location.href,
              html: document.documentElement.outerHTML,
              scriptSrc: [...document.scripts]
                .map((s) => s.src)
                .filter(Boolean),
              meta: [...document.querySelectorAll("meta[name]")].reduce(
                (a, m) => {
                  (a[m.name.toLowerCase()] ??= []).push(m.content);
                  return a;
                },
                {},
              ),
            }));
            detect(id, new URL(page.url()).origin, items);
          } catch {}
        })(),
      ),
    );
  ctx.on("page", observePage);
  ctx.pages().forEach(observePage);
  ctx.on("close", () => {
    if (context === ctx) {
      context = null;
      active = null;
    }
  });
  return ctx;
}
app.get("/api/state", (req, res) =>
  res.json({
    active,
    paused,
    sessions: db
      .prepare(
        "SELECT s.*, (SELECT count(*) FROM traffic t WHERE t.session=s.id) count FROM sessions s ORDER BY created DESC",
      )
      .all(),
  }),
);
app.post("/api/launch", async (req, res, next) => {
  try {
    if (context) throw Error("Close the current capture browser first.");
    const url = req.body.url || "about:blank";
    if (url !== "about:blank" && !/^https?:\/\//i.test(url))
      throw Error("Enter an http:// or https:// URL");
    if (url !== "about:blank") new URL(url);
    let id = req.body.session;
    if (id && !db.prepare("SELECT id FROM sessions WHERE id=?").get(id))
      throw Error("Unknown session");
    if (!id) {
      id = crypto.randomUUID();
      run(
        "INSERT INTO sessions VALUES(?,?,?)",
        id,
        String(req.body.name || "Untitled capture").slice(0, 120),
        new Date().toISOString(),
      );
    }
    const ctx = await launch(id, req.body.browser);
    res.json({ id });
    const page = ctx.pages()[0] || (await ctx.newPage());
    page.goto(url).catch(() => {});
  } catch (e) {
    next(e);
  }
});
app.post("/api/pause", (req, res) => {
  paused = !paused;
  res.json({ paused });
});
app.post("/api/stop", async (req, res, next) => {
  try {
    await interceptor.dropAll();
    if (context) await context.close();
    await Promise.allSettled([...pending]);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});
app.get("/api/traffic", (req, res) => {
  const { where, args } = filter(req.query);
  res.json({
    rows: rows(req.query),
    total: db
      .prepare(`SELECT count(*) count FROM traffic WHERE ${where}`)
      .get(...args).count,
  });
});
app.get("/api/traffic/:id", (req, res) => {
  const row = db.prepare("SELECT * FROM traffic WHERE id=?").get(req.params.id);
  if (!row) return res.sendStatus(404);
  res.json({
    ...row,
    body: undefined,
    base64: row.body?.toString("base64"),
    size: row.body?.length || 0,
  });
});
app.get("/api/body/:id", (req, res) => {
  const row = db.prepare("SELECT * FROM traffic WHERE id=?").get(req.params.id);
  if (!row) return res.sendStatus(404);
  res
    .set(
      "Content-Disposition",
      `attachment; filename="capture-${row.id}${row.isjs ? ".js" : ".bin"}"`,
    )
    .type("application/octet-stream")
    .send(row.body || Buffer.alloc(0));
});
app.get("/api/technologies", (req, res) =>
  res.json(
    db
      .prepare("SELECT * FROM technologies WHERE session=?")
      .all(req.query.session)
      .map((r) => ({ ...r, result: JSON.parse(r.result) })),
  ),
);
app.post("/api/httpx", async (req, res, next) => {
  try {
    const urls = db
      .prepare(
        "SELECT DISTINCT url FROM traffic WHERE session=? AND type='document'",
      )
      .all(req.body.session)
      .map((r) => new URL(r.url).origin);
    if (!urls.length) throw Error("Capture a page first.");
    const bin = httpxBinary();
    const output = await new Promise((resolve, reject) => {
      const child = execFile(
        bin,
        ["-silent", "-json", "-tech-detect", "-no-color"],
        { timeout: 120000, maxBuffer: 16 * 1024 * 1024, windowsHide: true },
        (e, out, err) =>
          e
            ? reject(
                Error(
                  `ProjectDiscovery httpx failed: ${err || e.message}. Install ProjectDiscovery httpx or set HTTPX_PATH; see README.md.`,
                ),
              )
            : resolve(out),
      );
      child.stdin.end([...new Set(urls)].join("\n"));
    });
    let count = 0;
    for (const line of output.split("\n").filter(Boolean)) {
      const r = JSON.parse(line);
      const origin = new URL(r.url || r.input).origin;
      run(
        "INSERT OR REPLACE INTO technologies VALUES(?,?,?,?)",
        req.body.session,
        origin,
        "httpx",
        JSON.stringify(
          (r.tech || []).map((name) => ({ name, confidence: 100 })),
        ),
      );
      count++;
    }
    res.json({ count });
  } catch (e) {
    next(e);
  }
});
app.get("/api/export", (req, res) => {
  const data = rows(req.query, true);
  const format = req.query.format || "json";
  res.attachment(
    `capture-${Date.now()}.${format === "zip" ? "zip" : format === "har" ? "har" : "json"}`,
  );
  if (format === "zip") {
    res.type("application/zip");
    const zip = new archiver.ZipArchive();
    zip.on("error", () => res.destroy());
    zip.pipe(res);
    zip.append(
      JSON.stringify(
        data.map(({ body, ...r }) => ({
          ...r,
          file: body ? `${r.id}.js` : null,
        })),
        null,
        2,
      ),
      { name: "manifest.json" },
    );
    for (const r of data)
      if (r.body) zip.append(r.body, { name: `${r.id}.js` });
    zip.finalize();
  } else if (format === "har") {
    const headers = (s) =>
      Object.entries(JSON.parse(s || "{}")).map(([name, value]) => ({
        name,
        value,
      }));
    res.json({
      log: {
        version: "1.2",
        creator: { name: "Traceglass", version: "1.0" },
        entries: data.map((r) => ({
          startedDateTime: r.started,
          time: r.duration || 0,
          request: {
            method: r.method,
            url: r.url,
            httpVersion: "HTTP/1.1",
            headers: headers(r.requestHeaders),
            queryString: [...new URL(r.url).searchParams].map(
              ([name, value]) => ({ name, value }),
            ),
            cookies: [],
            headersSize: -1,
            bodySize: Buffer.byteLength(r.requestBody || ""),
            ...(r.requestBody
              ? {
                  postData: {
                    mimeType:
                      JSON.parse(r.requestHeaders || "{}")["content-type"] ||
                      "",
                    text: r.requestBody,
                  },
                }
              : {}),
          },
          response: {
            status: r.status || 0,
            statusText: "",
            httpVersion: "HTTP/1.1",
            headers: headers(r.responseHeaders),
            cookies: [],
            content: {
              size: r.body?.length || 0,
              mimeType:
                JSON.parse(r.responseHeaders || "{}")["content-type"] || "",
              text: r.body?.toString("base64") || "",
              encoding: "base64",
            },
            redirectURL: JSON.parse(r.responseHeaders || "{}").location || "",
            headersSize: -1,
            bodySize: r.body?.length || 0,
          },
          cache: {},
          timings: { send: 0, wait: r.duration || 0, receive: 0 },
          _error: r.error,
        })),
      },
    });
  } else
    res.json(
      data.map(({ body, ...r }) => ({
        ...r,
        bodyBase64: body?.toString("base64"),
      })),
    );
});
const recon = require("./recon").mountRecon(app, { db, W });
const handoff = require("./handoff").mountHandoff(app, { db });
app.use((err, req, res, next) => {
  console.error(err.message);
  if (!res.headersSent) res.status(400).json({ error: err.message });
});
const server = app.listen(port, "127.0.0.1", () =>
  console.log(
    `Traceglass running at http://127.0.0.1:${server.address().port}`,
  ),
);
process.on("SIGINT", async () => {
  for (const task of recon.running.values())
    task.controller.abort(Error("Server shutting down"));
  await Promise.allSettled([...recon.running.values()].map((t) => t.promise));
  if (context) await context.close();
  await Promise.allSettled([...pending]);
  db.close();
  server.close();
  process.exit();
});
module.exports = {
  app,
  server,
  db,
  launch,
  pending,
  filter,
  interceptor,
  recon,
  handoff,
};
