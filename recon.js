const crypto = require("node:crypto");
const dns = require("node:dns").promises;
const net = require("node:net");
const fs = require("node:fs");
const path = require("node:path");
const cheerio = require("cheerio");
const YAML = require("yaml");
const archiver = require("archiver");
const { isJavaScript, binaryKind } = require("./media-kind");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const exec = promisify(execFile);
const CATEGORIES = [
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
  "authorization",
  "mobile",
  "integrations",
  "source",
  "dependencies",
  "configuration",
  "schema",
  "authcode",
  "routes",
  "git",
  "tests",
  "cicd",
  "secrets",
];
const DEFAULT_PATHS = [
  "robots.txt",
  "sitemap.xml",
  ".well-known/security.txt",
  "swagger.json",
  "openapi.json",
  "openapi.yaml",
  "api-docs",
  "v3/api-docs",
  "swagger/",
  "docs/",
  "api/",
  "api/v1/",
  "api/v2/",
  "graphql",
  "health",
  "status",
  "login",
  "admin/",
];
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
function normalizeTarget(value) {
  const u = new URL(/^https?:\/\//i.test(value) ? value : "https://" + value);
  if (!["http:", "https:"].includes(u.protocol) || u.username || u.password)
    throw Error("Enter an HTTP(S) target without credentials.");
  u.hash = "";
  return u;
}
function inScope(value, options) {
  try {
    const u = normalizeTarget(value),
      root = normalizeTarget(options.target);
    const host = u.hostname.toLowerCase(),
      base = root.hostname.toLowerCase();
    if (!(host === base || (options.subdomains && host.endsWith("." + base))))
      return false;
    if (root.port && u.port !== root.port) return false;
    return !(options.exclude || []).some(
      (ex) =>
        ex && (host === ex || host.endsWith("." + ex) || u.href.includes(ex)),
    );
  } catch {
    return false;
  }
}
function optionsFrom(input) {
  const target = normalizeTarget(input.target).href;
  return {
    target,
    subdomains: !!input.subdomains,
    exclude: String(input.exclude || "")
      .split(/[\n,]+/)
      .map((x) => x.trim())
      .filter(Boolean),
    modules: [
      ...new Set(
        (input.modules || ["browser", "dns", "crawl"]).filter((x) =>
          [
            "browser",
            "dns",
            "ct",
            "archives",
            "rdap",
            "probe",
            "crawl",
            "paths",
            "graphql",
          ].includes(x),
        ),
      ),
    ],
    maxRequests: Math.max(1, Math.min(10000, Number(input.maxRequests) || 250)),
    maxPages: Math.max(1, Math.min(1000, Number(input.maxPages) || 100)),
    maxHosts: Math.max(1, Math.min(1000, Number(input.maxHosts) || 50)),
    delay: Math.max(50, Math.min(10000, Number(input.delay) || 300)),
    maxBody:
      Math.max(1, Math.min(30, Number(input.maxBody) || 5)) * 1024 * 1024,
    paths: String(input.paths || DEFAULT_PATHS.join("\n"))
      .split(/\r?\n/)
      .map((x) => x.trim())
      .filter(Boolean)
      .slice(0, 5000),
    role: String(input.role || "unlabeled").slice(0, 100),
    sourceSession: input.sourceSession || null,
  };
}
function mountRecon(app, { db, W, externalFetch = fetch, dnsResolver = dns }) {
  db.exec(
    `CREATE TABLE IF NOT EXISTS recon_jobs(id TEXT PRIMARY KEY,session TEXT,name TEXT,created TEXT,updated TEXT,status TEXT,options TEXT,stages TEXT,logs TEXT,requests INTEGER DEFAULT 0); CREATE TABLE IF NOT EXISTS recon_records(id INTEGER PRIMARY KEY,job TEXT,category TEXT,key TEXT,title TEXT,data TEXT,artifact TEXT,UNIQUE(job,category,key)); CREATE INDEX IF NOT EXISTS recon_job_category ON recon_records(job,category); CREATE TABLE IF NOT EXISTS recon_blobs(hash TEXT PRIMARY KEY,body BLOB);`,
  );
  db.prepare(
    "UPDATE recon_jobs SET status='interrupted' WHERE status IN ('running','queued')",
  ).run();
  const running = new Map();
  const add = (job, category, key, title, data = {}, body) => {
    let artifact = null;
    if (body !== undefined) {
      const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body);
      artifact = sha(bytes);
      db.prepare("INSERT OR IGNORE INTO recon_blobs VALUES(?,?)").run(
        artifact,
        bytes,
      );
    }
    const existing = db
      .prepare(
        "SELECT * FROM recon_records WHERE job=? AND category=? AND key=?",
      )
      .get(job, category, String(key));
    if (existing) {
      const prev = JSON.parse(existing.data);
      data = {
        ...prev,
        ...data,
        sources: [
          ...new Set(
            [
              ...(prev.sources || []),
              ...(data.sources || []),
              prev.source,
              data.source,
            ].filter(Boolean),
          ),
        ],
      };
    }
    db.prepare(
      "INSERT INTO recon_records(job,category,key,title,data,artifact) VALUES(?,?,?,?,?,?) ON CONFLICT(job,category,key) DO UPDATE SET data=excluded.data,artifact=coalesce(excluded.artifact,recon_records.artifact),title=excluded.title",
    ).run(
      job,
      category,
      String(key),
      String(title),
      JSON.stringify(data),
      artifact,
    );
    return artifact;
  };
  function log(job, message) {
    const row = db.prepare("SELECT logs FROM recon_jobs WHERE id=?").get(job);
    if (!row) return;
    const logs = JSON.parse(row.logs);
    logs.push({ time: new Date().toISOString(), message });
    db.prepare("UPDATE recon_jobs SET logs=?,updated=? WHERE id=?").run(
      JSON.stringify(logs.slice(-400)),
      new Date().toISOString(),
      job,
    );
  }
  function stage(job, name, status, detail = "") {
    const row = db.prepare("SELECT stages FROM recon_jobs WHERE id=?").get(job);
    const stages = JSON.parse(row.stages);
    stages[name] = { status, detail, updated: new Date().toISOString() };
    db.prepare("UPDATE recon_jobs SET stages=?,updated=? WHERE id=?").run(
      JSON.stringify(stages),
      new Date().toISOString(),
      job,
    );
  }
  function newJob(input, session, name) {
    const id = crypto.randomUUID(),
      now = new Date().toISOString();
    db.prepare("INSERT INTO recon_jobs VALUES(?,?,?,?,?,?,?,?,?,?)").run(
      id,
      session,
      name,
      now,
      now,
      "queued",
      JSON.stringify(input),
      "{}",
      "[]",
      0,
    );
    return id;
  }
  function getJob(id) {
    const row = db.prepare("SELECT * FROM recon_jobs WHERE id=?").get(id);
    if (!row) throw Error("Unknown recon run.");
    return {
      ...row,
      options: JSON.parse(row.options),
      stages: JSON.parse(row.stages),
      logs: JSON.parse(row.logs),
    };
  }
  async function readResponse(response, maxBytes, signal) {
    const parts = [];
    let length = 0;
    for await (const chunk of response.body || []) {
      signal?.throwIfAborted();
      length += chunk.length;
      if (length > maxBytes)
        throw Error(
          `Body exceeds configured ${Math.round(maxBytes / 1048576)} MiB limit`,
        );
      parts.push(Buffer.from(chunk));
    }
    return Buffer.concat(parts);
  }
  async function external(url, controller, max = 20 * 1024 * 1024) {
    const signal = AbortSignal.any([
      controller.signal,
      AbortSignal.timeout(25000),
    ]);
    const response = await externalFetch(url, {
      signal,
      headers: { "user-agent": "Traceglass-Recon/1.0" },
      redirect: "follow",
    });
    if (!response.ok) throw Error(`Provider returned HTTP ${response.status}`);
    return (await readResponse(response, max, signal)).toString("utf8");
  }
  function extract(job, text, url, source, options) {
    const candidates = new Set();
    for (const match of text.matchAll(
      /(?:https?:\/\/[^\s<>"'`\\]+|["'`]((?:\/{1}|\.\.?\/)[^\s<>"'`\\]{1,350})["'`])/g,
    )) {
      const raw = match[1] || match[0];
      try {
        const u = new URL(raw, url);
        u.hash = "";
        if (!["http:", "https:"].includes(u.protocol)) continue;
        candidates.add(u.href);
      } catch {}
    }
    for (const candidate of candidates) {
      if (inScope(candidate, options))
        add(job, "endpoints", candidate, candidate, {
          source,
          evidence: url,
          kind: "string-or-link",
          verified: false,
        });
      else
        add(
          job,
          "integrations",
          new URL(candidate).host,
          new URL(candidate).host,
          { source, evidence: url, url: candidate, observedOnly: true },
        );
    }
    const patterns = [
      ["AWS access key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
      [
        "Private key marker",
        /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
      ],
      [
        "Token assignment",
        /\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password)\s*[:=]\s*["']([^"'\r\n]{12,180})["']/gi,
      ],
      [
        "JWT-shaped value",
        /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g,
      ],
    ];
    for (const [kind, re] of patterns)
      for (const match of text.matchAll(re)) {
        const value = match[1] || match[0],
          line = text.slice(0, match.index).split("\n").length;
        add(
          job,
          "secrets",
          `${url}:${line}:${sha(value)}`,
          `${kind} candidate`,
          {
            source,
            evidence: url,
            line,
            kind,
            preview: value.slice(0, 4) + "…" + value.slice(-4),
            hash: sha(value),
            verified: false,
            note: "Pattern match only. May be a placeholder or public identifier.",
          },
        );
      }
    return [...candidates];
  }
  function parseAPI(job, text, url, source) {
    if (
      !/^\s*[\[{]/.test(text) &&
      !/(?:^|\n)\s*(?:openapi|swagger|item)\s*:/.test(text)
    )
      return;
    try {
      const spec = /^\s*[\[{]/.test(text) ? JSON.parse(text) : YAML.parse(text);
      if (!spec || typeof spec !== "object") return;
      if (spec.openapi || spec.swagger) {
        add(
          job,
          "api",
          url,
          url,
          {
            source,
            kind: "OpenAPI",
            version: spec.openapi || spec.swagger,
            title: spec.info?.title,
            paths: Object.keys(spec.paths || {}),
          },
          text,
        );
        for (const [route, methods] of Object.entries(spec.paths || {}))
          for (const method of Object.keys(methods || {}).filter((m) =>
            /^(get|post|put|patch|delete|head|options|trace)$/.test(m),
          ))
            add(
              job,
              "routes",
              `${url}:${method}:${route}`,
              `${method.toUpperCase()} ${route}`,
              {
                source,
                evidence: url,
                method: method.toUpperCase(),
                route,
                parameters: methods[method].parameters || [],
              },
            );
      }
      if (spec.info?.schema?.includes("getpostman.com") || spec.item) {
        add(job, "api", url, url, { source, kind: "Postman collection" }, text);
        const walk = (items) => {
          for (const item of items || []) {
            if (item.item) walk(item.item);
            if (item.request)
              add(job, "routes", `${url}:${item.name}`, item.name, {
                source,
                evidence: url,
                request: item.request,
              });
          }
        };
        walk(spec.item);
      }
    } catch {}
  }
  function fingerprints(job, text, url, headers = {}, script = false) {
    try {
      const results = W.resolve(
        W.analyze({
          url,
          headers: Object.fromEntries(
            Object.entries(headers).map(([k, v]) => [k, [String(v)]]),
          ),
          html: script ? "" : text,
          scripts: script ? text : "",
          scriptSrc: script ? [url] : [],
          meta: !script
            ? (() => {
                const $ = cheerio.load(text),
                  meta = {};
                $("meta[name]").each((i, el) => {
                  const name = $(el).attr("name").toLowerCase();
                  (meta[name] ??= []).push($(el).attr("content") || "");
                });
                return meta;
              })()
            : {},
        }),
      );
      for (const r of results)
        add(job, "technologies", `${new URL(url).origin}:${r.name}`, r.name, {
          source: "Wappalyzer",
          evidence: url,
          origin: new URL(url).origin,
          version: r.version,
          confidence: r.confidence,
          categories: r.categories.map((c) => c.name),
        });
    } catch (e) {
      log(job, "Fingerprint error: " + e.message);
    }
  }
  function ingestTraffic(job, row, options, source = "browser") {
    if (!inScope(row.url, options)) return;
    const responseHeaders =
      typeof row.responseHeaders === "string"
        ? JSON.parse(row.responseHeaders || "{}")
        : row.responseHeaders || {};
    const requestHeaders =
      typeof row.requestHeaders === "string"
        ? JSON.parse(row.requestHeaders || "{}")
        : row.requestHeaders || {};
    const text = row.text || "",
      body = row.body || Buffer.from(text);
    const artifact = add(
      job,
      "traffic",
      `${source}:${row.id}`,
      `${row.method} ${row.url}`,
      {
        source,
        captureId: row.id,
        url: row.url,
        method: row.method,
        status: row.status,
        requestHeaders,
        requestBody: row.requestBody || "",
        requestBase64: row.requestBase64,
        requestEncoding: row.requestEncoding,
        responseHeaders,
        duration: row.duration,
        error: row.error,
        responseBodyAvailable: row.body != null || !!row.text,
        role: options.role,
      },
      body,
    );
    add(job, "headers", row.url, row.url, {
      source,
      status: row.status,
      headers: responseHeaders,
      missingSecurityHeaders: [
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
      ].filter((h) => !(h in responseHeaders)),
    });
    if (text) {
      extract(job, text, row.url, source, options);
      if (row.type === "document")
        fingerprints(job, text, row.url, responseHeaders, false);
    }
    add(job, "hosts", new URL(row.url).origin, new URL(row.url).origin, {
      source,
      status: row.status,
    });
    add(
      job,
      "endpoints",
      `${row.method}:${row.url}`,
      `${row.method} ${row.url}`,
      {
        source,
        method: row.method,
        url: row.url,
        status: row.status,
        verified: !!row.status,
      },
    );
    const boundary = `${options.role}:${row.method}:${new URL(row.url).origin}${new URL(row.url).pathname}`;
    add(
      job,
      "authorization",
      boundary,
      `${options.role} · ${row.method} ${new URL(row.url).pathname}`,
      {
        source,
        role: options.role,
        url: row.url,
        method: row.method,
        status: row.status,
        bodyHash: sha(body),
        size: body.length,
        artifact,
        note: "Observed response; expected access rights require manual review.",
      },
    );
    if (
      isJavaScript(
        row.url,
        responseHeaders["content-type"] || "",
        row.isjs ? "script" : row.type,
        body.subarray(0, 160),
      )
    ) {
      add(
        job,
        "javascript",
        row.url,
        row.url,
        {
          source,
          status: row.status,
          bytes: body.length,
          body_available: row.body != null || !!row.text,
          error: row.error || null,
        },
        body,
      );
      extract(job, text || body.toString(), row.url, source, options);
    } else if (
      binaryKind(
        row.url,
        responseHeaders["content-type"] || "",
        body.subarray(0, 16),
      ) === "webassembly"
    )
      add(
        job,
        "dependencies",
        row.url,
        row.url,
        {
          source,
          kind: "webassembly",
          bytes: body.length,
          note: "Binary dependency; retained without JavaScript parsing.",
        },
        body,
      );
    parseAPI(job, text, row.url, source);
    for (const [name, value] of Object.entries(requestHeaders))
      if (name.toLowerCase() === "origin" || name.toLowerCase() === "referer")
        try {
          if (!inScope(value, options))
            add(job, "integrations", new URL(value).host, new URL(value).host, {
              source,
              evidence: row.url,
              header: name,
            });
        } catch {}
  }
  async function execute(job, options, controller) {
    const root = normalizeTarget(options.target),
      hosts = new Set([root.hostname]);
    let count = 0,
      nextRequest = 0;
    const check = () => controller.signal.throwIfAborted();
    const report = (category, key, title, data, body) =>
      add(job, category, key, title, data, body);
    const targetFetch = async (value, method = "GET", body) => {
      check();
      if (!inScope(value, options))
        throw Error("Outside configured scope: " + value);
      let url = new URL(value);
      let response;
      for (let redirects = 0; redirects < 6; redirects++) {
        check();
        if (count >= options.maxRequests) throw Error("Request budget reached");
        const wait = nextRequest - Date.now();
        if (wait > 0) await new Promise((r) => setTimeout(r, wait));
        check();
        nextRequest = Date.now() + options.delay;
        count++;
        db.prepare("UPDATE recon_jobs SET requests=? WHERE id=?").run(
          count,
          job,
        );
        const signal = AbortSignal.any([
          controller.signal,
          AbortSignal.timeout(15000),
        ]);
        const started = Date.now();
        response = await externalFetch(url, {
          method,
          body,
          signal,
          redirect: "manual",
          headers: {
            "user-agent": "Traceglass-Recon/1.0",
            ...(body ? { "content-type": "application/json" } : {}),
          },
        });
        const bytes = await readResponse(response, options.maxBody, signal),
          headers = Object.fromEntries(response.headers),
          type = headers["content-type"] || "",
          text =
            /text|javascript|json|xml|yaml|graphql/.test(type) ||
            /\.m?js|\.ya?ml|\.json/.test(url.pathname)
              ? bytes.toString("utf8")
              : "";
        const artifact = report(
          "traffic",
          `active:${count}`,
          `${method} ${url}`,
          {
            source: "active-recon",
            url: url.href,
            method,
            status: response.status,
            responseHeaders: headers,
            requestBody: body || "",
            duration: Date.now() - started,
            role: "unauthenticated",
          },
          bytes,
        );
        report("hosts", url.origin, url.origin, {
          source: "probe",
          status: response.status,
          title: cheerio.load(text)("title").text().slice(0, 300),
          url: url.href,
        });
        report("headers", url.href, url.href, {
          source: "HTTP",
          status: response.status,
          headers,
          missingSecurityHeaders: [
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
          ].filter((h) => !(h in headers)),
          note: "Missing headers are observations, not confirmed vulnerabilities.",
        });
        report("endpoints", `${method}:${url}`, `${method} ${url}`, {
          source: "active-recon",
          method,
          url: url.href,
          status: response.status,
          verified: true,
          artifact,
        });
        if (
          response.status >= 300 &&
          response.status < 400 &&
          headers.location
        ) {
          const next = new URL(headers.location, url);
          if (!inScope(next.href, options)) {
            report("integrations", next.host, next.host, {
              source: "redirect",
              evidence: url.href,
              url: next.href,
              observedOnly: true,
            });
            return {
              url: url.href,
              status: response.status,
              text,
              headers,
              body: bytes,
              redirectBlocked: true,
            };
          }
          url = next;
          continue;
        }
        if (isJavaScript(url.href, type, "", bytes.subarray(0, 160))) {
          report(
            "javascript",
            url.href,
            url.href,
            { source: "crawler", status: response.status, bytes: bytes.length },
            bytes,
          );
          fingerprints(job, text, url.href, headers, true);
        } else if (/html/.test(type))
          fingerprints(job, text, url.href, headers, false);
        parseAPI(job, text, url.href, "active-recon");
        return {
          url: url.href,
          status: response.status,
          text,
          headers,
          body: bytes,
        };
      }
      throw Error("Redirect limit reached");
    };
    const step = async (name, fn) => {
      check();
      stage(job, name, "running");
      log(job, `Started ${name}`);
      try {
        const detail = await fn();
        stage(job, name, "complete", detail || "Collected available evidence");
      } catch (e) {
        if (controller.signal.aborted) throw e;
        stage(job, name, "partial", e.message);
        log(job, `${name}: ${e.message}`);
      }
    };
    if (options.modules.includes("browser"))
      await step("Browser evidence", async () => {
        const sourceSession = options.sourceSession || getJob(job).session;
        const dependencies = new Set();
        const rememberDependencies = (r) => {
          const text = r.text || "";
          try {
            const headers =
              typeof r.responseHeaders === "string"
                ? JSON.parse(r.responseHeaders || "{}")
                : r.responseHeaders || {};
            if (/html/.test(headers["content-type"] || "")) {
              const $ = cheerio.load(text);
              $('script[src],link[rel="modulepreload"][href]').each((i, el) => {
                try {
                  dependencies.add(
                    new URL($(el).attr("src") || $(el).attr("href"), r.url)
                      .href,
                  );
                } catch {}
              });
            }
            if (r.isjs || r.type === "script")
              for (const match of text.matchAll(
                /["'`]([^"'`\r\n]*\.m?js(?:\?[^"'`\r\n]*)?)["'`]/g,
              ))
                try {
                  dependencies.add(new URL(match[1], r.url).href);
                } catch {}
          } catch {}
        };
        const upper =
          db
            .prepare("SELECT max(id) id FROM traffic WHERE session=?")
            .get(sourceSession).id || 0;
        let total = 0,
          cursor = 0;
        while (cursor < upper) {
          const records = db
            .prepare(
              "SELECT * FROM traffic WHERE session=? AND id>? AND id<=? ORDER BY id LIMIT 100",
            )
            .all(sourceSession, cursor, upper);
          if (!records.length) break;
          for (const r of records) {
            cursor = r.id;
            check();
            if (inScope(r.url, options)) {
              rememberDependencies(r);
              ingestTraffic(job, r, options);
              total++;
            } else
              try {
                const requestHeaders =
                  typeof r.requestHeaders === "string"
                    ? JSON.parse(r.requestHeaders || "{}")
                    : r.requestHeaders || {};
                const referrer =
                  requestHeaders.referer || requestHeaders.referrer;
                const connected =
                  dependencies.has(r.url) ||
                  (referrer &&
                    (inScope(referrer, options) || dependencies.has(referrer)));
                const responseHeaders =
                  typeof r.responseHeaders === "string"
                    ? JSON.parse(r.responseHeaders || "{}")
                    : r.responseHeaders || {};
                if (
                  connected &&
                  isJavaScript(
                    r.url,
                    responseHeaders["content-type"] || "",
                    r.isjs ? "script" : r.type,
                    r.body?.subarray(0, 160),
                  )
                ) {
                  dependencies.add(r.url);
                  rememberDependencies(r);
                  report(
                    "javascript",
                    r.url,
                    r.url,
                    {
                      source: "browser-dependency",
                      status: r.status,
                      bytes: r.body?.length || 0,
                      body_available: r.body != null || !!r.text,
                      error: r.error || null,
                      in_scope: false,
                      passive_only: true,
                    },
                    r.body || Buffer.from(r.text || ""),
                  );
                }
                if (
                  connected &&
                  binaryKind(r.url, responseHeaders["content-type"] || "") ===
                    "webassembly"
                )
                  report(
                    "dependencies",
                    r.url,
                    r.url,
                    {
                      source: "browser-dependency",
                      kind: "webassembly",
                      passive_only: true,
                      in_scope: false,
                      bytes: r.body?.length || 0,
                    },
                    r.body || Buffer.alloc(0),
                  );
                report(
                  "integrations",
                  new URL(r.url).host,
                  new URL(r.url).host,
                  {
                    source: "browser",
                    evidence: r.url,
                    observedOnly: true,
                  },
                );
              } catch {}
          }
          await new Promise((resolve) => setImmediate(resolve));
        }
        for (const r of db
          .prepare("SELECT * FROM technologies WHERE session=?")
          .all(sourceSession))
          if (inScope(r.origin, options))
            for (const t of JSON.parse(r.result))
              report("technologies", `${r.origin}:${t.name}`, t.name, {
                ...t,
                source: r.engine,
                evidence: r.origin,
              });
        return `${total} in-scope captured requests imported as ${options.role}`;
      });
    if (options.modules.includes("ct"))
      await step("Certificate transparency", async () => {
        if (net.isIP(root.hostname) || !root.hostname.includes("."))
          throw Error("Certificate discovery requires a public DNS domain");
        let data,
          discoverySource = "crt.sh";
        try {
          data = JSON.parse(
            await external(
              `https://crt.sh/?q=${encodeURIComponent("%." + root.hostname)}&output=json`,
              controller,
            ),
          );
        } catch (e) {
          log(
            job,
            "Certificate provider unavailable: " +
              e.message +
              "; trying public host search",
          );
          discoverySource = "HackerTarget hostsearch";
          const lines = await external(
            "https://api.hackertarget.com/hostsearch/?q=" +
              encodeURIComponent(root.hostname),
            controller,
          );
          if (/error|API count exceeded/i.test(lines))
            throw Error(
              "Public host search unavailable: " + lines.slice(0, 200),
            );
          data = lines
            .trim()
            .split("\n")
            .map((line) => ({ name_value: line.split(",")[0] }));
        }
        let found = 0;
        for (const row of data)
          for (let host of String(row.name_value || "").split("\n")) {
            host = host.replace(/^\*\./, "").toLowerCase();
            if (host === root.hostname || host.endsWith("." + root.hostname)) {
              report("subdomains", host, host, {
                source: discoverySource,
                issuer: row.issuer_name,
                notBefore: row.not_before,
                notAfter: row.not_after,
                inScope: inScope(
                  `${root.protocol}//${host}${root.port ? ":" + root.port : ""}`,
                  options,
                ),
              });
              hosts.add(host);
              found++;
            }
          }
        return `${found} certificate names observed; not proof of current ownership or liveness`;
      });
    if (options.modules.includes("archives"))
      await step("Archived URLs", async () => {
        const archivePattern =
          (options.subdomains ? "*." : "") + root.hostname + "/*";
        const providers = [
          [
            "Wayback",
            `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(archivePattern)}&output=json&collapse=urlkey&fl=original,timestamp,statuscode,mimetype&limit=5000`,
          ],
          ["Common Crawl", null],
        ];
        let failures = [];
        for (const [provider, endpoint] of providers) {
          check();
          try {
            let urls = [];
            if (endpoint) {
              const entries = JSON.parse(await external(endpoint, controller));
              urls = entries.slice(1).map(([url, timestamp, status, mime]) => ({
                url,
                timestamp,
                status,
                mime,
              }));
            } else {
              const collections = JSON.parse(
                await external(
                  "https://index.commoncrawl.org/collinfo.json",
                  controller,
                ),
              );
              if (!collections[0]?.["cdx-api"])
                throw Error("No index available");
              const lines = await external(
                collections[0]["cdx-api"] +
                  "?url=" +
                  encodeURIComponent(archivePattern) +
                  "&output=json&collapse=urlkey&pageSize=1",
                controller,
              );
              urls = lines
                .split("\n")
                .filter(Boolean)
                .map((line) => JSON.parse(line))
                .map((r) => ({
                  url: r.url,
                  timestamp: r.timestamp,
                  status: r.status,
                  mime: r.mime,
                }));
            }
            for (const r of urls) {
              try {
                normalizeTarget(r.url);
                report("archives", r.url, r.url, {
                  ...r,
                  source: provider,
                  inScope: inScope(r.url, options),
                  verified: false,
                });
                const host = new URL(r.url).hostname;
                if (
                  host === root.hostname ||
                  host.endsWith("." + root.hostname)
                ) {
                  hosts.add(host);
                  report("subdomains", host, host, {
                    source: provider,
                    inScope: inScope(r.url, options),
                  });
                }
              } catch {}
            }
            log(
              job,
              `${provider}: ${urls.length} archived records; provider/query coverage limits apply`,
            );
          } catch (e) {
            failures.push(provider + ": " + e.message);
          }
        }
        if (failures.length) throw Error(failures.join("; "));
        return "Public archive snapshots collected; archive URLs were not automatically requested";
      });
    const scopedHosts = [...hosts]
      .filter((h) =>
        inScope(
          `${root.protocol}//${h}${root.port ? ":" + root.port : ""}`,
          options,
        ),
      )
      .slice(0, options.maxHosts);
    if (hosts.size > options.maxHosts)
      log(
        job,
        `Host limit ${options.maxHosts} reached; additional discovered hosts retained without probing.`,
      );
    if (options.modules.includes("dns"))
      await step("DNS records", async () => {
        let errors = 0;
        for (const host of scopedHosts) {
          check();
          if (net.isIP(host)) {
            report("infrastructure", host, host, {
              source: "target",
              ip: host,
            });
            continue;
          }
          for (const type of [
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "TXT",
            "NS",
            "SOA",
            "CAA",
          ]) {
            check();
            try {
              const result = await Promise.race([
                dnsResolver.resolve(host, type),
                new Promise((_, reject) => {
                  const timer = setTimeout(
                    () => reject(Error("DNS lookup timeout")),
                    5000,
                  );
                  timer.unref();
                }),
              ]);
              report("dns", `${host}:${type}`, `${host} · ${type}`, {
                source: "DNS",
                host,
                type,
                answers: result,
              });
              if (type === "A" || type === "AAAA")
                for (const ip of result)
                  report("infrastructure", ip, ip, { source: "DNS", host, ip });
            } catch (e) {
              if (!["ENODATA", "ENOTFOUND"].includes(e.code)) {
                errors++;
                log(job, `${host} ${type}: ${e.message}`);
              }
            }
          }
        }
        if (errors)
          throw Error(
            `${errors} DNS queries failed or timed out; successful results retained`,
          );
        return "A, AAAA, CNAME, MX, TXT, NS, SOA and CAA queried for scoped hosts";
      });
    if (options.modules.includes("rdap"))
      await step("Infrastructure registration", async () => {
        const asns = new Set();
        const registration = async (kind, value) => {
          let last;
          for (const provider of ["https://rdap.org", "https://rdap.net"])
            try {
              return JSON.parse(
                await external(
                  provider + "/" + kind + "/" + encodeURIComponent(value),
                  controller,
                ),
              );
            } catch (e) {
              last = e;
              log(job, provider + " " + kind + ": " + e.message);
            }
          throw last;
        };
        const ips = db
          .prepare(
            "SELECT title FROM recon_records WHERE job=? AND category='infrastructure'",
          )
          .all(job)
          .map((r) => r.title)
          .filter(net.isIP)
          .slice(0, options.maxHosts);
        let failures = 0;
        if (!net.isIP(root.hostname))
          try {
            const r = await registration("domain", root.hostname);
            report(
              "infrastructure",
              "domain:" + root.hostname,
              root.hostname + " registration",
              { source: "RDAP", registration: r },
            );
          } catch (e) {
            log(job, "Domain RDAP: " + e.message);
            failures++;
          }
        for (const ip of ips) {
          check();
          try {
            const r = await registration("ip", ip);
            report("infrastructure", ip, ip, {
              source: "RDAP",
              ip,
              name: r.name,
              range: { start: r.startAddress, end: r.endAddress },
              country: r.country,
              registration: r,
              note: "Registration/range does not establish testing scope.",
            });
            if (net.isIP(ip)) {
              try {
                let asnQuery;
                if (net.isIP(ip) === 4)
                  asnQuery =
                    ip.split(".").reverse().join(".") + ".origin.asn.cymru.com";
                else {
                  let value = ip;
                  if (value.includes(".")) {
                    const at = value.lastIndexOf(":");
                    const bytes = value
                      .slice(at + 1)
                      .split(".")
                      .map(Number);
                    value =
                      value.slice(0, at + 1) +
                      ((bytes[0] << 8) | bytes[1]).toString(16) +
                      ":" +
                      ((bytes[2] << 8) | bytes[3]).toString(16);
                  }
                  const halves = value.split("::"),
                    left = halves[0] ? halves[0].split(":") : [],
                    right = halves[1] ? halves[1].split(":") : [];
                  const expanded = [
                    ...left,
                    ...Array(8 - left.length - right.length).fill("0"),
                    ...right,
                  ]
                    .map((p) => p.padStart(4, "0"))
                    .join("");
                  asnQuery =
                    expanded.split("").reverse().join(".") +
                    ".origin6.asn.cymru.com";
                }
                const answers = await dnsResolver.resolve(asnQuery, "TXT");
                report("infrastructure", ip, ip, {
                  source: "Team Cymru DNS",
                  asn: answers.flat().join(" | "),
                });
                for (const answer of answers.flat()) {
                  const asn = String(answer).split("|")[0].trim();
                  for (const number of asn.split(/\s+/))
                    if (/^\d+$/.test(number)) asns.add(number);
                }
              } catch (e) {
                log(job, "ASN lookup " + ip + ": " + e.message);
              }
            }
          } catch (e) {
            failures++;
            log(job, "IP RDAP " + ip + ": " + e.message);
          }
        }
        for (const asn of asns) {
          check();
          try {
            const result = JSON.parse(
              await external(
                "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" +
                  asn,
                controller,
              ),
            );
            report(
              "infrastructure",
              "asn:" + asn,
              "AS" + asn + " announced prefixes",
              {
                source: "RIPEstat",
                asn,
                announcedPrefixes: result.data?.prefixes || [],
                queryStart: result.data?.query_starttime,
                queryEnd: result.data?.query_endtime,
                note: "Public ASN context only. These ranges are not automatically in target scope and are never probed.",
              },
            );
          } catch (e) {
            failures++;
            log(job, "ASN prefix lookup " + asn + ": " + e.message);
          }
        }
        if (failures)
          throw Error(
            `${failures} registration lookups unavailable; successful results retained`,
          );
      });
    if (options.modules.includes("probe"))
      await step("Live host probing", async () => {
        let failed = 0;
        for (const host of scopedHosts) {
          check();
          const url =
            host === root.hostname
              ? root.origin
              : `${root.protocol}//${host}${root.port ? ":" + root.port : ""}`;
          try {
            await targetFetch(url);
          } catch (e) {
            failed++;
            report("hosts", url, url, {
              source: "probe",
              error: e.message,
              status: 0,
            });
          }
        }
        if (failed)
          throw Error(`${failed} hosts failed to respond within limits`);
        return `${scopedHosts.length} host origins probed`;
      });
    if (options.modules.includes("crawl"))
      await step("Website crawl", async () => {
        const queue = [root.href],
          seen = new Set();
        let failed = 0;
        while (
          queue.length &&
          seen.size < options.maxPages &&
          count < options.maxRequests
        ) {
          check();
          const url = queue.shift();
          if (seen.has(url) || !inScope(url, options)) continue;
          seen.add(url);
          try {
            const r = await targetFetch(url);
            const links = extract(job, r.text, r.url, "crawler", options);
            if (/html/.test(r.headers["content-type"] || "")) {
              const $ = cheerio.load(r.text);
              $("a[href],script[src],link[href],iframe[src],form[action]").each(
                (i, el) => {
                  const raw =
                    $(el).attr("href") ||
                    $(el).attr("src") ||
                    $(el).attr("action");
                  try {
                    const u = new URL(raw, r.url);
                    u.hash = "";
                    if (inScope(u.href, options)) {
                      report("endpoints", u.href, u.href, {
                        source: "HTML",
                        evidence: r.url,
                        verified: false,
                        formMethod: $(el).is("form")
                          ? ($(el).attr("method") || "GET").toUpperCase()
                          : undefined,
                      });
                      if (
                        !$(el).is("form") &&
                        (/script|iframe|a/.test(el.name) ||
                          /\.m?js$/.test(u.pathname))
                      )
                        queue.push(u.href);
                    } else if (["http:", "https:"].includes(u.protocol))
                      report("integrations", u.host, u.host, {
                        source: "HTML",
                        evidence: r.url,
                        url: u.href,
                        observedOnly: true,
                      });
                  } catch {}
                },
              );
            }
            if (
              /xml/.test(r.headers["content-type"] || "") ||
              /sitemap/.test(url)
            )
              for (const match of r.text.matchAll(
                /<loc>\s*([^<]+)\s*<\/loc>/gi,
              ))
                try {
                  const u = new URL(match[1].replace(/&amp;/g, "&"));
                  if (inScope(u.href, options)) queue.push(u.href);
                } catch {}
            for (const candidate of links)
              if (
                /\.m?js(?:[?#]|$)/.test(candidate) &&
                inScope(candidate, options)
              )
                queue.push(candidate);
          } catch (e) {
            failed++;
            log(job, `Crawl ${url}: ${e.message}`);
          }
        }
        if (queue.length)
          throw Error(
            `Crawl limit reached after ${seen.size} URLs; ${queue.length} queued links remain`,
          );
        if (failed)
          throw Error(
            `${failed} crawl requests failed; collected results retained`,
          );
        return `${seen.size} URLs visited; forms were not submitted`;
      });
    if (options.modules.includes("paths"))
      await step("Endpoint discovery", async () => {
        const baselinePath =
          "/__traceglass_missing_" + crypto.randomBytes(8).toString("hex");
        let baseline;
        try {
          baseline = await targetFetch(new URL(baselinePath, root).href);
        } catch (e) {
          log(job, "Soft-404 baseline unavailable: " + e.message);
        }
        let failures = 0;
        for (const candidate of options.paths) {
          check();
          if (count >= options.maxRequests)
            throw Error(
              "Request budget reached; remaining wordlist paths not requested",
            );
          let url;
          try {
            url = new URL(candidate, root.origin + "/");
            if (!inScope(url.href, options)) continue;
            const r = await targetFetch(url.href);
            const soft404 =
              !!baseline &&
              r.status === baseline.status &&
              (sha(r.body) === sha(baseline.body) ||
                (r.body.length === baseline.body.length && r.status === 200));
            report("endpoints", `GET:${url}`, `GET ${url}`, {
              source: "wordlist",
              url: url.href,
              status: r.status,
              verified: true,
              possibleSoft404: soft404,
              baselineStatus: baseline?.status,
            });
            extract(job, r.text, r.url, "wordlist", options);
          } catch (e) {
            failures++;
            log(job, `Discovery ${candidate}: ${e.message}`);
          }
        }
        if (failures) throw Error(`${failures} discovery requests failed`);
        return `${options.paths.length} paths tested; soft-404 flags require review`;
      });
    if (options.modules.includes("graphql"))
      await step("GraphQL schema", async () => {
        const url = new URL("/graphql", root).href;
        const r = await targetFetch(
          url,
          "POST",
          JSON.stringify({
            query:
              "query TraceglassSchema { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name description fields { name args { name type { kind name ofType { kind name } } } type { kind name ofType { kind name } } } } } }",
          }),
        );
        let result;
        try {
          result = JSON.parse(r.text);
        } catch {
          throw Error("GraphQL endpoint did not return JSON");
        }
        if (!result.data?.__schema)
          throw Error(
            "Introspection unavailable or requires an authenticated account",
          );
        report(
          "api",
          url,
          url,
          {
            source: "GraphQL introspection",
            status: r.status,
            kind: "GraphQL schema",
          },
          r.body,
        );
        return "Read-only schema introspection collected";
      });
    if (count >= options.maxRequests)
      log(
        job,
        "Configured target request budget exhausted. Increase limits and run again for more coverage.",
      );
  }
  async function start(job, work) {
    const controller = new AbortController();
    db.prepare("UPDATE recon_jobs SET status='running' WHERE id=?").run(job);
    const promise = (async () => {
      try {
        await work(controller);
        const row = getJob(job);
        db.prepare("UPDATE recon_jobs SET status=?,updated=? WHERE id=?").run(
          Object.values(row.stages).some((s) => s.status === "partial")
            ? "partial"
            : "complete",
          new Date().toISOString(),
          job,
        );
        log(
          job,
          "Run finished. Results describe observed coverage, not a complete target inventory.",
        );
      } catch (e) {
        db.prepare("UPDATE recon_jobs SET status=?,updated=? WHERE id=?").run(
          controller.signal.aborted ? "cancelled" : "failed",
          new Date().toISOString(),
          job,
        );
        log(job, e.message);
        const row = getJob(job);
        for (const [name, s] of Object.entries(row.stages))
          if (s.status === "running")
            stage(
              job,
              name,
              controller.signal.aborted ? "cancelled" : "failed",
              e.message,
            );
      } finally {
        running.delete(job);
      }
    })();
    running.set(job, { controller, promise });
    return promise;
  }
  const assertSession = (id) => {
    if (!db.prepare("SELECT id FROM sessions WHERE id=?").get(id))
      throw Error("Select or create a session first.");
  };
  const ensureSession = (id, target) => {
    if (!id) {
      id = crypto.randomUUID();
      db.prepare("INSERT INTO sessions VALUES(?,?,?)").run(
        id,
        "Recon · " + normalizeTarget(target).hostname,
        new Date().toISOString(),
      );
    }
    assertSession(id);
    return id;
  };
  app.post("/api/recon/start", (req, res, next) => {
    try {
      let session = req.body.session;
      if (!session) {
        session = crypto.randomUUID();
        db.prepare("INSERT INTO sessions VALUES(?,?,?)").run(
          session,
          "Recon · " + normalizeTarget(req.body.target).hostname,
          new Date().toISOString(),
        );
      }
      assertSession(session);
      const options = optionsFrom(req.body);
      const job = newJob(
        options,
        session,
        "Recon · " + new URL(options.target).hostname,
      );
      void start(job, (c) => execute(job, options, c));
      res.json({ id: job, session });
    } catch (e) {
      next(e);
    }
  });
  app.get("/api/recon/jobs", (req, res) =>
    res.json(
      db
        .prepare(
          "SELECT id,session,name,created,status,requests FROM recon_jobs WHERE session=? ORDER BY created DESC",
        )
        .all(req.query.session || ""),
    ),
  );
  app.get("/api/recon/jobs/:id", (req, res, next) => {
    try {
      const job = getJob(req.params.id);
      const counts = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
      for (const row of db
        .prepare(
          "SELECT category,count(*) count FROM recon_records WHERE job=? GROUP BY category",
        )
        .all(job.id))
        counts[row.category] = row.count;
      res.json({ ...job, counts });
    } catch (e) {
      next(e);
    }
  });
  app.post("/api/recon/jobs/:id/cancel", (req, res, next) => {
    try {
      getJob(req.params.id);
      running.get(req.params.id)?.controller.abort(Error("Cancelled by user"));
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });
  function resultFilter(q) {
    const clauses = ["job=?"],
      args = [q.job || ""];
    if (q.category) {
      clauses.push("category=?");
      args.push(q.category);
    }
    if (q.q) {
      clauses.push(
        "(title LIKE ? ESCAPE '\\' OR data LIKE ? ESCAPE '\\' OR CAST((SELECT body FROM recon_blobs WHERE hash=artifact) AS TEXT) LIKE ? ESCAPE '\\')",
      );
      args.push(
        ...Array(3).fill("%" + String(q.q).replace(/[\\%_]/g, "\\$&") + "%"),
      );
    }
    return { where: clauses.join(" AND "), args };
  }
  app.get("/api/recon/results", (req, res) => {
    const { where, args } = resultFilter(req.query);
    res.json({
      rows: db
        .prepare(
          `SELECT id,job,category,key,title,data,artifact FROM recon_records WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`,
        )
        .all(
          ...args,
          Math.min(200, Math.max(1, Number(req.query.limit) || 100)),
          Math.max(0, Number(req.query.offset) || 0),
        )
        .map((r) => ({ ...r, data: JSON.parse(r.data) })),
      total: db
        .prepare(`SELECT count(*) count FROM recon_records WHERE ${where}`)
        .get(...args).count,
    });
  });
  app.get("/api/recon/artifact/:id", (req, res) => {
    const row = db
      .prepare(
        "SELECT r.*,b.body FROM recon_records r JOIN recon_blobs b ON b.hash=r.artifact WHERE r.id=?",
      )
      .get(req.params.id);
    if (!row) return res.sendStatus(404);
    res
      .attachment(`recon-${row.id}-${row.category}.bin`)
      .type("application/octet-stream")
      .send(row.body);
  });
  app.get("/api/recon/preview/:id", (req, res) => {
    const row = db
      .prepare(
        "SELECT b.body FROM recon_records r JOIN recon_blobs b ON b.hash=r.artifact WHERE r.id=?",
      )
      .get(req.params.id);
    if (!row) return res.json({ text: "No attached content." });
    res.json({
      text: row.body.subarray(0, 512 * 1024).toString("utf8"),
      bytes: row.body.length,
      truncated: row.body.length > 512 * 1024,
    });
  });
  app.get("/api/recon/export", (req, res, next) => {
    try {
      const { where, args } = resultFilter(req.query);
      const job = getJob(req.query.job);
      const records = db
        .prepare(`SELECT * FROM recon_records WHERE ${where} ORDER BY id`)
        .all(...args)
        .map((r) => ({ ...r, data: JSON.parse(r.data) }));
      if (req.query.format === "zip") {
        res.attachment(`recon-${job.id}.zip`);
        const zip = new archiver.ZipArchive();
        zip.on("error", () => res.destroy());
        zip.pipe(res);
        zip.append(JSON.stringify({ job, records }, null, 2), {
          name: "manifest.json",
        });
        const blobs = new Set(records.map((r) => r.artifact).filter(Boolean));
        for (const hash of blobs) {
          const row = db
            .prepare("SELECT body FROM recon_blobs WHERE hash=?")
            .get(hash);
          if (row) zip.append(row.body, { name: "artifacts/" + hash });
        }
        for (const record of records) {
          if (!record.artifact) continue;
          let filename;
          if (record.category === "source" && record.data.path) {
            const parts = record.data.path
              .split(/[\\/]/)
              .filter((p) => p && p !== "." && p !== "..")
              .map((p) => p.replace(/[<>:"|?*\x00-\x1f]/g, "_"));
            filename = "source/" + parts.join("/");
          } else if (record.category === "git" && record.key === "bundle")
            filename = "git/repository.bundle";
          else if (record.category === "javascript")
            filename =
              "javascript/" +
              record.id +
              "-" +
              path
                .basename(new URL(record.key).pathname)
                .replace(/[^a-zA-Z0-9_.-]/g, "_");
          if (filename) {
            const blob = db
              .prepare("SELECT body FROM recon_blobs WHERE hash=?")
              .get(record.artifact);
            if (blob) zip.append(blob.body, { name: filename });
          }
        }
        zip.finalize();
      } else if (req.query.format === "txt") {
        res
          .attachment("recon-urls.txt")
          .type("text/plain")
          .send(
            [
              ...new Set(
                records
                  .map(
                    (r) =>
                      r.data.url || (/^https?:/.test(r.key) ? r.key : null),
                  )
                  .filter(Boolean),
              ),
            ].join("\n"),
          );
      } else
        res.attachment(`recon-${job.id}.json`).json({
          job,
          records: records.map((record) => ({
            ...record,
            ...(record.artifact
              ? {
                  bodyBase64: db
                    .prepare("SELECT body FROM recon_blobs WHERE hash=?")
                    .get(record.artifact)
                    ?.body.toString("base64"),
                }
              : {}),
          })),
        });
    } catch (e) {
      next(e);
    }
  });
  app.post("/api/recon/import-har", (req, res, next) => {
    try {
      req.body.session = ensureSession(req.body.session, req.body.target);
      const options = optionsFrom({ ...req.body, modules: [] });
      const entries = req.body.har?.log?.entries;
      if (!Array.isArray(entries))
        throw Error("Expected a HAR 1.2 file with log.entries.");
      if (entries.length > 20000)
        throw Error("HAR exceeds 20,000 entries; split it before importing.");
      const job = newJob(
        options,
        req.body.session,
        "HAR · " + String(req.body.name || "Imported traffic"),
      );
      let imported = 0;
      for (const [i, entry] of entries.entries()) {
        const url = entry.request?.url;
        if (!url) continue;
        const headers = Object.fromEntries(
          (entry.response?.headers || []).map((h) => [
            h.name.toLowerCase(),
            h.value,
          ]),
        );
        const content = entry.response?.content || {};
        const body = Buffer.from(
          content.text || "",
          content.encoding === "base64" ? "base64" : "utf8",
        );
        if (inScope(url, options)) {
          ingestTraffic(
            job,
            {
              id: i,
              url,
              method: entry.request.method,
              status: entry.response?.status,
              requestHeaders: Object.fromEntries(
                (entry.request.headers || []).map((h) => [
                  h.name.toLowerCase(),
                  h.value,
                ]),
              ),
              requestBody: entry.request.postData?.text || "",
              responseHeaders: headers,
              text: body.toString("utf8"),
              body,
              duration: entry.time,
              isjs: /javascript/.test(headers["content-type"] || ""),
            },
            options,
            req.body.mobile ? "mobile-HAR" : "HAR",
          );
          if (req.body.mobile)
            add(job, "mobile", String(i), `${entry.request.method} ${url}`, {
              source: "mobile-HAR",
              url,
              status: entry.response?.status,
              role: options.role,
            });
          imported++;
        }
      }
      stage(
        job,
        "HAR import",
        "complete",
        `${imported} in-scope requests imported from ${entries.length} entries`,
      );
      db.prepare("UPDATE recon_jobs SET status='complete' WHERE id=?").run(job);
      res.json({ id: job, session: req.body.session, imported });
    } catch (e) {
      next(e);
    }
  });
  app.get("/api/recon/roles", (req, res) => {
    const rows = db
      .prepare(
        "SELECT r.data,j.name,j.id job FROM recon_records r JOIN recon_jobs j ON j.id=r.job WHERE j.session=? AND r.category='authorization' ORDER BY r.id",
      )
      .all(req.query.session || "");
    const matrix = new Map();
    for (const row of rows) {
      const d = JSON.parse(row.data);
      const key =
        d.method + " " + new URL(d.url).origin + new URL(d.url).pathname;
      if (!matrix.has(key)) matrix.set(key, { endpoint: key, roles: {} });
      matrix.get(key).roles[d.role] = {
        status: d.status,
        size: d.size,
        bodyHash: d.bodyHash,
        job: row.job,
      };
    }
    res.json([...matrix.values()]);
  });
  require("./source-recon").mountSourceRecon(app, {
    db,
    add,
    stage,
    log,
    newJob,
    start,
    assertSession,
    ensureSession,
    optionsFrom,
    extract,
    parseAPI,
    exec,
    sha,
  });
  return { running, add, newJob, start, getJob, execute, ingestTraffic };
}
module.exports = { mountRecon, inScope, optionsFrom, CATEGORIES };
