const { test } = require("node:test");
const assert = require("node:assert/strict");
const express = require("express");
const Database = require("better-sqlite3");
const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");
const zlib = require("node:zlib");
const { chromium } = require("playwright");
const { mountRecon } = require("../recon");
const { mountHandoff } = require("../handoff");
const {
  analyzeJavaScript,
  endpointIdentity,
  bodyParameters,
  idName,
} = require("../handoff-analysis");
// Assemble a synthetic scanner fixture without storing a complete API-key-shaped value.
const stripeSecretFixture = ["sk", "live", "0123456789AbCdEfGhJkLmNoPq"].join(
  "_",
);
function unzip(buffer) {
  let end = buffer.length - 22;
  while (end >= 0 && buffer.readUInt32LE(end) !== 0x06054b50) end--;
  assert.ok(end >= 0);
  let cursor = buffer.readUInt32LE(end + 16);
  const count = buffer.readUInt16LE(end + 10),
    files = new Map();
  for (let i = 0; i < count; i++) {
    assert.equal(buffer.readUInt32LE(cursor), 0x02014b50);
    const method = buffer.readUInt16LE(cursor + 10),
      size = buffer.readUInt32LE(cursor + 20),
      nameLen = buffer.readUInt16LE(cursor + 28),
      extra = buffer.readUInt16LE(cursor + 30),
      comment = buffer.readUInt16LE(cursor + 32),
      local = buffer.readUInt32LE(cursor + 42);
    const name = buffer.subarray(cursor + 46, cursor + 46 + nameLen).toString();
    const offset =
      local +
      30 +
      buffer.readUInt16LE(local + 26) +
      buffer.readUInt16LE(local + 28);
    const data = buffer.subarray(offset, offset + size);
    files.set(name, method === 8 ? zlib.inflateRawSync(data) : data);
    cursor += 46 + nameLen + extra + comment;
  }
  return files;
}
test("parameter shapes and traceable local JavaScript triage", () => {
  const e = endpointIdentity(
    "https://api.test/v1/users/12/invoices/550e8400-e29b-41d4-a716-446655440000?owner_id=5&page=2",
    "GET",
  );
  assert.equal(e.looks_like_object_id, true);
  assert.ok(e.params.includes("user_id"));
  assert.ok(e.parameter_details.some((p) => p.id_shapes.includes("uuid")));
  assert.equal(
    e.parameter_details.find((p) => p.name === "page").looks_like_object_id,
    false,
  );
  assert.equal(idName("valid"), false);
  assert.equal(idName("userId"), true);
  assert.ok(
    endpointIdentity("https://api.test/users/$%7Buser.id%7D", "GET")
      .looks_like_object_id,
  );
  const body = bodyParameters(
    '{"customerId":482,"quantity":2,"nested":{"invoice_id":"abc"}}',
    "application/json",
  );
  assert.ok(
    body.some((p) => p.name === "nested.invoice_id" && p.looks_like_object_id),
  );
  assert.equal(
    body.find((p) => p.name === "quantity").looks_like_object_id,
    false,
  );
  const js =
    'const token = account.token;\nconst featureFlags = {new_checkout_v2: true};\nfetch(`/api/invoices/${invoiceId}`, {method:"POST",body:JSON.stringify({customerId: user.id, quantity:2})});\nconst secret="' +
    stripeSecretFixture +
    '"; const fakeToken="example_placeholder_token_value";\nconst route="/internal/admin/export";';
  const found = analyzeJavaScript(js, "app.min.js");
  assert.ok(found.feature_flags.includes("new_checkout_v2"));
  const post = found.endpoint_evidence.find((r) => r.method === "POST");
  assert.equal(post.line, 3);
  assert.equal(js[post.offset], "`");
  assert.ok(post.parameter_details.some((p) => p.name === "customerId"));
  assert.ok(found.internal_routes.includes("/internal/admin/export"));
  assert.ok(found.potential_secrets.some((s) => s.confidence === "high"));
  assert.ok(found.potential_secrets.some((s) => s.confidence === "low"));
  assert.ok(
    !JSON.stringify(found.potential_secrets).includes(stripeSecretFixture),
  );
});
test(
  "sandbox package, stable diffs, raw sample links, manual auth and UI",
  { timeout: 120000 },
  async () => {
    const db = new Database(":memory:");
    db.exec(
      "CREATE TABLE sessions(id TEXT PRIMARY KEY,name TEXT,created TEXT);CREATE TABLE traffic(id INTEGER PRIMARY KEY,session TEXT,url TEXT,method TEXT,status INTEGER,type TEXT,requestHeaders TEXT,requestBody TEXT,responseHeaders TEXT,body BLOB,text TEXT,error TEXT,isjs INTEGER);CREATE TABLE technologies(session TEXT,origin TEXT,engine TEXT,result TEXT);",
    );
    db.prepare("INSERT INTO sessions VALUES(?,?,?)").run(
      "handoff-test",
      "Sandbox handoff",
      new Date().toISOString(),
    );
    let phase = 1,
      requests = 0;
    const js = () =>
      `const featureFlags={new_checkout_v2:true};\nconst liveKey="${stripeSecretFixture}";\nfetch('/api/v1/invoices/482?owner_id=10&page=1');\nfetch('/api/v1/invoices/483?owner_id=11&page=2');\nfetch(\`/api/v1/users/\${userId}/invoices\`,{method:'POST',body:JSON.stringify({tenantId:tenant.id})});\nconst internal='/internal/admin/export';\n${phase === 3 ? "fetch('/api/new-feature');" : ""}`;
    const fixture = http.createServer((req, res) => {
      requests++;
      res.setHeader("x-request-id", String(requests));
      res.setHeader("x-powered-by", "Express/4.18");
      if (req.headers["x-fixture-host"] === "staging.sandbox.test") {
        res.setHeader("content-type", "text/html");
        res.end("<title>Staging Admin Panel</title>");
        return;
      }
      if (req.url === "/") {
        res.setHeader("content-type", "text/html");
        res.end(
          '<title>Sandbox billing</title><script src="/app.js"></script><a href="/api/v1/invoices/482?owner_id=10&page=1">invoice</a>',
        );
      } else if (req.url === "/app.js") {
        res.setHeader("content-type", "application/javascript");
        res.end(js());
      } else if (req.url === "/swagger.json") {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            openapi: "3.0.0",
            info: { title: "Billing" },
            components: {
              schemas: {
                ReviewInput: {
                  type: "object",
                  properties: {
                    reference: { type: "string", format: "uuid" },
                    quantity: { type: "integer", example: 2 },
                    metadata: {
                      type: "object",
                      properties: { projectId: { type: "integer" } },
                    },
                  },
                },
              },
            },
            paths: {
              "/api/v1/invoices/{invoiceId}": {
                get: {
                  parameters: [
                    {
                      name: "invoiceId",
                      in: "path",
                      schema: { type: "integer" },
                    },
                  ],
                },
              },
              "/schema-only/{recordId}": {
                servers: [{ url: "/service" }],
                post: {
                  requestBody: {
                    content: {
                      "application/json": {
                        schema: { $ref: "#/components/schemas/ReviewInput" },
                      },
                    },
                  },
                },
              },
            },
          }),
        );
      } else if (req.url.startsWith("/api/v1/invoices/")) {
        res.setHeader("content-type", "application/json");
        res.end('{"invoiceId":482,"owner":"account-a","total":10}');
      } else {
        res.statusCode = 404;
        res.end("not found");
      }
    });
    await new Promise((r) => fixture.listen(0, "127.0.0.1", r));
    const fixtureBase = "http://127.0.0.1:" + fixture.address().port;
    const app = express();
    app.use(express.json({ limit: "20mb" }));
    app.get("/bootstrap.js", (req, res) =>
      res.type("js").send('window.CAPTURE_TOKEN="test"'),
    );
    app.use(express.static("public"));
    const fetcher = (url, init) => {
      const u = new URL(url);
      if (u.hostname === "crt.sh")
        return Promise.resolve(
          new Response(
            JSON.stringify([{ name_value: "staging.sandbox.test" }]),
          ),
        );
      if (u.hostname.endsWith("sandbox.test"))
        return fetch(fixtureBase + u.pathname + u.search, {
          ...init,
          headers: { ...init?.headers, "x-fixture-host": u.hostname },
        });
      throw Error("Unexpected external request");
    };
    const recon = mountRecon(app, {
      db,
      W: { analyze: () => [], resolve: () => [] },
      externalFetch: fetcher,
    });
    const handoff = mountHandoff(app, { db });
    app.get("/api/state", (req, res) =>
      res.json({
        active: null,
        paused: false,
        sessions: [
          {
            id: "handoff-test",
            name: "Sandbox handoff",
            created: new Date().toISOString(),
            count: 0,
          },
        ],
      }),
    );
    app.get("/api/intercept", (req, res) =>
      res.json({ enabled: false, queue: [] }),
    );
    app.get("/api/traffic", (req, res) => res.json({ rows: [], total: 0 }));
    app.use((e, req, res, next) => res.status(400).json({ error: e.message }));
    const server = app.listen(0, "127.0.0.1");
    await new Promise((r) => server.once("listening", r));
    const base = "http://127.0.0.1:" + server.address().port;
    const api = async (url, body, status = 200) => {
      const r = await fetch(base + "/api/" + url, {
        method: body ? "POST" : "GET",
        headers: { "content-type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
      assert.equal(r.status, status, await r.clone().text());
      return r.json();
    };
    const scan = async () => {
      const started = await api("recon/start", {
        session: "handoff-test",
        target: "http://sandbox.test",
        subdomains: true,
        modules: ["ct", "probe", "crawl", "paths"],
        paths: "swagger.json",
        maxRequests: 25,
        delay: 50,
      });
      for (let i = 0; i < 300; i++) {
        const j = await api("recon/jobs/" + started.id);
        if (!["queued", "running"].includes(j.status)) {
          assert.equal(j.status, "complete", JSON.stringify(j.stages));
          recon.add(
            started.id,
            "technologies",
            "http://sandbox.test:Express",
            "Express",
            {
              source: "sandbox fingerprint",
              origin: "http://sandbox.test",
              name: "Express",
              version: phase === 3 ? "4.19" : "4.18",
              confidence: 100,
            },
          );
          recon.add(
            started.id,
            "javascript",
            "https://cdn.vendor.test/loader.js",
            "https://cdn.vendor.test/loader.js",
            {
              source: "browser-dependency",
              passive_only: true,
              in_scope: false,
            },
            Buffer.from('fetch("/api/cdn-derived");'),
          );
          return started.id;
        }
        await new Promise((r) => setTimeout(r, 25));
      }
      throw Error("Sandbox scan timed out");
    };
    let browser;
    try {
      const first = await scan();
      const support = [];
      for (const role of ["account-a", "account-b"]) {
        const response = await fetch(
          fixtureBase + "/api/v1/invoices/482?owner_id=10&page=1",
          { headers: { "x-account": role } },
        );
        const body = await response.text();
        const h = await api("recon/import-har", {
          session: "handoff-test",
          target: "http://sandbox.test",
          subdomains: true,
          role,
          har: {
            log: {
              entries: [
                {
                  request: {
                    url: "http://sandbox.test/api/v1/invoices/482?owner_id=10&page=1",
                    method: "GET",
                    headers: [{ name: "x-account", value: role }],
                  },
                  response: {
                    status: response.status,
                    headers: [
                      { name: "content-type", value: "application/json" },
                    ],
                    content: { text: body },
                  },
                },
              ],
            },
          },
        });
        support.push(h.id);
      }
      const initial = await api("handoff/build", {
        primary: first,
        jobs: [first, ...support],
        baseline: "none",
        name: "Sandbox baseline",
      });
      assert.equal(initial.diff.initial_baseline, true);
      const p1 = handoff.readPackage(initial.id).document;
      assert.ok(
        p1.assets.some(
          (a) =>
            a.host === "staging.sandbox.test" &&
            a.is_non_production_candidate &&
            a.title === "Staging Admin Panel",
        ),
      );
      assert.ok(p1.assets.some((a) => a.tech_stack.includes("Express 4.18")));
      const invoice = p1.endpoints.find(
        (e) =>
          e.method === "GET" &&
          e.url === "http://sandbox.test/api/v1/invoices/{invoiceId}",
      );
      assert.ok(invoice);
      assert.ok(invoice.params.includes("owner_id"));
      assert.ok(invoice.params.includes("invoiceId"));
      assert.equal(
        invoice.parameter_details.find((p) => p.name === "page")
          .looks_like_object_id,
        false,
      );
      assert.ok(invoice.traffic_samples.length);
      assert.ok(
        p1.endpoints.some(
          (e) => e.url === "http://sandbox.test/api/cdn-derived",
        ),
      );
      assert.ok(!p1.endpoints.some((e) => e.url.includes("${")));
      const schemaOnly = p1.endpoints.find(
        (e) => e.url === "http://sandbox.test/service/schema-only/{recordId}",
      );
      assert.ok(schemaOnly);
      assert.ok(schemaOnly.params.includes("metadata.projectId"));
      assert.ok(
        schemaOnly.parameter_details.some(
          (p) => p.name === "reference" && p.id_shapes.includes("uuid"),
        ),
      );
      assert.equal(
        schemaOnly.parameter_details.find((p) => p.name === "quantity")
          .looks_like_object_id,
        false,
      );
      assert.ok(
        !p1.endpoints.some(
          (e) => e.url === "http://sandbox.test/schema-only/{recordId}",
        ),
      );
      assert.equal(
        p1.js_findings
          .find((f) => f.file.endsWith("/app.js"))
          .potential_secrets.filter((s) => s.kind === "Stripe secret key")
          .length,
        1,
      );
      assert.equal(
        p1.auth_map.find((e) => e.endpoint_key === invoice.key).flag,
        "not_tested",
      );
      assert.match(initial.summary, /object-ID|object-reference|object-ID/i);
      assert.ok(!initial.summary.includes(stripeSecretFixture));
      phase = 2;
      const second = await scan();
      const unchanged = await api("handoff/build", {
        primary: second,
        jobs: [second, ...support],
        baseline: "auto",
        name: "Unchanged sandbox",
      });
      assert.equal(unchanged.diff.baseline_id, initial.id);
      for (const cat of ["assets", "endpoints", "javascript", "secrets"])
        for (const key of ["added", "changed", "not_observed"])
          assert.equal(unchanged.diff[cat][key].length, 0, cat + " " + key);
      assert.match(unchanged.diff_markdown, /No inventory changes observed/);
      phase = 3;
      const third = await scan();
      const changed = await api("handoff/build", {
        primary: third,
        jobs: [third, ...support],
        baseline: "auto",
        name: "Sandbox final handoff",
      });
      assert.ok(
        changed.diff.endpoints.added.some((e) =>
          e.label.includes("/api/new-feature"),
        ),
      );
      assert.ok(
        changed.diff.assets.changed.some((a) =>
          a.changed_fields.includes("tech_stack"),
        ),
      );
      assert.equal(changed.diff.javascript.changed.length, 1);
      const auth = handoff
        .readPackage(changed.id)
        .document.auth_map.find((e) => e.endpoint_key === invoice.key);
      await api(
        "handoff/packages/" + changed.id + "/auth/" + auth.id,
        { flag: "possible_idor" },
        400,
      );
      const review = {
        account_a_label: "account-a owner",
        account_b_label: "account-b outsider",
        account_a_result: "200 OK returns invoice owned by A",
        account_b_result: "200 OK returns the same invoice; expected denial",
        expected_account_b_access: "deny",
        ownership_notes: "Controlled sandbox invoice belongs to account A.",
        flag: "possible_idor",
        review_status: "reviewed",
        auth_required: "yes",
        checklist: auth.checklist.map((c) => ({ ...c, done: true })),
      };
      await api("handoff/packages/" + changed.id + "/auth/" + auth.id, review);
      const updated = await api("handoff/packages/" + changed.id);
      assert.match(updated.summary, /manually flagged possible IDOR/);
      const download = await fetch(
        base + "/api/handoff/packages/" + changed.id + "/download",
      );
      const archive = Buffer.from(await download.arrayBuffer()),
        files = unzip(archive),
        prefix = "target_recon_package/";
      for (const name of [
        "summary.md",
        "assets.json",
        "endpoints.json",
        "js_findings.json",
        "auth_map.json",
        "diff_from_last_run.md",
      ])
        assert.ok(files.has(prefix + name), name);
      const exportedEndpoints = JSON.parse(
        files.get(prefix + "endpoints.json"),
      );
      for (const [filename, content] of files)
        if (filename.endsWith("/pair.json")) {
          const pair = JSON.parse(content);
          for (const ref of [
            pair.request.body_file,
            pair.response.body_file,
          ].filter(Boolean)) {
            const target = path.posix.normalize(
              path.posix.join(path.posix.dirname(filename), ref),
            );
            assert.ok(files.has(target), "Missing shared body " + target);
          }
          assert.equal(pair.request.body_base64, undefined);
        }
      for (const e of exportedEndpoints) {
        assert.ok(Array.isArray(e.params));
        for (const ref of e.traffic_samples) assert.ok(files.has(prefix + ref));
      }
      const exportedJS = JSON.parse(files.get(prefix + "js_findings.json"));
      for (const f of exportedJS) {
        assert.ok(files.has(prefix + f.original_file));
        for (const secret of f.potential_secrets)
          assert.ok(secret.location.line > 0 && secret.location.column > 0);
      }
      assert.equal(
        JSON.parse(files.get(prefix + "auth_map.json")).find(
          (e) => e.id === auth.id,
        ).flag,
        "possible_idor",
      );
      await fs.mkdir("test-results", { recursive: true });
      await fs.writeFile("test-results/target_recon_package.zip", archive);
      const out = path.resolve("test-results/sandbox_handoff");
      for (const [filename, content] of files) {
        const absolute = path.resolve(out, filename);
        assert.ok(absolute.startsWith(out + path.sep));
        await fs.mkdir(path.dirname(absolute), { recursive: true });
        await fs.writeFile(absolute, content);
      }
      browser = await chromium.launch({ headless: true });
      const view = await browser.newPage({
        viewport: { width: 1550, height: 1100 },
      });
      const errors = [];
      view.on("pageerror", (e) => errors.push(e.message));
      await view.goto(base);
      await view.locator('[data-tab="handoff"]').click();
      await view.waitForFunction(() =>
        document
          .getElementById("handoffPreview")
          .textContent.includes("Highest-priority candidates"),
      );
      await view.locator('[data-handoff-view="auth_map"]').click();
      await view.waitForTimeout(300);
      await view.locator("#handoffSearch").fill("invoiceId");
      await view.waitForTimeout(300);
      await view.locator("#handoffRows tr").first().click();
      await view.locator("#authNotes").fill("Reviewed through the browser UI.");
      await view.locator("#handoffAuthSave").click();
      await view.waitForFunction(
        () => !document.getElementById("handoffAuthDialog").open,
      );
      await view.locator('[data-handoff-view="summary"]').click();
      await view.screenshot({ path: "test-results/handoff.png" });
      await view.locator("#handoffBuildOpen").click();
      await view.locator("#handoffPrimary").selectOption(third);
      await view.locator("#handoffName").fill("UI-built package");
      await view.locator("#handoffBuild").click();
      await view.waitForFunction(
        () => !document.getElementById("handoffBuildDialog").open,
      );
      await view.waitForFunction(() =>
        document
          .getElementById("handoffPackages")
          .selectedOptions[0]?.textContent.includes("UI-built package"),
      );
      assert.match(
        await view.locator("#handoffPreview").textContent(),
        /Target:/,
      );
      assert.deepEqual(errors, []);
    } finally {
      if (browser) await browser.close();
      for (const task of recon.running.values()) task.controller.abort();
      await Promise.allSettled(
        [...recon.running.values()].map((t) => t.promise),
      );
      await new Promise((r) => server.close(r));
      await new Promise((r) => fixture.close(r));
      db.close();
    }
  },
);
