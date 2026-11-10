const http = require("node:http");
const https = require("node:https");
const zlib = require("node:zlib");
const crypto = require("node:crypto");

function requestSpec(input) {
  const url = new URL(input.url);
  if (!["http:", "https:"].includes(url.protocol))
    throw Error("Use an HTTP or HTTPS URL.");
  if (url.username || url.password)
    throw Error("Put credentials in the Authorization header.");
  const method = String(input.method || "GET").toUpperCase();
  if (!/^[!#$%&'*+.^_`|~\w-]+$/.test(method))
    throw Error("Invalid HTTP method.");
  if (method === "CONNECT")
    throw Error("CONNECT tunnels are not supported in this HTTP repeater.");
  if (
    !input.headers ||
    typeof input.headers !== "object" ||
    Array.isArray(input.headers)
  )
    throw Error("Headers must be a JSON object.");
  const headers = {};
  for (const [name, value] of Object.entries(input.headers)) {
    http.validateHeaderName(name);
    http.validateHeaderValue(name, value);
    if (typeof value !== "string")
      throw Error("Header values must be strings.");
    headers[name.toLowerCase()] = value;
  }
  if (
    input.encoding === "base64" &&
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      input.body || "",
    )
  )
    throw Error("Body is not valid padded Base64.");
  if (headers.upgrade)
    throw Error(
      "Protocol upgrades are not supported by this HTTP request editor.",
    );
  const body =
    input.encoding === "base64"
      ? Buffer.from(input.body || "", "base64")
      : Buffer.from(input.body || "", "utf8");
  return { url: url.href, method, headers, body };
}

class Interceptor {
  constructor(onForward) {
    this.enabled = false;
    this.queue = new Map();
    this.onForward = onForward;
    this.match = { method: "", url: "" };
  }
  async attach(ctx, session) {
    this.enabled = false;
    await ctx.route("**/*", async (route) => {
      const req = route.request();
      const matches = () =>
        this.enabled &&
        (!this.match.method || req.method() === this.match.method) &&
        (!this.match.url ||
          req.url().toLowerCase().includes(this.match.url.toLowerCase()));
      if (!matches()) {
        await route.continue().catch(() => {});
        return;
      }
      const headers = await req.allHeaders().catch(() => req.headers());
      if (!matches()) {
        await route.continue().catch(() => {});
        return;
      }
      const bytes = req.postDataBuffer() || Buffer.alloc(0);
      const text = bytes.toString("utf8");
      const encoding = Buffer.from(text).equals(bytes) ? "utf8" : "base64";
      const id = crypto.randomUUID();
      let release;
      const held = new Promise((r) => {
        release = r;
      });
      this.queue.set(id, {
        id,
        session,
        created: new Date().toISOString(),
        url: req.url(),
        method: req.method(),
        type: req.resourceType(),
        headers,
        body: encoding === "utf8" ? text : bytes.toString("base64"),
        encoding,
        route,
        req,
        release,
        busy: false,
      });
      await held;
    });
    ctx.on("close", () => {
      this.enabled = false;
      for (const item of this.queue.values()) item.release();
      this.queue.clear();
    });
  }
  state() {
    return {
      enabled: this.enabled,
      match: this.match,
      queue: [...this.queue.values()].map(
        ({ route, req, release, busy, ...item }) => ({ ...item, busy }),
      ),
    };
  }
  async resolve(id, action, input) {
    const item = this.queue.get(id);
    if (!item) throw Error("This request is no longer held.");
    if (item.busy) throw Error("This request is already being released.");
    let spec;
    if (action === "forward" && input) {
      spec = requestSpec(input);
      if (new URL(spec.url).protocol !== new URL(item.url).protocol)
        throw Error(
          "Browser forwarding must keep the same URL protocol. Use Repeater to change HTTP ↔ HTTPS.",
        );
      for (const name of ["host", "cookie", "connection", "content-length"]) {
        if (name in spec.headers && spec.headers[name] !== item.headers[name])
          throw Error(
            `${name} is browser-managed. Edit this header in Repeater instead.`,
          );
        if (
          name in item.headers &&
          !(name in spec.headers) &&
          name === "cookie"
        )
          throw Error(
            "Browser cookies come from its cookie jar. Use Repeater to remove Cookie.",
          );
        delete spec.headers[name];
      }
    }
    item.busy = true;
    try {
      if (action === "drop") await item.route.abort("blockedbyclient");
      else if (action === "forward") {
        await item.route.continue(
          spec
            ? {
                url: spec.url,
                method: spec.method,
                headers: spec.headers,
                postData: spec.body,
              }
            : {},
        );
        if (spec) this.onForward(item.req, spec);
      } else throw Error("Choose forward or drop.");
      return { ok: true };
    } catch (e) {
      await item.route.abort("failed").catch(() => {});
      throw Error("Could not release request: " + e.message);
    } finally {
      this.queue.delete(id);
      item.release();
    }
  }
  async disable() {
    this.enabled = false;
    return Promise.allSettled(
      [...this.queue.keys()].map((id) => this.resolve(id, "forward")),
    );
  }
  async dropAll() {
    this.enabled = false;
    return Promise.allSettled(
      [...this.queue.keys()].map((id) => this.resolve(id, "drop")),
    );
  }
}

function sendRequest(spec, { timeout = 30000, verifyTLS = true, signal } = {}) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const url = new URL(spec.url);
    const headers = { ...spec.headers };
    // Recalculate framing after edits; preserve explicit Host and Cookie in Repeater.
    delete headers["content-length"];
    delete headers["transfer-encoding"];
    delete headers.connection;
    if (spec.body.length || !["GET", "HEAD"].includes(spec.method))
      headers["content-length"] = String(spec.body.length);
    const req = (url.protocol === "https:" ? https : http).request(
      url,
      { method: spec.method, headers, rejectUnauthorized: verifyTLS, signal },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on("data", (chunk) => {
          size += chunk.length;
          if (size > 100 * 1024 * 1024) {
            res.destroy(Error("Response exceeds the 100 MiB repeater limit."));
            return;
          }
          chunks.push(chunk);
        });
        res.on("error", reject);
        res.on("end", () => {
          let body = Buffer.concat(chunks),
            decodeError = "";
          try {
            const encoding = res.headers["content-encoding"];
            if (encoding === "gzip")
              body = zlib.gunzipSync(body, {
                maxOutputLength: 100 * 1024 * 1024,
              });
            else if (encoding === "deflate")
              body = zlib.inflateSync(body, {
                maxOutputLength: 100 * 1024 * 1024,
              });
            else if (encoding === "br")
              body = zlib.brotliDecompressSync(body, {
                maxOutputLength: 100 * 1024 * 1024,
              });
          } catch (e) {
            decodeError = "Could not decode body: " + e.message;
          }
          resolve({
            status: res.statusCode,
            statusText: res.statusMessage,
            headers: res.rawHeaders.reduce((a, v, i, all) => {
              if (i % 2 === 0) a.push({ name: v, value: all[i + 1] });
              return a;
            }, []),
            text: body.toString("utf8"),
            bodyBase64: body.toString("base64"),
            size: body.length,
            wireSize: size,
            duration: Date.now() - started,
            error: decodeError,
          });
        });
      },
    );
    const timer = setTimeout(
      () => req.destroy(Error(`Request timed out after ${timeout / 1000}s.`)),
      timeout,
    );
    req.on("close", () => clearTimeout(timer));
    req.on("error", reject);
    req.end(spec.body);
  });
}

function mountWorkbench(app, { db, getContext, getActive, onForward }) {
  db.exec(
    "CREATE TABLE IF NOT EXISTS repeater(id TEXT PRIMARY KEY,session TEXT,name TEXT,created TEXT,request TEXT,response TEXT); CREATE INDEX IF NOT EXISTS repeater_session ON repeater(session,created);",
  );
  const interceptor = new Interceptor(onForward);
  const inflight = new Map();
  app.get("/api/intercept", (req, res) => res.json(interceptor.state()));
  app.post("/api/intercept", async (req, res, next) => {
    try {
      if (!getContext()) throw Error("Open a capture browser first.");
      if (typeof req.body.enabled !== "boolean")
        throw Error("enabled must be a boolean.");
      if (req.body.enabled) {
        interceptor.match = {
          method: String(req.body.method || "").toUpperCase(),
          url: String(req.body.url || ""),
        };
        interceptor.enabled = true;
      } else await interceptor.disable();
      res.json(interceptor.state());
    } catch (e) {
      next(e);
    }
  });
  app.post("/api/intercept/:id", async (req, res, next) => {
    try {
      res.json(
        await interceptor.resolve(
          req.params.id,
          req.body.action,
          req.body.request,
        ),
      );
    } catch (e) {
      next(e);
    }
  });
  app.get("/api/repeater", (req, res) =>
    res.json(
      db
        .prepare(
          "SELECT id,session,name,created,json_extract(response,'$.status') status,json_extract(response,'$.duration') duration FROM repeater WHERE session=? ORDER BY created DESC LIMIT 200",
        )
        .all(req.query.session || ""),
    ),
  );
  app.get("/api/repeater/:id", (req, res) => {
    const row = db
      .prepare("SELECT * FROM repeater WHERE id=?")
      .get(req.params.id);
    if (!row) return res.sendStatus(404);
    res.json({
      ...row,
      request: JSON.parse(row.request),
      response: JSON.parse(row.response),
    });
  });
  app.post("/api/repeater/send", async (req, res, next) => {
    const id = crypto.randomUUID();
    try {
      const spec = requestSpec(req.body);
      const session = String(req.body.session || getActive() || "");
      if (!db.prepare("SELECT id FROM sessions WHERE id=?").get(session))
        throw Error("Select or create a capture session first.");
      const clientId = String(req.body.clientId || id);
      if (inflight.has(clientId))
        throw Error("This request is already in flight.");
      const controller = new AbortController();
      inflight.set(clientId, controller);
      let response;
      try {
        response = await sendRequest(spec, {
          timeout: Math.max(
            1000,
            Math.min(120000, Number(req.body.timeout) || 30000),
          ),
          verifyTLS: req.body.verifyTLS !== false,
          signal: controller.signal,
        });
      } catch (e) {
        response = {
          status: 0,
          text: "",
          bodyBase64: "",
          size: 0,
          duration: 0,
          headers: [],
          error: e.message,
        };
      } finally {
        inflight.delete(clientId);
      }
      const request = {
        url: spec.url,
        method: spec.method,
        headers: spec.headers,
        body: req.body.body || "",
        encoding: req.body.encoding || "utf8",
      };
      const name = String(
        req.body.name || `${spec.method} ${new URL(spec.url).pathname}`,
      ).slice(0, 160);
      const created = new Date().toISOString();
      db.prepare("INSERT INTO repeater VALUES(?,?,?,?,?,?)").run(
        id,
        session,
        name,
        created,
        JSON.stringify(request),
        JSON.stringify(response),
      );
      res.json({ id, session, name, created, request, response });
    } catch (e) {
      next(e);
    }
  });
  app.post("/api/repeater/cancel", (req, res) => {
    const controller = inflight.get(req.body.clientId);
    if (controller) controller.abort();
    res.json({ ok: !!controller });
  });
  app.get("/api/repeater/:id/body", (req, res) => {
    const row = db
      .prepare("SELECT response FROM repeater WHERE id=?")
      .get(req.params.id);
    if (!row) return res.sendStatus(404);
    res
      .attachment("repeater-" + req.params.id + ".bin")
      .type("application/octet-stream")
      .send(Buffer.from(JSON.parse(row.response).bodyBase64 || "", "base64"));
  });
  return interceptor;
}
module.exports = { mountWorkbench, requestSpec, sendRequest };
