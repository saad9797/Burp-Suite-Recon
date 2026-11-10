const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");
const { chromium } = require("playwright");
process.env.PORT = "0";
const testDatabasePath = require("node:path").join(
  require("node:os").tmpdir(),
  "traceglass-integration-" + require("node:crypto").randomUUID() + ".sqlite",
);
process.env.TRACEGLASS_DB = testDatabasePath;
test("real browser capture, search, exports, fingerprints and UI", async () => {
  const { server, db, launch, pending } = require("../server");
  await new Promise((r) =>
    server.listening ? r() : server.once("listening", r),
  );
  const base = "http://127.0.0.1:" + server.address().port;
  const bootstrap = await (await fetch(base + "/bootstrap.js")).text();
  const token = JSON.parse(bootstrap.split("=")[1]);
  const api = async (url, body) => {
    const r = await fetch(base + "/api/" + url, {
      method: body ? "POST" : "GET",
      headers: { "x-capture-token": token, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    assert.equal(r.status, 200, await r.clone().text());
    return r.json();
  };
  const received = [];
  const fixture = http.createServer((req, res) => {
    received.push(req.url);
    if (req.url.startsWith("/echo")) {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            url: req.url,
            method: req.method,
            body: Buffer.concat(chunks).toString(),
            header: req.headers["x-edited"],
            cookie: req.headers.cookie,
          }),
        );
      });
      return;
    }
    if (req.url === "/slow") {
      setTimeout(() => res.end("late"), 1200);
      return;
    }
    if (req.url === "/redirect") {
      res.writeHead(302, { location: "/echo-redirect" });
      res.end();
      return;
    }
    if (req.url === "/app.js") {
      res.setHeader("Content-Type", "application/javascript");
      res.end('window.fixture="script-needle-123";');
    } else if (req.url === "/submit") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ result: "response-needle-456" }));
    } else {
      res.setHeader("Content-Type", "text/html");
      res.setHeader("X-Powered-By", "Express");
      res.end(
        '<html><head><meta name="generator" content="WordPress 6.0"><script src="/app.js"></script></head><body><h1>Fixture</h1></body></html>',
      );
    }
  });
  await new Promise((r) => fixture.listen(0, "127.0.0.1", r));
  const id = "test-" + Date.now();
  db.prepare("INSERT INTO sessions VALUES(?,?,?)").run(
    id,
    "Integration test",
    new Date().toISOString(),
  );
  let ctx, ui;
  try {
    ctx = await launch(id, "chromium", true);
    const page = ctx.pages()[0];
    await page.goto("http://127.0.0.1:" + fixture.address().port);
    await page.evaluate(() =>
      fetch("/submit", { method: "POST", body: "request-needle-789" }).then(
        (r) => r.text(),
      ),
    );
    await page.waitForTimeout(500);
    await Promise.allSettled([...pending]);
    let list = await api("traffic?session=" + id);
    assert.ok(list.total >= 3);
    assert.equal(
      (
        await api(
          "traffic?session=" + id + "&method=POST&q=response-needle-456",
        )
      ).total,
      1,
    );
    assert.equal(
      (await api("traffic?session=" + id + "&q=request-needle-789")).total,
      1,
    );
    assert.equal(
      (await api("traffic?session=" + id + "&js=1&q=script-needle-123")).total,
      1,
    );
    assert.equal((await api("traffic?session=" + id + "&q=%25")).total, 0);
    const tech = await api("technologies?session=" + id);
    assert.ok(tech.some((r) => r.result.some((t) => t.name === "WordPress")));
    const har = await api("export?session=" + id + "&format=har&method=POST");
    assert.equal(har.log.entries.length, 1);
    assert.match(
      Buffer.from(
        har.log.entries[0].response.content.text,
        "base64",
      ).toString(),
      /response-needle/,
    );
    const zip = await fetch(
      base + "/api/export?session=" + id + "&js=1&format=zip",
      { headers: { "x-capture-token": token } },
    );
    assert.equal(
      Buffer.from(await zip.arrayBuffer()).readUInt32LE(),
      0x04034b50,
    );
    const noToken = await fetch(base + "/api/state");
    assert.equal(noToken.status, 403);
    const cross = await fetch(base + "/bootstrap.js", {
      headers: { "sec-fetch-site": "cross-site" },
    });
    assert.equal(cross.status, 403);
    // A held browser request must not reach the fixture until explicitly forwarded.
    const origin = "http://127.0.0.1:" + fixture.address().port;
    await api("intercept", { enabled: true, method: "POST", url: "/echo" });
    const heldFetch = page.evaluate(() =>
      fetch("/echo-original", { method: "POST", body: "original" }).then((r) =>
        r.json(),
      ),
    );
    const waitQueue = async (count) => {
      for (let attempt = 0; attempt < 100; attempt++) {
        const state = await api("intercept");
        if (state.queue.length === count) return state;
        await new Promise((r) => setTimeout(r, 20));
      }
      throw Error("Queue did not reach " + count);
    };
    let intercepted = await waitQueue(1);
    assert.ok(!received.includes("/echo-original"));
    const held = intercepted.queue[0];
    await api("intercept/" + held.id, {
      action: "forward",
      request: {
        ...held,
        url: origin + "/echo-edited",
        headers: { ...held.headers, "x-edited": "yes" },
        body: "changed",
      },
    });
    assert.deepEqual(await heldFetch, {
      url: "/echo-edited",
      method: "POST",
      body: "changed",
      header: "yes",
    });
    await waitQueue(0);
    const dropFetch = page.evaluate(() =>
      fetch("/echo-drop", { method: "POST" }).then(
        () => false,
        () => true,
      ),
    );
    intercepted = await waitQueue(1);
    await api("intercept/" + intercepted.queue[0].id, { action: "drop" });
    assert.equal(await dropFetch, true);
    assert.ok(!received.includes("/echo-drop"));
    const multiple = page.evaluate(() =>
      Promise.all(
        ["/echo-a", "/echo-b"].map((url) =>
          fetch(url, { method: "POST", body: url }).then((r) => r.json()),
        ),
      ),
    );
    await waitQueue(2);
    await api("intercept", { enabled: false });
    assert.equal((await multiple).length, 2);
    await waitQueue(0);
    // Repeater preserves explicit cookies and edited headers, and can send repeatedly.
    const first = await api("repeater/send", {
      session: id,
      url: origin + "/echo-repeat",
      method: "POST",
      headers: {
        "content-type": "text/plain",
        "x-edited": "repeated",
        cookie: "test=123",
        "content-length": "999",
      },
      body: "repeat-body",
      clientId: "test-first",
    });
    assert.equal(first.response.status, 200);
    assert.deepEqual(JSON.parse(first.response.text), {
      url: "/echo-repeat",
      method: "POST",
      body: "repeat-body",
      header: "repeated",
      cookie: "test=123",
    });
    const second = await api("repeater/send", {
      session: id,
      url: origin + "/echo-repeat2",
      method: "PUT",
      headers: { "x-edited": "second" },
      body: "second-body",
    });
    assert.equal(JSON.parse(second.response.text).method, "PUT");
    const redirect = await api("repeater/send", {
      session: id,
      url: origin + "/redirect",
      method: "GET",
      headers: {},
    });
    assert.equal(redirect.response.status, 302);
    const cancelSend = api("repeater/send", {
      session: id,
      url: origin + "/slow",
      method: "GET",
      headers: {},
      clientId: "cancel-test",
    });
    await new Promise((r) => setTimeout(r, 100));
    await api("repeater/cancel", { clientId: "cancel-test" });
    assert.match((await cancelSend).response.error, /abort/i);
    assert.equal((await api("repeater?session=" + id)).length, 4);
    if (require("fs").existsSync("tools/httpx.exe")) {
      const probe = await api("httpx", { session: id });
      assert.ok(probe.count >= 1);
      assert.ok(
        (await api("technologies?session=" + id)).some(
          (r) => r.engine === "httpx",
        ),
      );
    }
    ui = await chromium.launch({ headless: true });
    const view = await ui.newPage({ viewport: { width: 1500, height: 1000 } });
    const errors = [];
    view.on("pageerror", (e) => errors.push(e.message));
    await view.goto(base);
    await view.getByText("Integration test", { exact: true }).first().click();
    await view.locator("#search").fill("response-needle-456");
    await view.waitForTimeout(600);
    await view.locator("#traffic tr").first().click();
    await view.locator('[data-detail="source"]').click();
    assert.match(
      await view.locator("#detailContent").textContent(),
      /response-needle/,
    );
    await view.locator("#closeInspector").click();
    await view.locator('[data-tab="tech"]').click();
    await view.waitForTimeout(300);
    assert.match(
      await view.locator("#technologies").textContent(),
      /WordPress/,
    );
    require("fs").mkdirSync("test-results", { recursive: true });
    await view.screenshot({ path: "test-results/technologies.png" });
    await view.locator("[data-tab=traffic]").click();
    await view.locator("#reset").click();
    await view.waitForTimeout(500);
    await view.screenshot({ path: "test-results/traffic.png" });
    await view.locator("#search").fill("echo-edited");
    await view.waitForTimeout(500);
    await view.locator("#traffic tr").first().click();
    await view.locator("#sendToRepeater").click();
    assert.equal(await view.locator("#repeatMethod").inputValue(), "POST");
    await view.locator("#repeatBody").fill("from-repeater-ui");
    await view.locator("#repeatSend").click();
    await view.waitForFunction(() =>
      document.getElementById("repeatSummary").textContent.includes("200"),
    );
    assert.match(
      await view.locator("#repeatResponse").textContent(),
      /from-repeater-ui/,
    );
    await view.locator("#repeatBody").fill("second-ui-send");
    await view.locator("#repeatSend").click();
    await view.waitForFunction(() =>
      document
        .getElementById("repeatResponse")
        .textContent.includes("second-ui-send"),
    );
    assert.match(
      await view.locator("#repeatComparison").textContent(),
      /body changed/,
    );
    await view.locator("#repeatGroupName").fill("Login flow");
    await view.locator("#repeatGroupCreate").click();
    const firstTab = await view
      .locator("[data-open-tab]")
      .first()
      .getAttribute("data-open-tab");
    await view.locator("#repeaterNew").click();
    await view.locator("#repeatUrl").fill(base + "/draft");
    await view.locator("#repeatBody").fill("unsent draft");
    await view.locator("#repeatGroup").selectOption({ label: "Login flow" });
    await view.locator(`[data-open-tab="${firstTab}"]`).click();
    assert.equal(
      await view.locator("#repeatBody").inputValue(),
      "second-ui-send",
    );
    await view
      .context()
      .grantPermissions(["clipboard-read", "clipboard-write"]);
    await view.locator("#repeatGroupCopy").click();
    const context = JSON.parse(
      await view.evaluate(() => navigator.clipboard.readText()),
    );
    assert.equal(context.group, "Login flow");
    assert.equal(context.requests.length, 2);
    assert.equal(context.requests[0].lastExchange.response.status, 200);
    assert.equal(context.requests[1].request.body, "unsent draft");
    await view.locator("[data-close-tab]").last().click();
    assert.equal(await view.locator("[data-open-tab]").count(), 1);
    await view.screenshot({ path: "test-results/repeater.png" });
    await view.locator('[data-tab="intercept"]').click();
    await view.locator("#captureGroupName").fill("Checkout flow");
    await view.locator("#captureGroupCreate").click();
    await view.locator("#interceptMethod").selectOption("POST");
    await view.locator("#interceptUrl").fill("/echo-ui");
    await view.locator("#interceptToggle").click();
    const uiHold = page.evaluate(() =>
      fetch("/echo-ui", { method: "POST", body: "held-ui" }).then((r) =>
        r.json(),
      ),
    );
    await waitQueue(1);
    await view.waitForFunction(
      () => !document.getElementById("interceptEditor").hidden,
    );
    await view.locator("#heldBody").fill("edited-in-ui");
    await view.screenshot({ path: "test-results/intercept.png" });
    await view.locator("#heldForward").click();
    assert.equal((await uiHold).body, "edited-in-ui");
    const secondHold = page.evaluate(() =>
      fetch("/echo-ui-second", {
        method: "POST",
        body: "second-group-request",
      }).then((r) => r.json()),
    );
    await waitQueue(1);
    await view.waitForFunction(() =>
      document.getElementById("heldUrl").value.endsWith("/echo-ui-second"),
    );
    await view.locator("#heldForward").click();
    await secondHold;
    await api("intercept", { enabled: false });
    await view.locator("#captureGroupSend").click();
    assert.equal(
      await view.locator("#repeatBody").inputValue(),
      "second-group-request",
    );
    assert.equal(
      await view.locator("#repeatGroup option:checked").textContent(),
      "Checkout flow",
    );
    await view.locator("#repeatGroupCopy").click();
    const collected = JSON.parse(
      await view.evaluate(() => navigator.clipboard.readText()),
    );
    assert.equal(collected.requests.length, 2);
    assert.equal(collected.requests[0].request.body, "edited-in-ui");
    assert.equal(collected.requests[1].request.body, "second-group-request");
    await view.reload();
    await view.locator('[data-tab="repeater"]').click();
    assert.equal(await view.locator("[data-open-tab]").count(), 3);
    assert.equal(
      await view.locator("#repeatBody").inputValue(),
      "second-group-request",
    );
    assert.deepEqual(errors, []);
  } finally {
    if (ui) await ui.close();
    if (ctx) await ctx.close();
    await Promise.allSettled([...pending]);
    db.prepare("DELETE FROM traffic WHERE session=?").run(id);
    db.prepare("DELETE FROM technologies WHERE session=?").run(id);
    db.prepare("DELETE FROM sessions WHERE id=?").run(id);
    db.prepare("DELETE FROM repeater WHERE session=?").run(id);
    await new Promise((r) => fixture.close(r));
    await new Promise((r) => server.close(r));
    db.close();
    for (const ext of ["", "-wal", "-shm"])
      require("node:fs").rmSync(testDatabasePath + ext, { force: true });
  }
});
