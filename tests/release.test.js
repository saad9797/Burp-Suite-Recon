const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const script = fs.readFileSync(
  path.join(__dirname, "../scripts/release-check.js"),
);
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "traceglass-release-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  function put(file, body = "fixture") {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), body);
  }
  function git(...args) {
    const r = spawnSync("git", args, { cwd: root, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
  }
  git("init");
  for (const file of [
    "README.md",
    "LICENSE",
    "THIRD_PARTY.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/ROADMAP.md",
    ".github/workflows/ci.yml",
    "vendor/wappalyzer/LICENSE",
    "vendor/wappalyzer/src/wappalyzer.js",
    "vendor/wappalyzer/src/categories.json",
    "vendor/wappalyzer/src/technologies/a.json",
  ])
    put(file);
  put(".gitignore", "data/\n.env\n");
  put("package.json", JSON.stringify({ version: "1.0.0", dependencies: {} }));
  put(
    "package-lock.json",
    JSON.stringify({
      version: "1.0.0",
      packages: { "": { dependencies: {} } },
    }),
  );
  put("scripts/release-check.js", script);
  return {
    put,
    git,
    check: () =>
      spawnSync(process.execPath, ["scripts/release-check.js"], {
        cwd: root,
        encoding: "utf8",
      }),
  };
}
test("release gate accepts a clean source tree and ignores private local data", (t) => {
  const f = fixture(t);
  f.put("data/private.sqlite", "synthetic private fixture");
  f.put(".env", "SYNTHETIC_ONLY=1");
  const r = f.check();
  assert.equal(r.status, 0, r.stderr);
});
test("release gate rejects force-tracked private files even when ignored", (t) => {
  const f = fixture(t);
  f.put("data/private.sqlite");
  f.git("add", "--force", "data/private.sqlite");
  const r = f.check();
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Private artifact.*data\/private.sqlite/);
});
test("release gate rejects a missing publishable fingerprint database", (t) => {
  const f = fixture(t);
  f.put(".gitignore", "vendor/\n");
  const r = f.check();
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Missing publishable fingerprint/);
});
test("release gate rejects inconsistent dependency metadata", (t) => {
  const f = fixture(t);
  f.put(
    "package.json",
    JSON.stringify({ version: "1.0.0", dependencies: { unexpected: "1.0.0" } }),
  );
  const r = f.check();
  assert.equal(r.status, 1);
  assert.match(r.stderr, /lockfile disagree/);
});
