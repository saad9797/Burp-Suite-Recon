const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { httpxBinary, parsePort } = require("../runtime");
let failures = 0;
function report(name, ok, help, optional = false) {
  console.log(
    (ok ? "OK   " : optional ? "NOTE " : "FAIL ") +
      name +
      (ok ? "" : ": " + help),
  );
  if (!ok && !optional) failures++;
}
const [major, minor] = process.versions.node.split(".").map(Number);
report(
  "Node.js " + process.versions.node,
  major > 22 || (major === 22 && minor >= 19),
  "Install Node.js 22.19 or newer.",
);
try {
  const Database = require("better-sqlite3");
  const db = new Database(":memory:");
  db.prepare("SELECT 1").get();
  db.close();
  report("SQLite native module", true);
} catch {
  report(
    "SQLite native module",
    false,
    "Run npm ci for this Node version; native builds may need a C++ toolchain.",
  );
}
try {
  const browser = require("playwright").chromium.executablePath();
  report(
    "Playwright Chromium",
    fs.existsSync(browser),
    "Run npm run setup:browser (Linux: npx playwright install --with-deps chromium).",
  );
} catch {
  report("Playwright", false, "Run npm ci.");
}
const git = spawnSync("git", ["--version"], {
  encoding: "utf8",
  windowsHide: true,
  timeout: 5000,
});
report(
  "Git (source imports)",
  git.status === 0,
  "Install Git to enable repository imports.",
  true,
);
const probe = spawnSync(httpxBinary(), ["-version"], {
  encoding: "utf8",
  windowsHide: true,
  timeout: 5000,
});
report(
  "ProjectDiscovery httpx (optional)",
  probe.status === 0 &&
    /projectdiscovery/i.test((probe.stdout || "") + (probe.stderr || "")),
  "Install ProjectDiscovery httpx and set HTTPX_PATH. Capture works without it.",
  true,
);
try {
  parsePort(process.env.PORT);
  report("PORT", true);
} catch (e) {
  report("PORT", false, e.message);
}
for (const file of [
  "vendor/wappalyzer/src/wappalyzer.js",
  "vendor/wappalyzer/src/categories.json",
])
  report(
    file,
    fs.existsSync(path.join(__dirname, "..", file)),
    "Restore the vendored files from this repository.",
  );
console.log("Data: " + path.resolve("data") + " (unencrypted; keep private).");
process.exitCode = failures ? 1 : 0;
