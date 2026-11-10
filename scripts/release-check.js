const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const root = path.resolve(__dirname, "..");
let failures = 0;
for (const file of [
  "README.md",
  "LICENSE",
  "THIRD_PARTY.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "docs/ROADMAP.md",
  "vendor/wappalyzer/LICENSE",
  "vendor/wappalyzer/src/wappalyzer.js",
  "vendor/wappalyzer/src/categories.json",
  ".gitignore",
  ".github/workflows/ci.yml",
])
  if (!fs.existsSync(path.join(root, file))) {
    console.error("Missing " + file);
    failures++;
  }
const pkg = require("../package.json"),
  lock = require("../package-lock.json");
if (
  pkg.version !== lock.version ||
  JSON.stringify(pkg.dependencies) !==
    JSON.stringify(lock.packages[""].dependencies)
) {
  console.error("Package metadata and lockfile disagree.");
  failures++;
}
const git = spawnSync(
  "git",
  ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
  { cwd: root, encoding: "utf8" },
);
if (git.status !== 0) {
  console.error("Initialize Git first: git init -b main");
  failures++;
} else {
  const files = git.stdout.split("\0").filter(Boolean);
  if (
    !files.some(
      (f) =>
        f.startsWith("vendor/wappalyzer/src/technologies/") &&
        f.endsWith(".json"),
    )
  ) {
    console.error("Missing publishable fingerprint database.");
    failures++;
  }
  for (const file of [
    "vendor/wappalyzer/src/wappalyzer.js",
    "vendor/wappalyzer/src/categories.json",
    "vendor/wappalyzer/LICENSE",
  ])
    if (!files.includes(file)) {
      console.error("Missing publishable vendor file: " + file);
      failures++;
    }
  const sensitive =
    /^(?:data|node_modules|test-results|playwright-report|coverage)\/|(?:^|\/)\.env(?:\.|$)|\.(?:sqlite(?:-.*)?|db|har|bundle|zip|pem|key|pfx|p12|log|exe)$|\.before-/i;
  for (const file of files)
    if (file !== ".env.example" && sensitive.test(file)) {
      console.error("Private artifact is publishable: " + file);
      failures++;
    }
  console.log(
    "Inspected " +
      files.length +
      " publishable paths; ignored local data is preserved.",
  );
}
console.log(
  "Path and metadata checks are not a credential scanner. Review staged contents before publishing.",
);
process.exitCode = failures ? 1 : 0;
