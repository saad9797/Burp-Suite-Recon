const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const root = path.resolve(__dirname, "..");
const files = [];
function walk(dir) {
  for (const entry of fs.readdirSync(path.join(root, dir), {
    withFileTypes: true,
  })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(file);
    else if (file.endsWith(".js")) files.push(file);
  }
}
for (const file of fs.readdirSync(root))
  if (file.endsWith(".js")) files.push(file);
for (const dir of ["public", "scripts", "tests"]) walk(dir);
let failed = false;
for (const file of files) {
  const result = spawnSync(
    process.execPath,
    ["--check", path.join(root, file)],
    { encoding: "utf8" },
  );
  if (result.status !== 0) {
    failed = true;
    console.error(result.stderr || result.error);
  }
}
console.log("Checked " + files.length + " JavaScript files.");
process.exitCode = failed ? 1 : 0;
