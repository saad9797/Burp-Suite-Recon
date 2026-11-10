const path = require("node:path");
const fs = require("node:fs");
function parsePort(value) {
  const text = String(value ?? "4310");
  if (!/^\d+$/.test(text) || Number(text) > 65535)
    throw new Error("PORT must be an integer between 0 and 65535.");
  return Number(text);
}
function httpxBinary(
  env = process.env,
  platform = process.platform,
  root = __dirname,
) {
  if (env.HTTPX_PATH) return env.HTTPX_PATH;
  const local = path.join(
    root,
    "tools",
    platform === "win32" ? "httpx.exe" : "httpx",
  );
  return fs.existsSync(local) ? local : "httpx";
}
module.exports = { parsePort, httpxBinary };
