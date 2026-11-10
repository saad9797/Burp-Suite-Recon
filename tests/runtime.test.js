const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parsePort, httpxBinary } = require("../runtime");
test("port parsing supports ephemeral ports and rejects invalid values", () => {
  assert.equal(parsePort(), 4310);
  assert.equal(parsePort("0"), 0);
  assert.equal(parsePort("65535"), 65535);
  for (const value of [
    "",
    "-1",
    "1.5",
    "65536",
    "NaN",
    "4310junk",
    "/tmp/socket",
  ])
    assert.throws(() => parsePort(value), /PORT/);
});
test("httpx override is preserved and missing bundled binaries use PATH", () => {
  assert.equal(
    httpxBinary({ HTTPX_PATH: "C:/custom/httpx.exe" }),
    "C:/custom/httpx.exe",
  );
  const missing = require("node:path").join(
    require("node:os").tmpdir(),
    require("node:crypto").randomUUID(),
  );
  assert.equal(httpxBinary({}, "linux", missing), "httpx");
  assert.equal(httpxBinary({}, "win32", missing), "httpx");
});
