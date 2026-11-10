function binaryKind(url = "", mime = "", prefix) {
  if (
    prefix &&
    /^\s*(?:<!doctype\s+html|<html(?:\s|>))/i.test(prefix.toString("utf8"))
  )
    return "html_response";
  if (
    /\.wasm(?:[?#]|$)/i.test(url) ||
    /application\/(?:wasm|x-webassembly)/i.test(mime) ||
    (prefix &&
      prefix.length >= 4 &&
      prefix[0] === 0 &&
      prefix.subarray(1, 4).toString() === "asm")
  )
    return "webassembly";
  if (
    /^(?:image|audio|video|font)\//i.test(mime) ||
    /application\/(?:pdf|zip|x-zip|gzip|x-7z|vnd\.rar)/i.test(mime)
  )
    return "binary";
  if (
    prefix?.length >= 4 &&
    (prefix.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 3, 4])) ||
      prefix.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47])) ||
      prefix.subarray(0, 4).toString() === "%PDF" ||
      prefix.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])))
  )
    return "binary";
  return null;
}
function isJavaScript(url, mime = "", resourceType = "", prefix) {
  if (binaryKind(url, mime, prefix)) return false;
  return (
    /\.m?js(?:[?#]|$)/i.test(url) ||
    /javascript|ecmascript/i.test(mime) ||
    resourceType === "script"
  );
}
module.exports = { binaryKind, isJavaScript };
