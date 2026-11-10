const { Worker } = require("node:worker_threads");
const path = require("node:path");
const { binaryKind } = require("./media-kind");
const VERSION = "bounded-js-v1";
const PRESETS = {
  balanced: {
    astFile: 2 * 1048576,
    astTotal: 15 * 1048576,
    patternFile: 256 * 1024,
    patternTotal: 6 * 1048576,
    jsMs: 30000,
    fileMs: 2000,
    packageMs: 60000,
  },
  quick: {
    astFile: 512 * 1024,
    astTotal: 5 * 1048576,
    patternFile: 256 * 1024,
    patternTotal: 2 * 1048576,
    jsMs: 15000,
    fileMs: 1500,
    packageMs: 40000,
  },
  inventory: {
    astFile: 0,
    astTotal: 0,
    patternFile: 0,
    patternTotal: 0,
    jsMs: 5000,
    fileMs: 1000,
    packageMs: 30000,
  },
};
function profile(name) {
  return {
    name: PRESETS[name] ? name : "balanced",
    ...(PRESETS[name] || PRESETS.balanced),
  };
}
function workerAnalysis(
  bytes,
  options,
  timeout,
  workerFile = path.join(__dirname, "handoff-js-worker.js"),
) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const worker = new Worker(workerFile, {
      workerData: { bytes, options },
      resourceLimits: { maxOldGenerationSizeMb: 192, stackSizeMb: 4 },
    });
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.terminate().catch(() => {});
      error ? reject(error) : resolve(result);
    };
    const timer = setTimeout(
      () => finish(Error("JavaScript worker reached its hard time limit.")),
      Math.max(1, timeout),
    );
    worker.on("message", (m) =>
      m.error ? finish(Error(m.error)) : finish(null, m.result),
    );
    worker.on("error", (e) =>
      finish(Error("JavaScript worker stopped: " + e.message)),
    );
    worker.on("exit", (code) => {
      if (!settled)
        finish(
          Error("JavaScript worker exited without a result (" + code + ")."),
        );
    });
  });
}
function emptyFinding(hash, bytes, note) {
  return {
    file: "__content__",
    sha256: hash,
    bytes,
    analysis_method: "inventory only; no parsing performed",
    analysis_notes: [note],
    analysis_status: "skipped",
    endpoints_found: [],
    endpoint_evidence: [],
    potential_secrets: [],
    feature_flags: [],
    feature_flag_evidence: [],
    internal_routes: [],
    params: [],
    parameter_evidence: [],
    unverified: true,
  };
}
function rebind(value, file) {
  if (Array.isArray(value)) return value.map((v) => rebind(v, file));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, v]) => [
        key,
        key === "file" && v === "__content__" ? file : rebind(v, file),
      ]),
    );
  return value;
}
function priority(script, target) {
  let score = 0;
  try {
    if (script.file.startsWith("source:")) score += 35;
    else if (new URL(script.file).hostname === new URL(target).hostname)
      score += 50;
  } catch {}
  if (
    /app|main|checkout|billing|account|auth|admin|workspace/i.test(script.file)
  )
    score += 25;
  if (
    /vendor|polyfill|react|jquery|analytics|gtag|segment|sentry|captcha|recaptcha|akamai/i.test(
      script.file,
    )
  )
    score -= 45;
  if (script.size > 2 * 1048576) score -= 30;
  return score;
}
async function analyzeScripts({
  db,
  scripts,
  target,
  analysisProfile = "balanced",
  onProgress = () => {},
}) {
  db.exec(
    "CREATE TABLE IF NOT EXISTS handoff_js_cache(hash TEXT,version TEXT,mode TEXT,result TEXT,created TEXT,PRIMARY KEY(hash,version,mode));",
  );
  const budget = profile(analysisProfile),
    started = Date.now();
  let astBytes = 0,
    patternBytes = 0;
  const sizes = new Map(
    db
      .prepare("SELECT hash,length(body) bytes FROM recon_blobs")
      .all()
      .map((r) => [r.hash, r.bytes]),
  );
  const ordered = scripts
    .map((s) => ({ ...s, size: sizes.get(s.artifact) || 0 }))
    .sort(
      (a, b) =>
        priority(b, target) - priority(a, target) ||
        a.size - b.size ||
        a.file.localeCompare(b.file),
    );
  const memo = new Map(),
    results = [];
  const stats = {
    profile: budget.name,
    total_files: ordered.length,
    unique_contents: new Set(ordered.map((s) => s.artifact)).size,
    full_ast: 0,
    pattern_only: 0,
    skipped: 0,
    non_javascript: 0,
    binary_dependencies: [],
    non_javascript_assets: [],
    cache_hits: 0,
    deduplicated: 0,
    timeouts: 0,
    ast_bytes: 0,
    pattern_bytes: 0,
    elapsed_ms: 0,
    limits: budget,
  };
  const cached = (hash, mode) => {
    const row = db
      .prepare(
        "SELECT result FROM handoff_js_cache WHERE hash=? AND version=? AND mode=?",
      )
      .get(hash, VERSION, mode);
    return row ? JSON.parse(row.result) : null;
  };
  for (const script of ordered) {
    onProgress({
      phase: "javascript",
      completed: results.length,
      total: ordered.length,
      current_file: script.file,
      stats: { ...stats },
    });
    const header = db
      .prepare("SELECT substr(body,1,160) body FROM recon_blobs WHERE hash=?")
      .get(script.artifact)?.body;
    const kind = binaryKind(script.file, "", header);
    if (kind) {
      const finding = emptyFinding(
        script.artifact,
        script.size,
        `${kind} dependency retained as original evidence; it is not JavaScript and was not parsed.`,
      );
      finding.analysis_status = "not_javascript";
      finding.asset_type = kind;
      stats.non_javascript++;
      const asset = {
        file: script.file,
        hash: script.artifact,
        bytes: script.size,
        kind,
      };
      stats.non_javascript_assets.push(asset);
      if (kind !== "html_response") stats.binary_dependencies.push(asset);
      results.push({ script, finding: rebind(finding, script.file) });
      continue;
    }
    let result = memo.get(script.artifact);
    if (result) {
      stats.deduplicated++;
    } else {
      result = cached(script.artifact, "ast");
      if (result) {
        stats.cache_hits++;
      } else {
        const patternCache = cached(script.artifact, "pattern");
        const remaining = budget.jsMs - (Date.now() - started);
        const vendor =
          /vendor|polyfill|react(?:[.-]|$)|jquery|analytics|gtag|segment|sentry|captcha|recaptcha/i.test(
            script.file,
          );
        let mode =
          !vendor &&
          script.size <= budget.astFile &&
          astBytes + script.size <= budget.astTotal
            ? "ast"
            : "pattern";
        if (mode === "pattern" && patternCache) {
          result = patternCache;
          stats.cache_hits++;
        } else if (remaining < 250 || (!budget.astFile && !budget.patternFile))
          result = emptyFinding(
            script.artifact,
            script.size,
            remaining < 250
              ? "The package JavaScript time budget was exhausted. Original evidence is retained."
              : "Inventory-only profile: original JavaScript retained; fresh analysis was not requested.",
          );
        else if (
          mode === "pattern" &&
          patternBytes + Math.min(script.size, budget.patternFile) >
            budget.patternTotal
        )
          result = emptyFinding(
            script.artifact,
            script.size,
            "Total bounded-pattern byte budget reached. Original evidence is retained.",
          );
        else {
          const max =
            mode === "ast"
              ? script.size
              : Math.min(script.size, budget.patternFile);
          const bytes =
            db
              .prepare(
                "SELECT substr(body,1,?) body FROM recon_blobs WHERE hash=?",
              )
              .get(max, script.artifact)?.body || Buffer.alloc(0);
          if (mode === "ast") astBytes += bytes.length;
          else patternBytes += bytes.length;
          try {
            result = await workerAnalysis(
              bytes,
              {
                patternOnly: mode === "pattern",
                noLoose: true,
                maxBytes: max || 1,
                maxNodes: 250000,
                maxFindings: 2000,
                maxSecrets: 100,
              },
              Math.min(budget.fileMs, remaining),
            );
          } catch (error) {
            stats.timeouts++;
            const left = budget.jsMs - (Date.now() - started);
            const count = Math.min(script.size, budget.patternFile);
            if (
              mode === "ast" &&
              left > 300 &&
              patternBytes + count <= budget.patternTotal
            ) {
              const prefix =
                db
                  .prepare(
                    "SELECT substr(body,1,?) body FROM recon_blobs WHERE hash=?",
                  )
                  .get(count, script.artifact)?.body || Buffer.alloc(0);
              patternBytes += prefix.length;
              mode = "pattern";
              try {
                result = await workerAnalysis(
                  prefix,
                  {
                    patternOnly: true,
                    noLoose: true,
                    maxBytes: count || 1,
                    maxFindings: 2000,
                    maxSecrets: 100,
                  },
                  Math.min(1000, left),
                );
                result.analysis_notes.push(
                  error.message + " Used bounded patterns instead.",
                );
              } catch {
                result = emptyFinding(
                  script.artifact,
                  script.size,
                  "Worker time/memory limit reached. Original evidence retained; no absence of findings can be inferred.",
                );
              }
            } else
              result = emptyFinding(
                script.artifact,
                script.size,
                error.message + " Original evidence retained.",
              );
          }
          result.sha256 = script.artifact;
          result.bytes = script.size;
          if (result.analysis_status !== "skipped") {
            result.analysis_status =
              mode === "ast" && result.analysis_method.startsWith("AST")
                ? "ast"
                : "pattern";
            result.analyzed_bytes = max;
            if (mode === "pattern") {
              result.analyzed_bytes = Math.min(script.size, budget.patternFile);
              if (script.size > result.analyzed_bytes)
                result.analysis_notes.push(
                  `Only the first ${result.analyzed_bytes} of ${script.size} bytes were scanned with bounded patterns. Full AST parsing was skipped; the complete original is retained.`,
                );
            }
            db.prepare(
              "INSERT OR REPLACE INTO handoff_js_cache VALUES(?,?,?,?,?)",
            ).run(
              script.artifact,
              VERSION,
              mode,
              JSON.stringify(result),
              new Date().toISOString(),
            );
          }
        }
      }
      memo.set(script.artifact, result);
    }
    if (result.analysis_status === "ast") stats.full_ast++;
    else if (result.analysis_status === "pattern") stats.pattern_only++;
    else stats.skipped++;
    results.push({ script, finding: rebind(result, script.file) });
    await new Promise((r) => setImmediate(r));
  }
  stats.ast_bytes = astBytes;
  stats.pattern_bytes = patternBytes;
  stats.elapsed_ms = Date.now() - started;
  onProgress({
    phase: "javascript_complete",
    completed: ordered.length,
    total: ordered.length,
    stats,
  });
  return { results, stats };
}
module.exports = { profile, workerAnalysis, analyzeScripts, priority };
