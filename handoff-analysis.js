const crypto = require("node:crypto");
const acorn = require("acorn");
const loose = require("acorn-loose");
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const sorted = (value) => [...new Set(value)].sort();
const controlName = (name) =>
  /^(?:page|limit|offset|size|count|per_page|pagesize|page_size|amount|price|quantity|qty|timeout|timestamp|version|year|month|day|sort|order)$/i.test(
    String(name).split(".").pop(),
  );
const idCandidate = (name, shape) =>
  idName(name) || !!(shape && (shape !== "numeric" || !controlName(name)));
const idName = (input) => {
  const name = String(input).split(".").pop();
  return (
    /^(?:id|uuid|guid)$/i.test(name) ||
    /[_-](?:id|uuid|guid)$/i.test(name) ||
    /[a-z]Id$|ID$/.test(name) ||
    /^(?:user|account|invoice|order|project|tenant|org|document|file|record|customer)id$/i.test(
      name,
    )
  );
};
function idShape(value) {
  const s = String(value);
  if (/^\d+$/.test(s)) return "numeric";
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s))
    return "uuid";
  if (/^[0-9a-f]{24}$/i.test(s)) return "objectid";
  return null;
}
function pathName(previous, index) {
  let name = previous
    .replace(/[^a-zA-Z0-9_]/g, "_")
    .replace(/ies$/, "y")
    .replace(/s$/, "");
  if (!name || /^v\d+$/.test(name)) name = "object";
  return name + "_id" + (index ? "_" + index : "");
}
function endpointIdentity(raw, method = "UNKNOWN", base) {
  let url;
  try {
    url = new URL(String(raw).replace(/\$\{([\w.]+)\}/g, "{$1}"), base);
  } catch {
    return null;
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password
  )
    return null;
  const details = [];
  const add = (name, location, value, extra = {}) => {
    const existing = details.find(
      (d) => d.name === name && d.location === location,
    );
    const shape = value == null ? null : idShape(value);
    if (existing) {
      if (value != null && !existing.examples.includes(String(value)))
        existing.examples.push(String(value));
      existing.id_shapes = sorted([
        ...existing.id_shapes,
        ...(shape ? [shape] : []),
      ]);
      existing.looks_like_object_id ||= idCandidate(name, shape);
      return;
    }
    details.push({
      name,
      location,
      examples: value == null ? [] : [String(value)],
      id_shapes: shape ? [shape] : [],
      looks_like_object_id: idCandidate(name, shape),
      ...extra,
    });
  };
  const segments = url.pathname.split("/").map((s) => {
    try {
      return decodeURIComponent(s).replace(/^\$\{([^}]+)\}$/, "{$1}");
    } catch {
      return s;
    }
  });
  const names = new Set();
  const pattern = segments
    .map((segment, i) => {
      const placeholder = segment.match(/^(?:\{([^}]+)\}|:([\w]+))$/);
      if (placeholder) {
        const name = placeholder[1] || placeholder[2];
        add(name, "path", null, { inferred: false });
        names.add(name);
        return "{" + name + "}";
      }
      const shape = idShape(segment);
      if (shape && i > 1) {
        let name = pathName(segments[i - 1], 0),
          n = 1;
        while (names.has(name)) name = pathName(segments[i - 1], n++);
        names.add(name);
        add(name, "path", segment, { inferred: true });
        return "{" + name + "}";
      }
      return segment;
    })
    .join("/");
  for (const [name, value] of url.searchParams)
    add(name, "query", value, { inferred: false });
  const normalizedMethod = String(method || "UNKNOWN").toUpperCase();
  return {
    key: normalizedMethod + " " + url.origin + pattern,
    url: url.origin + pattern,
    method: normalizedMethod,
    observed_url: url.href,
    params: details.map((d) => d.name),
    parameter_details: details,
    looks_like_object_id: details.some((d) => d.looks_like_object_id),
  };
}
function bodyParameters(text, contentType = "") {
  const result = [];
  const add = (name, value, location = "body") =>
    result.push({
      name,
      location,
      examples:
        typeof value === "string" || typeof value === "number"
          ? [String(value)]
          : [],
      id_shapes: idShape(value) ? [idShape(value)] : [],
      looks_like_object_id: idCandidate(name.split(".").pop(), idShape(value)),
      inferred: false,
    });
  if (!text) return result;
  if (/json/i.test(contentType) || /^\s*[\[{]/.test(text))
    try {
      const object = JSON.parse(text);
      const stack = [{ value: object, prefix: "" }];
      let n = 0;
      while (stack.length && n++ < 20000) {
        const { value, prefix } = stack.pop();
        if (value && typeof value === "object") {
          for (const [key, v] of Object.entries(value)) {
            const field = Array.isArray(value)
              ? prefix + "[]"
              : prefix
                ? prefix + "." + key
                : key;
            if (v && typeof v === "object")
              stack.push({ value: v, prefix: field });
            else add(field, v);
          }
        }
      }
      return result;
    } catch {}
  if (/x-www-form-urlencoded/i.test(contentType))
    for (const [name, value] of new URLSearchParams(text)) add(name, value);
  if (/multipart\/form-data/i.test(contentType))
    for (const m of text.matchAll(
      /content-disposition:[^\r\n]*\bname="([^"\r\n]+)"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n([^\r\n]*)/gi,
    ))
      add(m[1], m[2]);
  return result;
}
function locationAt(text, offset) {
  const before = text.slice(0, offset),
    last = before.lastIndexOf("\n");
  return {
    line: before.split("\n").length,
    column: offset - (last + 1) + 1,
    offset,
  };
}
const sensitiveContext = (value) =>
  String(value).replace(
    /\b(?:sk_(?:live|test)_[\w]+|(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]+|eyJ[A-Za-z0-9_.-]{20,})/g,
    "[redacted-secret]",
  );
function analyzeJavaScript(input, file, options = {}) {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const limit = options.maxBytes || 20 * 1048576;
  const text = bytes.subarray(0, limit).toString("utf8");
  const lineStarts = [0];
  for (let i = 0; i < text.length; i++)
    if (text[i] === "\n") lineStarts.push(i + 1);
  const loc = (offset) => {
    let lo = 0,
      hi = lineStarts.length;
    while (lo + 1 < hi) {
      const mid = (lo + hi) >> 1;
      if (lineStarts[mid] <= offset) lo = mid;
      else hi = mid;
    }
    return { line: lo + 1, column: offset - lineStarts[lo] + 1, offset };
  };
  const routes = [],
    flags = [],
    parameters = [],
    secrets = [],
    notes = [];
  let parseMode = options.patternOnly ? "bounded pattern extraction" : "AST";
  if (bytes.length > limit)
    notes.push(
      `Analysis limited to the first ${limit} bytes; the complete original is retained.`,
    );
  const evidence = (node, kind) => ({ file, ...loc(node?.start || 0), kind });
  function value(node, depth = 0) {
    if (depth > 64) return null;
    if (!node) return null;
    if (node.type === "Literal")
      return typeof node.value === "string" ? node.value : null;
    if (node.type === "TemplateLiteral") {
      let s = "";
      for (let i = 0; i < node.quasis.length; i++) {
        s += node.quasis[i].value.cooked || node.quasis[i].value.raw || "";
        if (node.expressions[i]) {
          const e = node.expressions[i];
          s +=
            "{" +
            (e.name ||
              text
                .slice(e.start, e.end)
                .replace(/[^\w.]/g, "")
                .slice(0, 80) ||
              "dynamic") +
            "}";
        }
      }
      return s;
    }
    if (node.type === "BinaryExpression" && node.operator === "+") {
      const left = value(node.left, depth + 1),
        right = value(node.right, depth + 1);
      if (left != null && right != null) return left + right;
      if (left != null && node.right.type === "Identifier")
        return left + "{" + node.right.name + "}";
      if (node.left.type === "Identifier" && right != null)
        return "{" + node.left.name + "}" + right;
    }
    return null;
  }
  const prop = (node) =>
    node?.type === "Identifier" ? node.name : node?.value;
  const nameOf = (node) =>
    node?.type === "Identifier"
      ? node.name
      : node?.type === "MemberExpression"
        ? [nameOf(node.object), prop(node.property)].filter(Boolean).join(".")
        : "";
  function route(raw, node, method = "UNKNOWN", kind = "string_literal") {
    if (routes.length >= (options.maxFindings || 5000)) {
      if (!notes.includes("Route finding limit reached."))
        notes.push("Route finding limit reached.");
      return;
    }
    if (typeof raw === "string") raw = raw.replace(/\$\{([\w.]+)\}/g, "{$1}");
    if (
      typeof raw !== "string" ||
      raw.length > 3000 ||
      !/^(?:https?:\/\/|\/|\.\.?\/)/.test(raw) ||
      /^\/\//.test(raw) ||
      /[\n\r<>]/.test(raw)
    )
      return;
    const finding = {
      url: raw,
      method,
      ...evidence(node, kind),
      params: [...raw.matchAll(/\{([^}]+)\}|:([a-zA-Z_]\w*)/g)].map(
        (m) => m[1] || m[2],
      ),
    };
    routes.push(finding);
    return finding;
  }
  function staticParams(node, location, prefix = "") {
    if (
      node?.type === "CallExpression" &&
      /stringify$/.test(nameOf(node.callee))
    )
      node = node.arguments[0];
    if (
      node?.type === "NewExpression" &&
      nameOf(node.callee) === "URLSearchParams"
    )
      node = node.arguments[0];
    if (node?.type !== "ObjectExpression") return [];
    const result = [];
    for (const p of node.properties) {
      const key = prop(p.key);
      if (!key) continue;
      const name = prefix ? prefix + "." + key : String(key);
      if (p.value?.type === "ObjectExpression")
        result.push(...staticParams(p.value, location, name));
      else {
        const raw = p.value?.type === "Literal" ? p.value.value : null;
        result.push({
          name,
          location,
          examples: raw == null ? [] : [String(raw)],
          id_shapes: raw != null && idShape(raw) ? [idShape(raw)] : [],
          looks_like_object_id: idCandidate(
            String(key),
            raw != null ? idShape(raw) : null,
          ),
          inferred: true,
          ...evidence(p, "JavaScript request field"),
        });
      }
    }
    return result;
  }
  function withConfig(route, config, body) {
    if (!route) return;
    route.parameter_details = [...staticParams(body, "body")];
    if (config?.type === "ObjectExpression")
      for (const p of config.properties) {
        const key = prop(p.key);
        if (["body", "data", "json"].includes(key))
          route.parameter_details.push(...staticParams(p.value, "body"));
        if (["params", "query", "searchParams"].includes(key))
          route.parameter_details.push(...staticParams(p.value, "query"));
      }
  }
  function secret(raw, node, label) {
    if (secrets.length >= (options.maxSecrets || 200)) {
      if (!notes.includes("Secret candidate limit reached."))
        notes.push("Secret candidate limit reached.");
      return;
    }
    if (typeof raw !== "string" || raw.length < 8) return;
    if (["'", '"', "`"].includes(text[node.start]))
      node = { start: node.start + 1 };
    const known = [
      ["Stripe secret key", /^sk_live_[A-Za-z0-9]{16,}$/, "high"],
      ["Stripe test secret key", /^sk_test_[A-Za-z0-9]{16,}$/, "medium"],
      ["AWS access key ID", /^(?:AKIA|ASIA)[A-Z0-9]{16}$/, "medium"],
      [
        "GitHub token",
        /^(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{30,})$/,
        "high",
      ],
      [
        "Private key material",
        /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
        "high",
      ],
      [
        "JWT-shaped token",
        /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
        "medium",
      ],
    ];
    let match = known.find(([, re]) => re.test(raw));
    let kind = match?.[0],
      confidence = match?.[2],
      reason = match
        ? "Recognized credential format; validity and privilege are unverified."
        : "";
    const placeholder =
      /example|placeholder|changeme|your[_-]|dummy|fake|sample|xxx|test[-_]?token|not[-_]?real/i.test(
        raw,
      );
    if (
      !match &&
      /(?:secret|token|password|api.?key|authorization)/i.test(label || "")
    ) {
      if (raw.length < 16) return;
      const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z0-9]/].filter((re) =>
        re.test(raw),
      ).length;
      kind = "Credential-like assignment";
      confidence = classes >= 3 && raw.length >= 24 ? "medium" : "low";
      reason =
        "Sensitive assignment name with a literal value; naming alone does not prove a secret.";
    }
    if (!kind) return;
    if (placeholder) {
      confidence = "low";
      reason = "Placeholder/test wording reduces confidence; verify manually.";
    }
    secrets.push({
      kind,
      confidence,
      match: raw.slice(0, 4) + "…" + raw.slice(-4),
      fingerprint: hash(raw),
      context: `line ${loc(node.start).line}, column ${loc(node.start).column}`,
      location: evidence(node, "secret_candidate"),
      reason,
      verified: false,
      label: label || null,
    });
  }
  let ast;
  if (!options.patternOnly)
    try {
      ast = acorn.parse(text, {
        ecmaVersion: "latest",
        sourceType: "module",
        allowHashBang: true,
        locations: false,
      });
    } catch {
      if (options.noLoose) {
        parseMode = "pattern fallback";
        notes.push(
          "Invalid/unsupported syntax; error-tolerant AST recovery skipped to keep processing bounded.",
        );
      } else {
        parseMode = "error-tolerant AST";
        try {
          ast = loose.parse(text, {
            ecmaVersion: "latest",
            sourceType: "module",
          });
        } catch (e) {
          parseMode = "pattern fallback";
          notes.push("Parser unavailable for this file: " + e.message);
        }
      }
    }
  if (ast) {
    const stack = [{ node: ast, parent: null }];
    let visited = 0;
    while (stack.length) {
      const { node, parent } = stack.pop();
      if (++visited > (options.maxNodes || 250000)) {
        notes.push("AST node budget reached; patterns still analyzed.");
        break;
      }
      if (!node || typeof node.type !== "string") continue;
      const str = value(node);
      if (
        (node.type === "Literal" && typeof node.value === "string") ||
        node.type === "TemplateLiteral"
      )
        route(str, node);
      if (
        node.type === "VariableDeclarator" ||
        node.type === "Property" ||
        node.type === "AssignmentExpression"
      ) {
        const label =
          node.type === "VariableDeclarator"
            ? nameOf(node.id)
            : node.type === "Property"
              ? prop(node.key)
              : nameOf(node.left);
        const val =
          node.type === "VariableDeclarator"
            ? node.init
            : node.type === "Property"
              ? node.value
              : node.right;
        secret(value(val), val || node, label);
        if (
          /(?:feature.?flags?|flags?|experiments?|toggles?)/i.test(label || "")
        ) {
          if (val?.type === "ObjectExpression")
            for (const p of val.properties || []) {
              const key = prop(p.key);
              if (key)
                flags.push({
                  name: String(key),
                  ...evidence(p, "feature_flag_object"),
                });
            }
          else if (typeof value(val) === "string")
            flags.push({
              name: value(val),
              ...evidence(val, "feature_flag_assignment"),
            });
        }
      }
      if (node.type === "CallExpression") {
        const called = nameOf(node.callee),
          args = node.arguments || [];
        let method = "UNKNOWN";
        if (
          /(?:^|\.)(?:get|post|put|patch|delete|head|options)$/i.test(called) &&
          /(?:axios|http|api|client|request)/i.test(called)
        ) {
          method = called.split(".").pop().toUpperCase();
          withConfig(
            route(value(args[0]), args[0], method, "HTTP client call"),
            args[method === "GET" ? 1 : 2],
            method === "GET" ? null : args[1],
          );
        }
        if (/(?:^|\.)(?:fetch|request|ajax)$/.test(called)) {
          const config = args.find((a) => a?.type === "ObjectExpression");
          if (config) {
            const methodNode = config.properties.find(
              (p) => prop(p.key) === "method",
            );
            method = (
              methodNode
                ? value(methodNode.value) || "UNKNOWN"
                : /fetch$/.test(called)
                  ? "GET"
                  : "UNKNOWN"
            ).toUpperCase();
            for (const p of config.properties)
              if (["url", "uri"].includes(prop(p.key)))
                withConfig(
                  route(
                    value(p.value),
                    p.value,
                    method,
                    "request configuration",
                  ),
                  config,
                );
          } else if (/fetch$/.test(called)) method = "GET";
          withConfig(
            route(value(args[0]), args[0], method, "HTTP request call"),
            config,
          );
        }
        if (
          /(?:isEnabled|isFeatureEnabled|variation|featureFlag|useFeature|useFeatureFlag|getFeatureFlag|isFeatureOn|experiment)/i.test(
            called,
          )
        ) {
          const flag = value(args[0]);
          if (flag)
            flags.push({
              name: flag,
              ...evidence(args[0], "feature_flag_call"),
            });
        }
        if (
          /(?:searchParams|URLSearchParams|params)\.(?:get|has|set|append)$/.test(
            called,
          )
        ) {
          const name = value(args[0]);
          if (name)
            parameters.push({
              name,
              location: "query",
              ...evidence(args[0], "query_parameter_access"),
            });
        }
      }
      for (const [key, child] of Object.entries(node)) {
        if (["start", "end", "loc"].includes(key)) continue;
        if (Array.isArray(child)) {
          for (let i = child.length - 1; i >= 0; i--)
            if (child[i]?.type) stack.push({ node: child[i], parent: node });
        } else if (child?.type) stack.push({ node: child, parent: node });
      }
    }
  }
  for (const m of text.matchAll(
    /(?:https?:\/\/[^\s"'`<>\\]+|["'`]((?:\/{1}|\.\.?\/)[^\s"'`<>\\]{1,1000})["'`])/g,
  ))
    route(
      m[1] || m[0],
      { start: m.index + (m[1] ? 1 : 0) },
      "UNKNOWN",
      "pattern",
    );
  for (const m of text.matchAll(
    /\b(?:sk_(?:live|test)_[A-Za-z0-9]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{30,})\b/g,
  ))
    secret(m[0], { start: m.index }, "recognized format");
  const dedup = (items, key) =>
    [...new Map(items.map((i) => [key(i), i])).values()].sort(
      (a, b) =>
        (a.offset ?? a.location?.offset ?? 0) -
          (b.offset ?? b.location?.offset ?? 0) ||
        JSON.stringify(a).localeCompare(JSON.stringify(b)),
    );
  const cleanRoutes = [],
    routeIndex = new Map();
  const rank = (r) =>
    r.method !== "UNKNOWN" ? 0 : r.kind === "pattern" ? 2 : 1;
  for (const r of routes.sort(
    (a, b) => rank(a) - rank(b) || a.offset - b.offset,
  )) {
    let existing;
    for (const offset of [r.offset, r.offset - 1, r.offset + 1]) {
      const candidate = routeIndex.get(r.url + "|" + offset);
      if (
        candidate &&
        (candidate.method === r.method || r.method === "UNKNOWN")
      ) {
        existing = candidate;
        break;
      }
    }
    if (existing) {
      existing.evidence_kinds = sorted([
        ...(existing.evidence_kinds || [existing.kind]),
        r.kind,
      ]);
    } else {
      cleanRoutes.push(r);
      routeIndex.set(r.url + "|" + r.offset, r);
    }
  }
  const endpoints = dedup(
    cleanRoutes,
    (r) => r.url + "|" + r.method + "|" + r.offset,
  );
  const potential = dedup(
    secrets,
    (s) => s.fingerprint + "|" + s.location.offset,
  );
  for (const route of endpoints) {
    const identity = endpointIdentity(
      route.url,
      route.method,
      "https://analysis.invalid",
    );
    if (identity)
      for (const p of identity.parameter_details)
        parameters.push({
          ...p,
          ...evidence({ start: route.offset }, "URL parameter evidence"),
        });
    for (const p of route.parameter_details || []) parameters.push(p);
  }
  return {
    file,
    sha256: hash(bytes),
    bytes: bytes.length,
    analysis_method: parseMode + " + deterministic patterns; no AI service",
    analysis_notes: notes,
    endpoints_found: sorted(endpoints.map((r) => r.url)),
    endpoint_evidence: endpoints,
    potential_secrets: potential,
    feature_flags: sorted(flags.map((f) => f.name)),
    feature_flag_evidence: dedup(flags, (f) => f.name + "|" + f.offset),
    internal_routes: sorted(
      endpoints
        .filter((r) =>
          /(?:^|\/)(?:internal|admin(?:[-_/]|$)|debug|private|dev|staging|preview|export)(?:[/?#_-]|$)/i.test(
            r.url,
          ),
        )
        .map((r) => r.url),
    ),
    params: sorted(parameters.map((p) => p.name)),
    parameter_evidence: dedup(parameters, (p) => p.name + "|" + p.offset),
    unverified: true,
  };
}
module.exports = {
  hash,
  sorted,
  idShape,
  idName,
  endpointIdentity,
  bodyParameters,
  analyzeJavaScript,
  locationAt,
  sensitiveContext,
};
