# Traceglass

A local workspace for browser HTTP capture, request inspection, scoped reconnaissance and traceable evidence packages. Free and open source under GPL-3.0-only. No AI account or API key required.

## Quick start

Requires Node.js **22.19 or newer** and npm. Git enables repository imports. Windows, Linux and macOS use the same Node entry point; Windows launchers are optional conveniences. Hosted CI is configured for all three platforms; local validation does not establish every OS as tested.

Clone your GitHub repository (or extract its source ZIP), then open a terminal in the project directory:

```sh
npm ci
npm run setup:browser
npm run doctor
npm start
```

On Linux install browser system dependencies with `npx playwright install --with-deps chromium`. On Windows PowerShell use `npm.cmd` if script policy blocks npm.ps1. Native SQLite installation may need a C++ build toolchain if a prebuilt binary is unavailable for your Node/OS.

Open **http://127.0.0.1:4310**. Run commands from the project directory. Stop the foreground server with Ctrl+C. After setup Windows users can also use start.bat.

### First capture

1. Create a capture session.
2. Enter a URL you own or are authorized to inspect, select Chromium, and launch the dedicated browser.
3. Browse the application. Select a request to inspect its headers and response; filter the history.
4. Send a request to Repeater to edit and resend it. Repeater and active recon send new requests.
5. Close the capture browser from the app, then export JSON/HAR or create a scoped Recon run and Handoff Package.

Start recon with a small explicit scope and the default request budget. For access-control comparisons, collect separate test-account roles and complete the manual checklist. Successful responses alone do not establish an authorization flaw.

### Optional ProjectDiscovery httpx

Capture, Repeater, recon and passive fingerprints work without httpx. The explicit technology probe requires the **ProjectDiscovery** binary, not the Python package.

Windows amd64: `npm run setup:httpx` downloads the upstream release and verifies its published SHA256. Elsewhere install ProjectDiscovery httpx separately and put it on PATH, or set HTTPX_PATH to the executable. Resolution uses HTTPX_PATH, then tools/httpx.exe on Windows or tools/httpx elsewhere, then PATH. See [upstream installation instructions](https://github.com/projectdiscovery/httpx). Run npm run doctor to check availability.

### Configuration

| Variable      | Default                | Purpose                                                         |
| ------------- | ---------------------- | --------------------------------------------------------------- |
| PORT          | 4310                   | Loopback HTTP port; 0 selects an ephemeral test port            |
| TRACEGLASS_DB | data/capture.sqlite    | SQLite path; parent must exist; other artifacts remain in data/ |
| HTTPX_PATH    | Bundled binary or PATH | Optional ProjectDiscovery executable                            |

Set environment variables in your shell; .env files are not loaded. PowerShell: `$env:PORT='4311'; npm.cmd start`. Bash: `PORT=4311 npm start`. The bind address remains 127.0.0.1.

### Troubleshooting

- Run `npm run doctor` for installation checks and repair hints. It never launches a browser or sends target requests.
- Missing browser: run `npm run setup:browser`; missing Linux libraries: use --with-deps as above.
- SQLite load error after changing Node: run `npm ci` using the intended Node version.
- Port in use: stop the existing instance or choose another PORT and open the printed URL.
- Empty history: use the browser launched by Traceglass; personal browser windows are not captured.
- Missing bodies or partial recon: read body errors and collector coverage notes before interpreting results.

### Development and publishing

```sh
npm run check
npm test
npm run release:check
```

Tests use headless Chromium and controlled fixtures. release:check requires Git and checks publishable paths and package metadata; it is not a credential scanner. Ignored local data is preserved.

For a new repository run `git init -b main` if needed. Review `git status --short`, then `git add .`, `npm run release:check` and `git diff --cached`. Commit with `git commit -m "Prepare Traceglass open-source release"`, add your remote using `git remote add origin <YOUR_REPOSITORY_URL>` and run `git push -u origin main`. Check the Actions tab before creating a release. No GitHub URL is assumed.

See [the practical roadmap](docs/ROADMAP.md), [contributing](CONTRIBUTING.md), [security policy](SECURITY.md) and [third-party notices](THIRD_PARTY.md). Keep data/, captures, exports, credentials and profiles private. Original exports may contain secrets even when previews are redacted.

## Features

- Persistent SQLite capture history and separate browser profiles per session.
- Live HTTP history, method/status/URL filters, and case insensitive literal search across URLs, request and response headers, and textual bodies. Filters combine dynamically; `%` and `_` are literal search characters.
- Request/response inspector, in-panel highlighting, copy, and original response body downloads. Page sizes of 200 keep the table responsive.
- Interception queue: enable **Intercept**, optionally scope by method and URL substring, then browse. Requests stop before transmission. Select a held request to edit its URL, method, headers, and body, **Forward** it, **Drop** it, or copy it to Repeater. Turning interception off forwards all held requests using their original values; forward an individual edited request to apply its changes. Queue polling preserves unsaved edits to the selected request. Closing the capture browser drops its queue. Interception is independent of capture pause.
- Repeater: use **Send to Repeater** in a captured request inspector or the interception editor, or start a blank request. Edit the request and send repeatedly. Each send is saved per session, with status, duration, response headers/body, text search, JSON formatting, byte download, and comparison to the previously viewed result. Sends support cancellation, a configurable timeout, and optional TLS certificate verification. UTF-8 and Base64 request bodies are supported; Host and Cookie can be changed explicitly. Framing headers are recalculated. Redirects are displayed without being followed. Repeater sends are stored separately from browser HTTP history and its exports.
- Filtered or complete JSON and HAR 1.2 exports with base64 response bodies; exports include all matching records across pagination.
- JavaScript library identifies script resource types, `.js`/`.mjs` URLs, and JavaScript MIME types. Search contents, inspect source, and export captured versions as ZIP with a URL manifest. Repeated responses remain separate to preserve versions.
- Passive Wappalyzer analysis of captured headers, HTML, meta tags, script URLs, and JavaScript contents. The vendored engine/database comes from https://github.com/tomnomnom/wappalyzer (GPL-3.0); its upstream license is retained. This is an archived fingerprint dataset, not Wappalyzer's paid current API. Detection confidence is a heuristic, not proof.
- Explicit ProjectDiscovery `httpx -tech-detect` probes of captured document origins. The installer downloads the official Windows amd64 release and validates its published SHA256. Set` HTTPX_PATH` to use an existing ProjectDiscovery binary. This is not the Python HTTP client with the same name.

## Consolidated handoff package

Use the separate **Handoff Package** tab after collecting evidence. Choose a primary finished recon run and explicitly select any source imports or role-labeled runs that belong to that scan. Supporting runs can come from other capture sessions with the same target origin, subdomain scope and exclusions. Do not combine every historical scan: that would prevent meaningful detection of assets that are no longer observed. Packaging analyzes already collected evidence locally and sends no target requests or AI API calls.

Choose an automatic compatible baseline, a specific previous package, or no baseline. Build the package, read/copy `summary.md`, fill the manual authorization checklist, then download **one complete ZIP** containing:

```text
target_recon_package/
  summary.md
  assets.json
  endpoints.json
  js_findings.json
  auth_map.json
  traffic_samples/<sample-id>/
    pair.json
    request.txt
    response.txt
  evidence/requests/<sha256>   # shared request bodies
  evidence/<sha256>            # shared response/source bodies
  diff_from_last_run.md
  package_manifest.json
  evidence_index.json
```

The requested seven core paths are always present. When there is no captured traffic, `traffic_samples/README.md` explains the gap. The extra manifest/index and original evidence make findings traceable without losing imported source/configuration/API documents. Missing response bodies remain explicitly unavailable; request/response text files are reconstructions of captured headers and decoded bytes, not original network wire framing. Original artifacts and traffic may contain credentials. Body bytes are stored once by hash; each pair.json body_file path is relative to its sample folder and points to the complete shared body. Text request/response views are capped at 64 KiB and explicitly link to the complete body when truncated. No role distinction or manually selected auth evidence is removed to meet analysis budgets.

- **Assets:** one consolidated host entry with live/discovered-only state, scope membership, HTTP status/title, headers, observed origins, DNS/IP information, source provenance, technology names/versions where observed, and staging/dev/internal-like name flags. `first_seen` means first seen in selected evidence or earlier compatible packages, not the host's actual creation date. Unknown versions remain unknown. HTTP header products are recorded as header evidence, and conflicting observed versions are retained. Non-production name flags are heuristics.
- **Endpoints:** consolidate methods and route patterns across traffic, archives, source/API route definitions and JavaScript. Preserve observed URLs, path/query/body/API-declared parameters, parameter locations, numeric/UUID/ObjectID evidence, inferred-vs-declared path names, possible adjacent numeric sequences, sources and sample references. Common pagination/count/amount parameters are not treated as object IDs merely because they are numeric. Unknown methods and unknown authorization requirements remain explicit. Purely historical status codes are separate from current observed responses. No arbitrary JavaScript execution or complete program/data-flow analysis is performed; dynamically computed fields may remain unknown.
- **JavaScript:** parse with Acorn and use bounded patterns for unsupported syntax instead of expensive error recovery, and record exact original file, SHA256, line, column and character offset. Extract HTTP calls, route strings, query/body field names and feature-flag names. Known credential formats rank above generic sensitive-name assignments; placeholders are downgraded. Match previews are redacted and fingerprints allow stable comparison. The same literal found by AST and regex is deduplicated. Confidence is format/heuristic confidence, not credential validity. Original bytes are retained under the referenced `evidence/` path. Balanced analysis allows AST parsing up to 2 MiB per file and 15 MiB total, with 250,000 AST nodes per file; vendor/oversized files use bounded pattern scanning of at most the first 256 KiB, up to 6 MiB total. Each analysis runs in a terminable worker with a 2-second time limit and 192 MiB heap limit. JavaScript processing has a 30-second budget; excess files remain inventory-only with coverage notes. Unchanged hashes reuse a persistent versioned cache, and identical bytes at different URLs are analyzed once. WebAssembly and HTML error responses are retained as evidence but never passed to the JavaScript parser. The Quick profile lowers budgets; Inventory uses existing cached findings without starting new parsing. Whole builds run off the web server thread with progress, cancellation, and a 60-second hard deadline (Quick 40 seconds; Inventory 30 seconds). A pathological build that reaches this final deadline fails explicitly instead of blocking the app indefinitely. Source maps and runtime string deobfuscation are not resolved. Browser snapshots also retain already-captured third-party JavaScript when a scoped referrer or observed script/import link connects it to the target; this passive dependency evidence never triggers out-of-scope requests. Unrelated browsing scripts are excluded. Relative JavaScript HTTP candidates use the configured target page as their assumed base; runtime document/base URL differences remain a stated uncertainty.
- **Manual authorization map:** create a checklist for every ID-bearing endpoint and attach captured role observations. You supply account labels, ownership, expected access, actual response results and your conclusion. HTTP 200 never automatically becomes an IDOR. A `possible_idor` flag requires both account labels/results and an explicit expected denial for B; marking a case reviewed additionally requires completing the checklist. Saving updates that package's` auth_map.json` and summary. Reviews are stored by scope and endpoint and can seed subsequent packages; old packages are not silently rewritten by future reviews. Recheck carried annotations if application behavior changes.
- **Stable diffs:** compare canonical hosts, endpoint methods/patterns/parameter shapes/statuses, JavaScript content versions, and unique secret fingerprints. Exclude timestamps, timings, volatile headers, evidence ordering and scanner-generated random soft-404 calibration URLs from inventory changes; calibration traffic remains available as raw evidence. Missing entries are labeled **not observed**, never proven removed. Differences in collector configuration, limits, role coverage or run status are called out. Initial packages explicitly say there is no prior baseline. Changing manual annotations does not pretend the attack surface changed.

Packages are saved in the local database and can be downloaded again. The ZIP preserves selected-run snapshots rather than silently including later browser traffic. Calendar scan/first-seen dates use Asia/Karachi; timestamps retain ISO UTC offsets for traceability. Building does not require an AI key: the resulting summary can be pasted into your chosen AI or reviewed manually. Raw imported text is labeled untrusted evidence, not instructions.

`npm test` exercises a controlled HTTP sandbox with three scans: a baseline, an unchanged scan with different request IDs/timestamps, and a changed JavaScript route/version. It validates parameter and ID-shape extraction, secret deduplication/trace locations, staging flags, stable diffs, ZIP contents and sample links, manual-review rules, and the Handoff UI. The test writes an example ZIP to` test-results/target_recon_package.zip` and an extracted example under` test-results/sandbox_handoff/target_recon_package/`. Those artifacts contain synthetic sandbox data, not a scan of your target.

## Recon workspace

Open **Recon > New recon run**, enter the target URL or root domain, choose collectors, and start. A browser session is created automatically if needed; you can also attach recon to an existing session. No AI service or provider API key is used.

Each run keeps its scope, options, request count, collector status, coverage notes, and evidence provenance. Search across metadata and attached JavaScript/source/response contents, filter by category, preview evidence, and export either the current filtered set or the whole run. ZIP exports include a manifest, content-addressed artifacts, convenient JavaScript copies, imported source paths, and a Git bundle when available. JSON exports include attached bytes in Base64. URL-list exports contain URLs only. Filters apply across all result pages. Failed or rate-limited providers produce partial statuses rather than pretending no assets exist. Cancelling retains collected records. Runs interrupted by a server restart are labeled interrupted; they are not automatically resumed.

Available collection:

- **Subdomains:** public certificate transparency via crt.sh, with a keyless public host-search fallback. Archived URLs can contribute additional names. Certificate names are candidates, not proof of current ownership. No claim of exhaustive enumeration is made.
- **DNS/infrastructure:** A, AAAA, CNAME, MX, TXT, NS, SOA and CAA for scoped discovered names; RDAP domain/IP registration via public bootstrap services, IPv4/IPv6 origin ASN mapping via Team Cymru DNS, and announced ASN prefixes via RIPEstat. CDN/shared-provider addresses and ASN ranges are contextual records, never automatically added to testing scope or probed as ranges.
- **Archived URLs:** a bounded Wayback query (up to 5,000 records) and one page of the latest Common Crawl index. This collects historical URL metadata, not every historical response body. Public provider coverage and availability vary. Archived endpoints are retained without automatically requesting every historical URL.
- **Live hosts and headers:** rate-limited HTTP probes with status, page title, headers, redirect observations, and missing-security-header annotations. Active redirects are checked against scope at every hop.
- **Crawler/JavaScript:** follow in-scope HTML links and scripts, preserve served JavaScript, identify endpoint strings, observe third-party integrations, extract public API documents and Wappalyzer fingerprints, and flag potential secret patterns. Source maps are preserved if explicitly discovered/requested; there is no guarantee of discovering unreferenced bundles. Forms are recorded without submission. This HTTP crawler does not execute JavaScript; use the capture browser and snapshot its evidence for dynamically loaded features.
- **Endpoint discovery:** configurable path wordlist, optional text-file wordlist import, and a random nonexistent-path baseline for possible soft-404s. Matching responses are evidence rather than confirmed hidden endpoints. Public OpenAPI/Swagger and Postman collections produce route records. Optional GraphQL introspection performs a read-only schema query at `/graphql` and reports when disabled or authentication is required.
- **Authenticated browser evidence:** import a snapshot of the current or another capture session with an explicit account-role label. Original requests, response bodies, JavaScript and observed integrations are preserved. Repeat with different roles/profiles and use **Compare account roles**. The matrix compares method/origin/path, status, size and body hash; it does not know intended permissions and cannot declare an access-control vulnerability.
- **Mobile/external traffic:** import a HAR file up to 15 MiB and optionally label it as mobile. Only in-scope entries are retained. HAR bodies must be present for content analysis. Device setup, TLS interception and certificate pinning are outside this importer; native mobile traffic is not automatically captured by the browser tool.
- **White-box inputs:** import a local source folder or clone a public HTTPS Git repository. Preserve files and classify dependency manifests, selected exact versions from npm lockfiles/requirements, configuration, migrations/schema, authorization-related code, API route patterns, tests and CI/CD. Git collection includes a commit index (up to 2,000 commits), available repository history as a bundle if within the source-size limit, and pattern scanning of the latest 100 commits' patches. Private repositories require an existing authorized local checkout; no private source is obtainable from a URL alone. Imported code, tests and CI/CD commands are not run. Submodules, dependency/cache directories and symbolic links are not followed. All exclusions and limits are recorded in the source inventory. Classification and route/secret extraction are heuristics, not complete semantic analysis or CVE verification.

The default active budget is 250 target requests, 100 crawl URLs, 50 hosts, 300 ms between target requests, and 5 MiB per fetched body. Limits are editable. Public archive/registration-provider requests and DNS queries are separate from the HTTP target-request counter. Source imports default to 25,000 files, 300 MiB total, and 20 MiB per file; text extraction skips binary files and files above 8 MiB, while included original bytes remain exportable. Preview is limited to 512 KiB; original downloads and exports retain collected bytes. Scope is host-based, includes subdomains only when selected, honors explicit nondefault target ports and excludes listed hosts/URL fragments. Collector GET requests can still change state on poorly designed applications; use appropriate target scope and test accounts.

Pattern-matched secrets are shown as redacted, unverified candidates. Original artifacts and exports retain full content, including any credentials supplied by your captures or repository. Everything remains in the local SQLite database and source-checkout/bundle folders under `data/`; no collected bodies or source code are sent to AI services. Public discovery queries necessarily send the target domain/IP/ASN to their respective providers. See the upstream [Common Crawl index documentation](https://index.commoncrawl.org/), [Team Cymru mapping documentation](https://www.team-cymru.com/ip-asn-mapping), and [RIPEstat announced-prefix documentation](https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes.html).

## Capture boundaries

This is a browser HTTP capture tool, not a system-wide MITM proxy or a complete Burp Suite replacement. It observes the dedicated Chrome/Chromium context, including HTTPS without installing a root CA. It does not capture other applications, arbitrary existing browser sessions, WebSocket message frames, or streamed bodies before the stream finishes. Browser-provided request headers and decoded response bodies are captured; raw TLS packets and exact HTTP wire framing are not available. Redirects and failed requests remain in history. Browser limitations can make a body unavailable (for example redirects, closed pages, or evicted resources); those records show a body error instead of silently pretending to contain a body. Service workers are blocked and browser caching is disabled for reliable interception; sites that require service workers may behave differently. Binary bodies are exported in base64 and downloaded as bytes; full text search covers textual MIME types and JavaScript. Newly captured binary request bodies retain their original bytes for Repeater; old captures made before this upgrade only retain the original text field.

Interception uses Playwright browser routing. The browser manages Cookie, Host, Connection, and Content-Length; use Repeater for explicit Cookie or Host edits. Intercepted URL edits must preserve the original protocol. The first request of a redirect chain is interceptable; subsequent redirect hops are still logged but are not separately held. Browser-side timeouts can expire while requests are held. The queue lives only in the running browser session. Repeater uses Node's HTTP/1.1 client and does not automatically reuse or update the browser cookie jar; copy a captured Cookie header when authentication is required. It does not implement CONNECT, protocol upgrades, duplicate request headers, or raw malformed HTTP framing. Repeater bodies are limited to 100 MiB per response, and request editor JSON to 20 MiB. Compressed gzip, deflate, and Brotli responses are decoded. Repeater history retains the latest 200 entries in the sidebar (older records remain in SQLite).

Pause excludes newly started requests while allowing already captured requests to finish. Capture resumes for subsequent requests. Large bodies are stored in full and may consume substantial disk and memory. Continuous event streams finish only when the connection closes. Wappalyzer's JavaScript-global/DOM selector and DNS probes are not run; passive matching uses the evidence listed above. httpx sends additional requests and uses its own bundled fingerprint database.

The server binds only to `127.0.0.1`, rejects cross-site browser requests, and requires a per-process API token. Data in` data/` is unencrypted and includes cookies, authorization headers, responses, and browser login state. Exports also contain these values. Deleting` data/` while the server is stopped removes the local history and profiles. Never commit it. Use on systems you are authorized to inspect.

`npm test` runs a real Chromium integration test against a local fixture, including capture, search, JavaScript, Wappalyzer, exports, interception holding/editing/dropping/queue release, repeater resend/cancel/redirect handling, and both workbench interfaces.` PORT` changes the local server port. GPL-3.0-only applies to this distribution because it includes the Wappalyzer engine.
