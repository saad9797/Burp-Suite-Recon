# Contributing

Use Node.js 22.19 or newer and Git. Clone the repository, run npm ci, then npm run setup:browser. On Linux use npx playwright install --with-deps chromium. Run npm run doctor before debugging installation problems.

## Development loop

1. Create a branch for a focused change.
2. Run npm start and open http://127.0.0.1:4310.
3. Use a local fixture or a target you are authorized to test.
4. Run npm run check and npm test. Tests include a real headless browser, local HTTP fixtures, temporary SQLite databases, source import, and evidence exports. Synthetic artifacts under data/ and test-results/ are ignored by Git.
5. Run npm run release:check and review git diff --cached before publishing.

Preserve byte-level evidence and provenance, and record incomplete collector coverage explicitly. Add regression tests for behavior changes. New active collectors must honor scope, request limits, cancellation and redirect checks. Never execute imported code or commands from evidence.

## Project map

- server.js: local server, token protection, capture and exports.
- workbench.js / public/workbench.js: interception and Repeater.
- recon.js / source-recon.js: scoped collection and source inventory.
- handoff*.js: consolidated evidence, analysis workers, budgets and diffs.
- public/: interface assets; tests/: unit and integration fixtures.
- runtime.js / scripts/: runtime validation, diagnostics and release checks.

Preserve vendor/wappalyzer's license and revision attribution. Contributions are distributed under GPL-3.0-only, consistent with LICENSE. See docs/ROADMAP.md for priorities and SECURITY.md for private reporting.
