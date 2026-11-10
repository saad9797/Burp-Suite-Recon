# First public release

1. Install from a clean clone with Node.js 22.19 or newer: npm ci, then npm run setup:browser (Linux: npx playwright install --with-deps chromium).
2. Run npm run doctor, npm run check, npm test, and npm run release:check.
3. Review git diff --cached. Ensure local evidence, credentials, profiles, personal notes, executables and archives are excluded. release:check checks paths, not file contents.
4. Create an empty GitHub repository and set its URL as origin. Commit the staged source and push main using the README commands.
5. Check all three OS jobs in GitHub Actions. Fix failures before declaring that platform supported.
6. Enable private vulnerability reporting in repository settings or publish a maintainer contact in SECURITY.md. Set the GitHub description/topics and confirm GPL-3.0-only is displayed.
7. Create a versioned release with the passing commit, supported platforms, installation instructions and known limitations. No binaries or private captures are needed.

## Local validation for this preparation

The existing browser capture, interception, Repeater, recon, evidence packaging, UI and worker-budget tests passed on Windows with Node.js 22.19.0. New runtime tests cover port parsing and httpx resolution; release-guard tests cover ignored data, force-tracked private data, missing vendor data and lockfile mismatch. Hosted Linux/macOS execution remains pending the first push.

The vendored Wappalyzer repository metadata was preserved locally under ignored data/vendor-wappalyzer-git-backup. The public repository includes the unchanged required engine, categories, fingerprint JSON files, README and GPL license as ordinary files. The upstream commit is recorded in THIRD_PARTY.md; fresh clones do not depend on a submodule.
