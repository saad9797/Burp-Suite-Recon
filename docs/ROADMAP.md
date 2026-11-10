# Practical product and open-source plan

## Product goal

Make Traceglass easy to install, useful for authorized HTTP investigation, and dependable when handing evidence to another reviewer. Primary users are developers, security learners and testers working on their own or explicitly authorized applications. It is a local browser workspace, not a complete system proxy.

## Release foundation implemented

| Work                     | Outcome                                                                              | Acceptance criteria                                                                                                                                                                     |
| ------------------------ | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Installation diagnostics | doctor checks Node, SQLite, Chromium, Git, port and optional httpx                   | Missing required dependencies produce a nonzero exit and repair hint; optional tools do not block capture                                                                               |
| Portable runtime         | Resolve bundled httpx by OS, otherwise PATH or HTTPX_PATH; validate PORT             | Unit tests cover overrides, fallback, ephemeral ports and malformed values                                                                                                              |
| Repository hygiene       | Ignore local data, profiles, binaries, archives, env files, private keys and backups | release:check rejects publishable paths in protected categories, including accidentally tracked files; regression tests cover private files, missing vendor files and lockfile mismatch |
| Automated validation     | Syntax checks and GitHub Actions OS matrix                                           | Windows, Linux and macOS execute setup, diagnostics, syntax, release checks and integration tests                                                                                       |
| Community onboarding     | Quick start, workflows, troubleshooting, contribution/security guides and templates  | A user can install and capture without an AI key or optional httpx                                                                                                                      |

Hosted CI must be observed after pushing; configured jobs are not evidence of passing on other platforms.

## Next milestones (planned, not implemented)

Effort ranges are planning estimates, not delivery promises. Complete each milestone before expanding scope.

### 1. Beginner workflow and reproducible demo (2?4 days)

Add an offline demo target with scripts and synthetic accounts, an onboarding checklist and useful empty states. Distinguish passive inspection from actions sending new requests. Acceptance: a first-time user captures a demo request, resends it, runs bounded recon and exports a package in under ten minutes, without a public target or credentials.

### 2. Data lifecycle and storage controls (3?5 days)

Add per-session disk accounting, retention settings, deletion with a preview of affected profiles/packages, and a consistent backup workflow. Acceptance: deleting one session leaves unrelated evidence intact; interrupted deletion is recoverable; retention preserves pinned evidence. Test populated fixtures and interrupted processes.

### 3. Shareable sanitized reports (4?7 days)

Add a separate redacted export mode covering authorization/cookie headers and sensitive fields across raw bodies, manifests and sample text. Preserve private originals and include a redaction manifest. Acceptance: seeded synthetic secrets do not occur anywhere in extracted public packages and reviewers can distinguish originals from derived views. Pattern matching alone cannot certify an export safe.

### 4. Reliability and performance (4?7 days)

Add capture body/disk budgets, precise truncation notes, consistent worker cancellation/shutdown and large-session benchmarks. Acceptance: a documented 10,000-request fixture remains responsive, resource ceilings are measured, cancellation retains readable partial results and shutdown leaves no build workers. Agree measured latency/memory targets before implementation.

### 5. Maintainable releases (2?4 days)

Pin CI actions to reviewed commits, add dependency-update automation and audit triage, tagged release notes, clean-clone smoke tests and maintainer/private-report contacts. Review vendor licensing/provenance before updates. Acceptance: tagged releases are reconstructable from lockfile/source, OS jobs are green and no local evidence or executable is included.

### 6. Accessibility and interoperability (3?6 days)

Audit keyboard navigation, focus order, table semantics, contrast and errors. Add versioned export schemas and HAR compatibility fixtures. Acceptance: capture-to-export works with a keyboard, malformed imports show actionable errors and existing packages remain readable after schema changes.

## Release gate

From a clean clone run npm ci, install Chromium, npm run doctor, npm run check, npm test and npm run release:check. Review staged contents and third-party notices, observe hosted CI, then create a versioned release. Keep real targets, cookies, keys and profiles out of screenshots/issues. Publish under GPL-3.0-only with vendored notices intact.
