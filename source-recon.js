const fs = require("node:fs/promises");
const path = require("node:path");
const net = require("node:net");

function mountSourceRecon(
  app,
  {
    db,
    add,
    stage,
    log,
    newJob,
    start,
    assertSession,
    ensureSession,
    optionsFrom,
    extract,
    parseAPI,
    exec,
    sha,
  },
) {
  app.post("/api/recon/import-source", async (req, res, next) => {
    try {
      req.body.session = ensureSession(req.body.session, req.body.target);
      const options = optionsFrom({ ...req.body, modules: [] });
      const location = String(req.body.location || "").trim();
      if (!location)
        throw Error("Enter a local source folder or public HTTPS Git URL.");
      const remote = /^https:\/\//i.test(location);
      if (remote) {
        const url = new URL(location);
        if (url.username || url.password)
          throw Error(
            "Use a public repository URL without embedded credentials.",
          );
      }
      const limits = {
        files: Math.min(
          100000,
          Math.max(1, Number(req.body.maxFiles) || 25000),
        ),
        bytes:
          Math.min(2048, Math.max(1, Number(req.body.maxMB) || 300)) * 1048576,
        fileBytes:
          Math.min(100, Math.max(1, Number(req.body.maxFileMB) || 20)) *
          1048576,
      };
      const job = newJob(
        { ...options, source: location, limits },
        req.body.session,
        "Source · " +
          (remote ? new URL(location).pathname : path.basename(location)),
      );
      void start(job, async (controller) => {
        stage(job, "Source repository", "running");
        let root;
        const execute = (args, extra = {}) =>
          exec(
            "git",
            [
              "-c",
              "core.hooksPath=" + path.resolve("data/disabled-hooks"),
              "-c",
              "protocol.file.allow=never",
              "-c",
              "protocol.ext.allow=never",
              ...args,
            ],
            {
              signal: controller.signal,
              windowsHide: true,
              timeout: 120000,
              maxBuffer: 16 * 1048576,
              env: {
                ...process.env,
                GIT_TERMINAL_PROMPT: "0",
                GIT_LFS_SKIP_SMUDGE: "1",
              },
              ...extra,
            },
          );
        if (remote) {
          root = path.resolve("data/source-checkouts", job);
          await fs.mkdir(path.dirname(root), { recursive: true });
          log(
            job,
            "Cloning public Git repository without submodules or external filters",
          );
          await execute([
            "clone",
            "--no-recurse-submodules",
            "--",
            location,
            root,
          ]);
        } else root = await fs.realpath(path.resolve(location));
        const stat = await fs.stat(root);
        if (!stat.isDirectory())
          throw Error("Source location must be a directory.");
        let files = 0,
          bytes = 0,
          skipped = 0;
        const skippedReasons = [];
        const ignore = new Set([
          ".git",
          "node_modules",
          ".venv",
          "venv",
          "__pycache__",
          ".next",
          ".cache",
          ".idea",
        ]);
        const isWithin = (p) => {
          const rel = path.relative(root, p);
          return (
            !rel.startsWith(".." + path.sep) &&
            rel !== ".." &&
            !path.isAbsolute(rel)
          );
        };
        const note = (file, reason) => {
          skipped++;
          if (skippedReasons.length < 500)
            skippedReasons.push({ file, reason });
        };
        async function walk(dir) {
          controller.signal.throwIfAborted();
          const entries = await fs.readdir(dir, { withFileTypes: true });
          for (const item of entries) {
            controller.signal.throwIfAborted();
            const absolute = path.join(dir, item.name),
              relative = path
                .relative(root, absolute)
                .split(path.sep)
                .join("/");
            if (!isWithin(absolute))
              throw Error("Source path escaped its selected root.");
            if (item.isSymbolicLink()) {
              note(relative, "Symbolic link not followed");
              continue;
            }
            if (item.isDirectory()) {
              if (ignore.has(item.name)) {
                note(
                  relative,
                  "Dependency/cache/VCS directory excluded; Git history is collected separately",
                );
                continue;
              }
              await walk(absolute);
              continue;
            }
            if (!item.isFile()) continue;
            const info = await fs.stat(absolute);
            if (files >= limits.files) {
              note(relative, "File count limit reached");
              continue;
            }
            if (info.size > limits.fileBytes) {
              note(relative, "Per-file size limit exceeded");
              continue;
            }
            if (bytes + info.size > limits.bytes) {
              note(relative, "Total source size limit exceeded");
              continue;
            }
            const real = await fs.realpath(absolute);
            if (!isWithin(real)) {
              note(relative, "Resolved path outside selected root");
              continue;
            }
            const body = await fs.readFile(real);
            files++;
            bytes += body.length;
            const artifact = add(
              job,
              "source",
              relative,
              relative,
              {
                source: remote ? location : root,
                path: relative,
                bytes: body.length,
                sha256: sha(body),
              },
              body,
            );
            if (body.includes(0) || body.length > 8 * 1048576) continue;
            const text = body.toString("utf8");
            const data = {
              source: "source-import",
              path: relative,
              bytes: body.length,
              artifact,
            };
            if (
              /(?:^|\/)(?:package(?:-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|Pipfile(?:\.lock)?|composer\.(?:json|lock)|Gemfile(?:\.lock)?|go\.(?:mod|sum)|Cargo\.(?:toml|lock)|pom\.xml|build\.gradle(?:\.kts)?|[^/]+\.csproj|packages\.lock\.json)$/i.test(
                relative,
              )
            ) {
              add(
                job,
                "dependencies",
                "manifest:" + relative,
                relative,
                { ...data, kind: "manifest" },
                body,
              );
              if (/(?:^|\/)package\.json$/.test(relative))
                try {
                  const pkg = JSON.parse(text);
                  for (const section of [
                    "dependencies",
                    "devDependencies",
                    "peerDependencies",
                    "optionalDependencies",
                  ])
                    for (const [name, version] of Object.entries(
                      pkg[section] || {},
                    ))
                      add(
                        job,
                        "dependencies",
                        `${relative}:${section}:${name}`,
                        `${name} ${version}`,
                        {
                          ...data,
                          name,
                          version,
                          section,
                          exact: /^\d+\.\d+\.\d+(?:[-+].+)?$/.test(version),
                          ecosystem: "npm",
                        },
                      );
                } catch {}
              if (/package-lock\.json$/.test(relative))
                try {
                  const lock = JSON.parse(text);
                  for (const [location, pkg] of Object.entries(
                    lock.packages || {},
                  ))
                    if (pkg.version && location)
                      add(
                        job,
                        "dependencies",
                        `${relative}:${location}`,
                        `${pkg.name || location.split("node_modules/").pop()} ${pkg.version}`,
                        {
                          ...data,
                          name:
                            pkg.name || location.split("node_modules/").pop(),
                          version: pkg.version,
                          exact: true,
                          ecosystem: "npm",
                          location,
                        },
                      );
                } catch {}
              if (/requirements[^/]*\.txt$/i.test(relative))
                for (const line of text.split("\n")) {
                  const m = line.match(/^\s*([\w.-]+)\s*==\s*([^\s;#]+)/);
                  if (m)
                    add(
                      job,
                      "dependencies",
                      `${relative}:${m[1]}`,
                      `${m[1]} ${m[2]}`,
                      {
                        ...data,
                        name: m[1],
                        version: m[2],
                        exact: true,
                        ecosystem: "PyPI",
                      },
                    );
                }
            }
            if (
              /(?:^|\/)(?:\.env[^/]*|[^/]*config[^/]*\.(?:json|ya?ml|toml|ini|js|ts|py)|settings[^/]*\.py|docker-compose[^/]*\.ya?ml|compose\.ya?ml|Dockerfile[^/]*|[^/]+\.(?:conf|ini))$/i.test(
                relative,
              )
            )
              add(job, "configuration", relative, relative, data, body);
            if (
              /(?:migrations?|schemas?|prisma)[/._-]|\.sql$|schema\.prisma$/i.test(
                relative,
              )
            )
              add(job, "schema", relative, relative, data, body);
            if (
              /(?:auth|permission|middleware|guards?|policy|policies|rbac|acl)/i.test(
                relative,
              ) ||
              /\b(?:authorize|requireAuth|hasPermission|login_required|permission_required)\b/.test(
                text,
              )
            )
              add(
                job,
                "authcode",
                relative,
                relative,
                {
                  ...data,
                  classification: "Filename or code-pattern heuristic",
                },
                body,
              );
            if (
              /(?:^|\/)(?:__tests__|tests?|spec)(?:\/|\.)|(?:\.test|\.spec|_test)\.[^.]+$|(?:^|\/)test_[^/]+/i.test(
                relative,
              )
            )
              add(job, "tests", relative, relative, data, body);
            if (
              /(?:^|\/)(?:\.github\/workflows\/|\.gitlab-ci\.ya?ml|Jenkinsfile|azure-pipelines\.ya?ml|\.circleci\/|\.buildkite\/|bitbucket-pipelines\.ya?ml|[^/]*(?:deploy|pipeline)[^/]*\.(?:sh|ps1|ya?ml))/.test(
                relative,
              )
            )
              add(job, "cicd", relative, relative, data, body);
            let line = 0;
            for (const value of text.split("\n")) {
              line++;
              const patterns = [
                /\b(?:app|router|route|server)\.(get|post|put|patch|delete|head|options|all|use)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
                /@(?:app|router)\.(get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)["']/gi,
                /\bRoute::(get|post|put|patch|delete|any)\s*\(\s*["']([^"']+)["']/gi,
              ];
              for (const regex of patterns)
                for (const m of value.matchAll(regex))
                  add(
                    job,
                    "routes",
                    `${relative}:${line}:${m[1]}:${m[2]}`,
                    `${m[1].toUpperCase()} ${m[2]}`,
                    {
                      ...data,
                      line,
                      method: m[1].toUpperCase(),
                      route: m[2],
                      verified: false,
                      note: "Static pattern extraction; framework prefixes and dynamic routes may require review.",
                    },
                  );
              const m = value.match(
                /@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)/,
              );
              if (m)
                add(
                  job,
                  "routes",
                  `${relative}:${line}`,
                  `${m[1].toUpperCase()} ${m[2]}`,
                  {
                    ...data,
                    line,
                    method: m[1].toUpperCase(),
                    route: m[2],
                    verified: false,
                  },
                );
            }
            parseAPI(job, text, "source:" + relative, "source-import");
            extract(
              job,
              text,
              new URL(relative.replace(/\\/g, "/"), options.target).href,
              "source-import",
              options,
            );
            if (files % 100 === 0)
              log(
                job,
                `${files} source files imported (${Math.round(bytes / 1048576)} MiB)`,
              );
          }
        }
        await walk(root);
        add(job, "source", "__inventory__", "Source import coverage", {
          source: location,
          files,
          bytes,
          skipped,
          skippedReasons,
          limits,
          excludedDirectories: [...ignore],
        });
        stage(
          job,
          "Source repository",
          skipped ? "partial" : "complete",
          `${files} files, ${Math.round(bytes / 1048576)} MiB imported; ${skipped} excluded or limited entries`,
        );
        stage(job, "Git history", "running");
        try {
          const result = await execute([
            "-C",
            root,
            "log",
            "--all",
            "--date=iso-strict",
            "--format=%H%x09%aI%x09%s",
            "-n",
            "2000",
          ]);
          add(
            job,
            "git",
            "log",
            "Git history index",
            {
              source: location,
              limit: 2000,
              note: "Up to 2,000 commits indexed. Full available history is included in the bundle if size permits.",
            },
            result.stdout,
          );
          const info = await execute([
            "-C",
            root,
            "rev-parse",
            "--is-shallow-repository",
          ]);
          const shallow = info.stdout.trim() === "true";
          const bundlePath = path.resolve(
            "data/source-bundles",
            job + ".bundle",
          );
          await fs.mkdir(path.dirname(bundlePath), { recursive: true });
          await execute(["-C", root, "bundle", "create", bundlePath, "--all"]);
          const bundleInfo = await fs.stat(bundlePath);
          if (bundleInfo.size <= limits.bytes) {
            add(
              job,
              "git",
              "bundle",
              "Repository history bundle",
              {
                source: location,
                bytes: bundleInfo.size,
                shallow,
                note: "Git bundle contains locally available refs and history; no unreachable/reflog-only objects.",
              },
              await fs.readFile(bundlePath),
            );
          } else {
            stage(
              job,
              "Git history",
              "partial",
              "Git bundle exceeded source size limit; commit index retained",
            );
            return;
          }
          try {
            const patch = await execute(
              [
                "-C",
                root,
                "log",
                "--all",
                "-p",
                "-n",
                "100",
                "--no-ext-diff",
                "--no-textconv",
                "--format=commit %H",
              ],
              { maxBuffer: 12 * 1048576 },
            );
            add(
              job,
              "git",
              "recent-patches",
              "Recent history patches",
              { source: location, maxCommits: 100 },
              patch.stdout,
            );
            extract(
              job,
              patch.stdout,
              new URL("/__git_history__", options.target).href,
              "git-history",
              options,
            );
          } catch (e) {
            log(job, "Recent patch scan incomplete: " + e.message);
          }
          stage(
            job,
            "Git history",
            shallow ? "partial" : "complete",
            shallow
              ? "Shallow repository: only locally available history collected"
              : "Commit index, available history bundle, and recent patch scan collected",
          );
        } catch (e) {
          if (controller.signal.aborted) throw e;
          stage(
            job,
            "Git history",
            "partial",
            "Git history unavailable: " + e.message,
          );
        }
      });
      res.json({ id: job, session: req.body.session });
    } catch (e) {
      next(e);
    }
  });
}
module.exports = { mountSourceRecon };
