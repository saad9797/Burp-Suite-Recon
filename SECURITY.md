# Security and privacy

Traceglass is a local tool for authorized testing. It binds to 127.0.0.1 and protects API requests with a process token and browser origin checks. Do not expose it through a reverse proxy, tunnel or public listener. Local users and software with access to your files can read the evidence.

The data/ directory contains unencrypted traffic, credentials, browser login state, imported source and generated packages. Exports retain original evidence even when previews are redacted. Review every export before sharing. Stop Traceglass before backing up or removing data/; preserve the entire directory if you need source bundles, profiles and generated packages as well as the database.

## Reporting vulnerabilities

Do not post secrets or exploit details in public issues. Use the repository Security tab and private vulnerability reporting if the owner has enabled it. If unavailable, open a minimal issue asking the maintainer to provide a private contact, without disclosing the vulnerability or evidence. A dedicated contact and response SLA have not yet been established.

Include affected version, a synthetic reproducer, expected and actual behavior, and impact. Only the latest published version is intended to receive fixes; there are no long-term support branches. Findings produced by this tool are heuristic observations requiring manual verification.
