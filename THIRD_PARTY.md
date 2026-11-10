# Third party components

Wappalyzer engine and fingerprint database: https://github.com/tomnomnom/wappalyzer, revision `30450a0841b28b5e89091110774d15867dd265c3`. Upstream GPL-3.0 license retained in `vendor/wappalyzer/LICENSE`. This copy is unchanged and runs locally; no Wappalyzer API subscription is required. Fingerprint freshness is limited to that upstream snapshot.

ProjectDiscovery httpx: https://github.com/projectdiscovery/httpx, MIT license. Installed separately by `npm run setup:httpx` from official release assets with SHA256 verification. The downloaded release includes its license in `tools/`.

Node dependencies and exact resolved versions are recorded in `package-lock.json`. Chromium is provided by Playwright's browser installer. Each component retains its upstream license.
