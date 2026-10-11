# Local scanner integrations

The CLI engines are free/open source for this local app. Optional hosted/enterprise products and AI quotas are separate. Versions and official release SHA-256 digests are pinned in tools/scanners.lock.json. Binaries live under .tools and databases under .scanner-cache; neither credentials nor these large caches are part of the source ZIP.

Install Linux x86_64 tools: `python tools/install_scanners.py` (run from repository or use its full path). Refresh public databases: `python tools/update_databases.py`. First-time database setup can take several minutes and several GB on disk. Database-update failures remain explicit scan gaps. The source ZIP includes installer/configuration files, not prebuilt third-party binaries.

| Engine | What runs | Network during scan |
|---|---|---|
| Semgrep / Bandit | Application-owned source rules / Python analysis | Offline |
| Trivy | Local filesystem vulnerability and configuration checks | Offline, local vulnerability DB |
| OSV-Scanner | Declared/locked dependency advisory lookup; no dependency resolution or call/build analysis | Package names/versions queried against OSV |
| Gitleaks | Bounded regular files, default rules extended by owned config | Offline; secret matches redacted |
| Syft | Directory package catalog, no enrichment/build tooling or nested archive expansion | Offline |
| Grype | Syft SBOM advisory matching | Offline, local vulnerability DB |
| zizmor | Workflow/action audits; target ignores/configs disabled | Offline; online audits unavailable |
| YARA-X | Three owned static signatures | Offline; no broad malware rule corpus |

Regular input files are limited to 1 MB and no target code is executed. Missing binaries, malformed output, timeouts, unavailable DBs and unmapped results do not become clean results. Syft inventory is merged into dependency records. Advisory severity stays unknown/info when upstream metadata has no normalized severity. Original engine observations remain in provenance. Imported repository configs cannot enable plugins, builds, or hooks. Reports remain PARTIAL because runtime, nested/binary semantics, exact dependency resolution and database coverage remain bounded.

AI is optional commentary, not a detector. The hub shares APKTrust's configured Groq/OpenRouter/Gemini providers. Starting a scan authorizes automatic summary review; only bounded findings/coverage summaries leave the backend. Commentary is stored separately in local SQLite and included as such in exports. Coverage shows live provider availability rather than the obsolete “No AI provider configured” message. Old scans retain historical scanner results; rerun analysis to use newly installed engines.

Official project/license sources:
- https://github.com/aquasecurity/trivy
- https://github.com/google/osv-scanner
- https://github.com/gitleaks/gitleaks
- https://github.com/anchore/syft
- https://github.com/anchore/grype
- https://github.com/zizmorcore/zizmor
- https://github.com/VirusTotal/yara-x
- https://oss.anchore.com/docs/guides/vulnerability/database/

## Automatic AI assessment

Starting a URL or archive scan through AEGIS automatically reviews the bounded static findings with shared APKTrust providers. Repository identity and paths are excluded. Unsupported-text review sends bounded redacted text that can contain embedded URLs. The workbench and exports wait for both static engines and AI to finish. Provider failure releases static evidence with a visible AI failure. The assessment enum is HIGH_RISK, REVIEW_REQUIRED, NO_HIGH_RISK_IDENTIFIED or INCONCLUSIVE; these are AI opinions, not runtime safety certificates. Old reports are not automatically regenerated. Manual retry still requires its per-request consent.

AI metrics include a validated assessment, LOW/MEDIUM/HIGH confidence with a reason, and full severity counts from static findings. Confidence is qualitative evidence strength, not a calibrated safety probability. AI receives at most 80 finding summaries plus total counts and the supplied count. Older reports without confidence display Not recorded; regenerate AI to add these fields.

Unsupported-text review: up to 24 readable unsupported objects, 8,000 characters per object, and 48,000 characters total. Truncated objects are AI partial, unreadable/over-budget objects AI skipped, provider/schema failures AI failed. Validated per-object reviews are saved in AI commentary and attached to file rows on retrieval. Original static statuses and inspected percentages do not change.
