# RepoSentinel — Repository Security

The repository investigation module in [AEGIS](../README.md), served at `/repository/`. It lives alongside the hub and APKTrust in the same GitHub repository.

## Investigation flow

1. Enter a public GitHub URL with an optional branch/tag/commit, or upload a `.tar.gz` snapshot.
2. Run first-party static inspection and installed external engines against bounded, regular files.
3. Automatically assess findings and unsupported readable text with shared Groq/OpenRouter/Gemini providers.
4. Open the evidence workbench after both stages terminate; failed AI preserves static results.
5. Save review notes, export JSON/HTML/SARIF/CycloneDX, or remove finished scans from history.

AI assessments include qualitative confidence and reasons. Per-file AI reviews appear beside limited static coverage: AI-reviewed, partial, failed or skipped. They never overwrite static inspection status or coverage percentages.

## Setup

Run these commands from the repository root, after the [AEGIS runtime setup](../README.md#quick-start):

```bash
.venv/bin/python repository/tools/install_scanners.py
.venv/bin/python repository/tools/update_databases.py
./start.sh
```

Open http://127.0.0.1:8797/repository/. Scanner assets are pinned for Linux x86_64 and verified against published SHA-256 digests. Trivy and Grype need local public databases and several GB on disk. Missing tools/databases and scanner failures remain explicit gaps.

Integrated external engines: Semgrep, Bandit, Trivy, OSV-Scanner, Gitleaks, Syft, Grype, zizmor and YARA-X. YARA-X uses three owned signatures; zizmor is offline. [Detailed engine policy and versions](docs-engines.md).

## AI and limits

Starting a scan sends bounded findings/coverage summaries and redacted unsupported text to configured providers. The AI bridge excludes repository identity and paths, but embedded URLs can remain in text; redaction is best effort. Limits: 24 text objects, 8,000 characters each and 48,000 total. Over-budget/unreadable objects remain skipped; truncated content is partial. CSS/SVG extension-based AI filtering is not yet implemented.

GitHub intake uses GitHub; OSV queries package metadata. Other integrated scanning is offline with cached databases where required. Target code, builds, hooks and tests are never executed. Uploads are limited to 80 MB and 12,000 objects; regular-file inspection is limited to 1 MB. Binaries, nested archives, LFS/submodules and runtime behavior retain documented gaps.

## Source and development

| Path | Role |
|---|---|
| `reposentinel/` | Intake, analysis, jobs, storage, API, normalization and exports |
| `web/src/` | React/TypeScript evidence workbench |
| `rules/` | Application-owned scanner configuration/signatures |
| `tools/` | Pinned external-engine installer and database updater |
| `tests/` | Analysis, scanner, lifecycle and API checks |
| `../repository_ai.py` | Shared provider bridge and bounded file review |

From the repository root:

```bash
npm ci --prefix repository
npm run build --prefix repository
PYTHONPATH=repository .venv/bin/python -m pytest repository/tests integration_tests -q
```

History/reviews/AI commentary live in `.data/repositories/scans.sqlite` when run through AEGIS. Historical reports are not automatically upgraded; start a new scan to use new engines or AI changes. A completed assessment is not a safety certificate.
