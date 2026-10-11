# APKTrust · Local analyst workbench

An operational, dependency-free first implementation of the APKTrust v2 architecture, with a polished responsive interface. This is an early static investigation workbench, **not the complete v1.0 security platform or a malware verdict engine**.

## Start

Requires Python 3.12 or later. No packages or API keys are needed for static analysis. Optional integrations use your locally configured keys.

```bash
python3 server.py
```

Open http://127.0.0.1:8765. Use `--port 8766` to change the port. The server always binds to loopback.

## Investigate

1. Click **New scan**, choose an APK, XAPK or APKS, and start the investigation.
2. Inspect risk, confidence and coverage separately. Open a finding to review evidence and provenance.
3. Review coverage and artifact inventory, record analyst decisions, and export JSON, HTML or SARIF.


## Implemented

- APK, XAPK and APKS intake; component SHA-256, base/split manifest identity, package-set ledger and split-attributed findings. OBB/container assets are inventoried with explicit unanalyzed content status.
- Streaming SHA-256 and bounded upload, maximum two concurrent jobs.
- Archive inventory with path traversal, duplicate, symlink and compression-ratio rejection. No sample extraction or execution.
- Text and binary Android XML manifest parsing; package/version, declared permissions and component attributes.
- Manifest rules for explicit debuggable builds, cleartext policy and explicitly exported components without component-level permissions.
- Bounded DEX/native/asset byte-reference indexing and literal endpoint extraction. Five contextual API/capability rules.
- Per-file inventory, stage coverage ledger, evidence source/offset/hash, conservative confidence, partial/inconclusive wording.
- Parser subprocess with Unix CPU/address-space/file limits and timeout; original upload deleted after analysis.
- SQLite scan persistence; saved review state; JSON, escaped HTML and SARIF exports.
- Responsive interface, keyboard controls and modal focus handling, searchable findings, severity/review filters, evidence drawer, dark theme, history and analyzer diagnostics.
- Optional Groq/OpenRouter/Gemini explanation adapters with validated JSON, provider failover, cooldown and deterministic fallback. Only allowlisted static, permission, reputation and runtime aggregates are sent when AI is selected.
- Optional VirusTotal/URLhaus top-level hash lookups, with no APK uploads or URL submissions.
- Strict same-origin upload checks, loopback Host validation for mutations, CSP, escaped sample-controlled text and non-clickable endpoint strings.

## Explicitly unavailable

- AAB conversion and device-specific APKS variant selection.
- Signature/certificate verification, JADX/apktool integration, control-flow/call graphs, taint analysis, complete native semantics, trackers/SBOM, source/binary comparison.
- Android sandbox and network containment, local model adapters, signed rule packs, arbitrary plugins, team authentication/RBAC and release signing.
- SSE, durable in-progress orchestration, restart resume, stage retry and cancellation. Current jobs use status polling; completed reports persist across restarts. An interrupted job has no completed report.

Behavior graphs show an explicit unavailable state until a graph analyzer is configured. A byte match is a **signal**, not proof of execution or exfiltration. The analysis coverage percentage reports completed analyzer stages, not a measured percentage of analyzable code or a safety percentage.

Subprocess resource limits are **not** a complete filesystem/network sandbox. This build should be used on a disposable workstation for untrusted samples until the restricted-worker/container integration is implemented. It never executes sample code, invokes shell commands from sample data, or automatically uploads content. Do not expose this local build over the network.

## API

- `POST /api/v1/scans?filename=sample.apk`: raw APK/XAPK/APKS bytes, `application/octet-stream`.
- `GET /api/v1/scans`: persisted completed/partial reports.
- `GET /api/v1/scans/{id}/status`: in-memory progress or persisted report.
- `GET /api/v1/scans/{id}`: report.
- `GET /api/v1/scans/{id}/{findings|coverage|inventory|endpoints|permissions|components}`.
- `POST /api/v1/scans/{id}/findings/{finding_id}/review`: JSON `{"status":"Confirmed"}`, `Dismissed`, or `Needs review`.
- `GET /api/v1/scans/{id}/report.{json|html|sarif}`.
- `GET /api/v1/system/health`.

Reports and normalized evidence are in `.data/scans.sqlite3`. This includes potentially sensitive endpoint or sample strings. The uploaded APK is removed after the worker finishes; reports remain local. Local reports are not encrypted at rest.

## Validation

```bash
python3 -m unittest discover -s tests -v
node --check web/app.js
```

Security regression tests cover binary and text manifest parsing, traversal, duplicate paths, unsupported archives, failed-manifest coverage, indexing budgets, contextual evidence, and hostile text preservation. Package tests additionally cover split-only signals, OBB gaps, corrupt components, nested traversal, mixed packages, shared indexing budgets and APK count limits.

## Implementation choices

Uses Python's standard library HTTP server, SQLite and a buildless frontend to keep this first local deliverable immediately runnable. The document's FastAPI/Next.js recommendations are a future migration target, not claimed dependencies of this build. No third-party assets or scripts load into the browser.

## XAPK / APKS boundaries

The container SHA-256 and each component SHA-256 are distinct. Evidence preserves its component hash and adds the container hash. Paths use `component.apk!/path` to prevent cross-split ambiguity. All bundled variants are inspected; selecting a device-compatible install set is not implemented. Package/version inconsistencies and ambiguous base selection are reported as limitations. APK components share the 128 MiB indexing budget, 50,000 nested-entry budget and 2 GiB declared nested-content budget. Containers may have up to 128 APK components, each up to 256 MiB. Corrupt/unsafe components remain failed ledger entries while successfully processed components retain their evidence. Temporary component copies are supervised and removed after analysis, including worker failure.

## Configure AI and threat intelligence

Edit the local `.env` beside `server.py`. A blank private file is prepared for this workspace; new installations can copy `.env.example` to `.env`. Paste values on their own lines:

```dotenv
GROQ_API_KEY=your_groq_key
GROQ_MODEL=openai/gpt-oss-20b
OPENROUTER_API_KEY=your_openrouter_key
OPENROUTER_MODEL=openrouter/free
GEMINI_API_KEY=your_gemini_key
GEMINI_MODEL=gemini-3.5-flash-lite
URLHAUS_AUTH_KEY=your_abuse_ch_auth_key
VT_API_KEY=your_virustotal_key
```

Model defaults come from the supplied test report, not a guarantee of future model availability. Use AI providers → Test connection for current account validation. Keys are loaded fresh for each request; environment variables take precedence over the file. File values are literal; no shell expansion or `source` is used. No secrets are returned by the provider-status endpoint. Keep `.env` out of Git, archives and screenshots, and restrict file permissions to your account.

Test connection makes a fixed generation request for AI (using API quota), a recent-list request for URLhaus, or a known test-hash query for VirusTotal. A VirusTotal 404 is unconfirmed authentication rather than a falsely successful key test.

Select a real investigation in Scan history, then go to AI providers. Send minimal summary to AI starts opt-in Groq → OpenRouter → Gemini → local fallback. Provider text is untrusted commentary; it cannot change risk, confidence, findings or evidence. The 2048-token output budget is larger than the insufficient 20-token test budget in the supplied report.

Look up SHA-256 externally sends only the top-level hash to VirusTotal and URLhaus. For XAPK/APKS this is the container hash; individual component hashes are not queried. URLs extracted from the sample are not submitted or looked up. A NOT_FOUND result is not a clean verdict. Each request has a 20-second timeout and responses are capped at 1 MiB; HTTP redirects are rejected. AI has one retry per provider and opens a 60-second circuit after three failed attempts. Static analysis never invokes these integrations automatically.

Additional endpoints: `GET /api/v1/providers/status`, `POST /api/v1/providers/{id}/test`, `POST /api/v1/scans/{id}/ai/explain`, `POST /api/v1/scans/{id}/reputation`.

Official API references: [Groq](https://console.groq.com/docs/api-reference), [OpenRouter](https://openrouter.ai/docs/api/api-reference/chat/send-chat-completion-request), [Gemini](https://ai.google.dev/api/generate-content), [URLhaus](https://urlhaus-api.abuse.ch/), [VirusTotal](https://docs.virustotal.com/reference/file-info).

## History and fresh scans

There is no analyzer-result cache: each upload writes a new input, creates a new scan ID and starts a fresh analyzer subprocess. Reports record `cache_used: false`, start/finish timestamps and execution provenance. Scan duration excludes upload transfer. Bounded static checks can complete quickly; clearing history does not activate deeper analyzers.

Scan history → Clear history hides completed saved reports and removes their completed in-memory status snapshots. API keys and running scans are preserved. Undo clear restores that batch; its token is retained locally across browser refreshes. This is reversible history clearing, not secure deletion or disk reclamation. There are no built-in sample investigations. The first page is an upload screen, and history contains only user-created scans.

History endpoints: `POST /api/v1/scans/clear-history` and `POST /api/v1/scans/restore-history/{undo_token}`.

The initial page accepts package selection or drag/drop before opening the scan options. No sample report is selected automatically. Real previously uploaded BeatWave packages, like any other real scan, remain in history until the user clears it.


## Optional remote dynamic analysis (v0.4.0)

Firebase Test Lab Robo is now available through a replaceable DynamicProvider interface. It requires an installed authenticated gcloud and configured project. Cloud uploads require explicit consent and automatic Google login is disabled. Static scans still work without Firebase. Retain an APK locally explicitly or reattach the exact matching APK after scanning. See [dynamic analysis](docs/dynamic-analysis.md) and [Firebase setup](docs/providers/firebase-test-lab.md) for commands, durable jobs, artifacts, privacy and limitations.

## Automatic AI and reputation results

New scans enable two visible, optional checkboxes by default: combined AI intelligence synthesis and VirusTotal/URLhaus SHA-256 lookups. Uncheck either to keep that request local. The upload form also offers an unchecked cloud-upload consent option. When checked, Firebase runs within the same pipeline before AI synthesis. API uploads remain static-only unless `auto_ai=true` and/or `auto_reputation=true` are supplied in the upload query.

The scan waits for every stage to complete or explicitly fail/skip. Static results are saved internally for correlation but are not published as a finished report during enrichment. Results are persisted in the scan report. Open **Overview** or **Intelligence** to see the results. Existing scans can use the run buttons in that section. AI uses the configured provider fallback chain; it does not inspect the APK bytes. VirusTotal and URLhaus query existing records for the top-level hash, without uploading the APK. Missing records do not establish safety. Hosted AI synthesizes the collected static, reputation and runtime summaries. A local AI fallback is labeled as hosted AI unavailable. Provider failures preserve static evidence.

Restart the running server after updating backend code, then refresh the browser. No real API requests are made by the normal test suite.
