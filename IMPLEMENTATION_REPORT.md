# Firebase Test Lab implementation — APKTrust 0.4.0

Implemented in the existing application. Static scans still run without Firebase. No live APK was uploaded to Google during development.

## Added and changed files

| Files | Change |
| --- | --- |
| `src/apktrust/dynamic/base.py`, `models.py`, `__init__.py` | Asynchronous provider interface and provider-neutral typed contracts |
| `src/apktrust/dynamic/config.py`, `security.py` | Standard-library JSON/environment settings, bounded argument-list process execution, exact workspace/hash validation |
| `src/apktrust/dynamic/manager.py`, `store.py`, `correlation.py` | Durable jobs/results/artifacts/observations, restart recovery, audit, correlation preserving static evidence |
| `src/apktrust/dynamic/providers/firebase_test_lab.py`, `gcloud_client.py`, `providers/__init__.py` | Firebase adapter, discovery/compatibility, Robo execution, normalized outcomes, Google API result transport |
| `src/apktrust/__init__.py`, `cli.py`, executable `apktrust` | CLI commands for scans, doctor, providers, devices and explicit cloud runs |
| `server.py` | Optional local retention, static SDK/ABI metadata, dynamic endpoints, startup recovery, exports and version |
| `web/app.js`, `web/dynamic.js`, `web/index.html`, `web/style.css` | Provider status, separate consent, Dynamic tab, timeline, evidence, paginated logs and lazy screenshots |
| `dynamic-config.example.json`, `.env.example`, `.gitignore` | Safe defaults, supported overrides and credential exclusions |
| `tests/test_dynamic.py`, `test_dynamic_api.py`, `firebase_integration.py`, `pytest.ini` | Unit/local API/security/CLI tests and separately gated optional live tests |
| `docs/dynamic-analysis.md`, `docs/providers/firebase-test-lab.md`, `README.md`, `GUIDE.md` | Architecture, privacy, setup, commands and current limits |

## Architecture decisions

- The core manages normalized dataclasses and enum states through `DynamicProvider`; Google response objects are interpreted inside the adapter. A second mock provider is tested against the unchanged storage/manager contract.
- `GCloudTestLabClient` submits through the official asynchronous CLI. Status/cancellation, Tool Results and GCS retrieval use documented JSON APIs with transient active-gcloud credentials. There is no dependency on a nonexistent gcloud matrices-describe command. A future direct-API submitter can replace this transport.
- SQLite extends existing scan storage; no OAuth/private-key storage is added. Cross-process locks prevent duplicate driving of a job. Remote jobs resume; ambiguous interrupted uploads are never automatically resubmitted.
- Static uploads delete their input unless local retention is explicitly selected. Dynamic submission has a separate server-enforced cloud consent gate and hashes the exact retained file. The scanned hash is stored in the audit.
- Progress follows the application's existing polling transport with actual state transitions, not fabricated percentages. Runtime correlation appends evidence and LIMITED coverage without overwriting static findings/risk/confidence.

## Setup and environment

This machine currently has no `gcloud` and no configured Test Lab project. Read [Firebase setup](docs/providers/firebase-test-lab.md). After installing Google Cloud CLI:

```bash
cd /home/nard/Documents/Codex/2026-10-11/bui/outputs/apktrust
gcloud components update
gcloud auth login
gcloud config set project PROJECT_ID
gcloud firebase test android models list --project PROJECT_ID
```

Add these non-secret settings to the existing local `.env`, or set them in the server's shell:

```dotenv
APKTRUST_DYNAMIC_ENABLED=true
APKTRUST_FTL_PROJECT_ID=PROJECT_ID
```

Optional overrides: `APKTRUST_FTL_DEVICE_MODEL`, `APKTRUST_FTL_ANDROID_VERSION`, `APKTRUST_FTL_TIMEOUT_SECONDS` (300 default), `APKTRUST_FTL_JOB_TIMEOUT_SECONDS` (900 default). The JSON example contains locale/orientation and collection settings. Do not store Google credentials in `.env`, the repository or SQLite. Existing `gcloud auth login` credentials authenticate the controller only; automatic device Google login is disabled.

## Exact verification and execution commands

From the project directory:

```bash
./apktrust config doctor
./apktrust dynamic providers
./apktrust dynamic devices --provider firebase_test_lab
```

A deliberately selected APK, with interactive confirmation defaulting to No:

```bash
./apktrust scan /absolute/path/test.apk --dynamic firebase_test_lab
```

Explicit non-interactive upload:

```bash
./apktrust scan /absolute/path/test.apk \
  --dynamic firebase_test_lab --confirm-cloud-upload
```

Existing scan, with SHA-256-verified local reattachment if needed:

```bash
./apktrust dynamic run SCAN_ID --provider firebase_test_lab \
  --apk /absolute/path/original.apk --confirm-cloud-upload
```

Start the workbench with `./start.sh`, then use Scan history → scan → Dynamic. The running local preview has been restarted; refresh the browser for the new navigation.

## Test results

- **98 unit/local API tests passed** using `python3 -m unittest discover -s tests -q`. This includes the original 38 static/package/integration-mock/history tests. No Firebase quota was consumed.
- JavaScript syntax checks passed for `web/app.js` and `web/dynamic.js`; Python modules compile.
- Browser flow against an isolated fake-provider server passed: unchecked consent disables Upload & Run, explicit consent starts a durable job, completed evidence/artifacts render, log page search works, screenshot preview decodes, results remain after refresh.
- Responsive checks passed at 390×844, 768×1024 and 1440×900, with matching viewport/document widths and no browser console errors. The fixture uses synthetic data and a one-pixel image, not any user's APK or screenshot.
- Real preview smoke check passed: upload-first page, Dynamic Analysis navigation and safe NOT_CONFIGURED response. CLI doctor/providers/devices report missing setup without exposing credentials.
- **Live Firebase integration tests were not run**: `gcloud`/project authentication are unavailable and no cloud upload was authorized. Optional pytest tests are supplied, marked `firebase`, gated by `APKTRUST_FTL_INTEGRATION_TEST=1`; live APK submission also needs `APKTRUST_FTL_CONFIRM_CLOUD_UPLOAD=1` and `APKTRUST_FTL_TEST_APK`. pytest is an optional developer dependency, not present in the system Python used here. See the provider guide for commands.

## Known limitations and TODO

Firebase Robo is not a full malware sandbox. Runtime coverage is LIMITED; no PCAP, full filesystem/syscall tracing, memory dumps or Frida. The adapter currently normalizes structured test issues/crashes, durations, artifact references and completion metadata. It does not infer permission/network/installer behavior from raw logs or claim unvisited behavior is absent. Generic correlation supports explicit observations from future trustworthy collection methods.

Remote submission currently requires a compatible standalone APK; XAPK/APKS retain static support. Logs use page-local search/filter/download, not whole-file indexing. Screenshots are capped at 8 MiB and exports only optionally include references. Videos remain remote. Remote retention is governed by Google's storage/bucket policies. Configuration/job locking currently targets Linux/macOS; a Windows lock adapter is future work.

Remaining validation: live gcloud JSON submission and API retrieval against a selected Google project and test APK. Future work: API-backed submission client, structured runtime permission/activity/network evidence, split installation, automatic local retention cleanup and additional dynamic providers. No Git repository is linked in this workspace; GitHub About metadata was prepared in README but not published.

## Coordinated investigation and intelligence brief — 2026-10-11

Fixed premature completion: `/status` previously treated an internally saved static result as a finished report while enrichment was still running. The server now persists a four-stage pipeline, gates status/report publication, protects running scans from history clearing, records static and total durations separately, and recovers interrupted progress without repeating uncertain external requests.

The upload form includes explicit Firebase cloud-upload consent. Reputation and consented dynamic collection precede hosted AI synthesis. The AI input uses allowlisted aggregates across all evidence sources; raw APK/source, identifiers, endpoints, logs, screenshots and credentials are excluded. Existing static evidence and verdicts remain intact.

The report UI uses a narrative brief, source states, readable provider cards, recommendations, analysis gaps and expandable commentary. HTML export is escaped, offline-readable and contains no executable scripts or automatic screenshot/video downloads.

Verification: 112 standard-library unit/API tests passed with mocked transports; no live Firebase execution or hosted AI quota was consumed. The isolated browser flow confirmed no early report, static → reputation → dynamic → AI ordering, and all four terminal stage states. Desktop (1440×900), tablet (768×1024), and phone (390×844) checks found no document overflow; upload headers/start controls remain visible and cloud consent starts unchecked. Real running-app Firebase readiness was checked and returned READY.
