# Optional remote dynamic analysis

APKTrust adds remote runtime observations to its deterministic static evidence. The first adapter is Firebase Test Lab Robo; a local Android emulator is not required. Static scans and local explanations work with dynamic analysis disabled.

## Data flow and consent

1. Upload and run a normal local static scan. Select **Retain this APK locally** if you want to run dynamic analysis later. Retention alone sends nothing outside this machine.
2. Open **Scan history → selected scan → Dynamic**. Older scans need **Attach original APK locally**: SHA-256 must match the original static report.
3. Choose **Run cloud dynamic analysis**, check **I understand this APK will leave this machine**, then choose **Upload & Run**.
4. APKTrust verifies the exact managed file, selects a compatible device and uploads it to Google. Google executes Robo; APKTrust polls actual state transitions and collects bounded result metadata. No synthetic percentages are shown.
5. Logs/screenshots are fetched only on request. Videos stay remote and are viewed through the authenticated Firebase console.

The server also enforces consent: a UI checkbox alone is not trusted. A CLI invocation needs a `y` answer or `--confirm-cloud-upload`. The default answer is No. Cloud submission can consume quota and incur charges. Quota is UNKNOWN unless the provider reports exhaustion; there are no hardcoded quota/pricing assumptions.

Local retained APKs are private files under `.data/dynamic/inputs/<scan-id>/app.apk`. Reports and artifacts are in `.data/scans.sqlite3`. History clearing hides reports; it does **not** delete local APKs, dynamic audits or Google results. Remote retention follows Google/bucket policies, not a guaranteed retention period imposed by APKTrust. Delete retained local inputs manually when no longer needed; avoid doing so while a job is uploading.

## Architecture

```text
Static report → DynamicManager → DynamicProvider
                                  └─ FirebaseTestLabProvider
                                       └─ GCloudTestLabClient
                                           ├─ gcloud: auth checks/catalog/submission
                                           ├─ Cloud Testing: matrix status/cancellation
                                           ├─ Tool Results: execution issues/duration
                                           └─ Cloud Storage: object metadata/ranged content
```

`src/apktrust/dynamic/base.py` defines asynchronous health, preparation, submission, status, result collection, cancellation and artifact-access methods. Models are dataclasses and string enums; no Google SDK objects cross the adapter boundary. Provider names and optional `provider_metadata` are plain normalized data. Other providers register in `PROVIDERS` and implement the contract. Core storage, correlation, HTTP handlers and report exports accept normalized models.

The JSON configuration intentionally uses the standard library rather than introducing a YAML dependency. Copy `dynamic-config.example.json` to `dynamic-config.json`. Environment variables or matching lines in `.env` override the file. See [Firebase setup](providers/firebase-test-lab.md).

## Durable lifecycle

SQLite tables `dynamic_jobs`, `dynamic_executions`, `dynamic_artifacts` and `dynamic_observations` store normalized records. Job records include consent time, scan association, uploaded SHA-256, actual device, remote identifier, provider result URL, stage transitions and adapter/app versions. Configuration snapshots contain allowed settings only, never OAuth tokens or service-account keys.

Jobs resume monitoring after a server restart once a remote identifier has been saved. A submission interrupted before its remote identifier was persisted becomes INCONCLUSIVE; APKTrust never blindly uploads it again. Check the provider console before manually retrying. Cross-process file locks prevent a CLI/server pair from driving the same job simultaneously. One scan cannot start a second job while its previous job is active. At most two dynamic workers run in one process.

States: PENDING, UPLOADING, QUEUED, RUNNING, COLLECTING, COMPLETED, FAILED, INCONCLUSIVE, CANCELLED, TIMED_OUT and NOT_RUN. NOT_RUN represents compatibility/configuration failures. Dynamic failure leaves the static `state`, risk, confidence and evidence intact and adds `analysis_completion: COMPLETED_WITH_GAPS`.

The existing web app uses job polling, so dynamic progress uses the same transport (five-second polling), not a newly invented SSE service. Stage timestamps are durable. A cancellation request does not mean Firebase has already stopped; the adapter polls for the remote outcome. On a provider deadline, it attempts cancellation and records the need to verify the remote console.

## Evidence and coverage

Static findings retain their original evidence and verdict. Correlation appends supports/contradicts/unresolved runtime evidence without deleting static evidence or reducing deterministic confidence. Explicit permission observations can support a manifest declaration; explicit installer activities can support an installer reference. A Robo completion summary alone cannot establish either behavior.

Runtime observations and findings use `FIREBASE_TEST_LAB` / `DYNAMIC_FIREBASE`. The report names the separate `STATIC`, `SOURCE_COMPARISON`, `DYNAMIC_FIREBASE` and `AI_ASSESSMENT` evidence classes. Source comparison is still unavailable; naming a class does not claim it ran.

The MVP reads structured Tool Results issues (crashes/test failures), durations and Robo completion metadata. It does **not** currently derive arbitrary permissions, network traffic or installation events from raw log text. Correlation supports such normalized observations when an adapter supplies explicit evidence; it never fabricates them.

Coverage stays LIMITED. Authentication-required/unvisited paths remain unknown. Use “behavior not observed during this Firebase Robo execution,” never absence/safety claims. Firebase is an app testing platform, **not a full malware sandbox**. Full filesystem/syscall tracing, PCAP, memory dumps and Frida are NOT_AVAILABLE.

## Artifacts and reports

Artifact states distinguish AVAILABLE, MISSING, FAILED_TO_FETCH and NOT_SUPPORTED. Artifact metadata is bounded to 10,000 GCS objects; truncated listings are recorded as gaps. Objects without requested type support are not claimed as evidence. GCS permissions or missing Tool Results data become explicit collection gaps.

The UI only shows sections with data. Logs use 32 KiB pages (API maximum 64 KiB), local page search/severity filters, original timestamps, copy and page download. Page boundaries may split a line/UTF-8 character; search is not a whole-log search. Tokens matching known credential patterns are redacted, but logs/screenshots may still contain app-specific private content; view/export them deliberately.

Screenshot previews are capped at 8 MiB and accept PNG/JPEG. A gallery loads an image only on click. Exports exclude screenshot references by default; the checkbox includes **references**, not image binaries. No export embeds remote screenshot contents. Videos are never fetched into the browser automatically. Remote content is accessed with existing Google credentials server-side; no tokens go to the browser.

## HTTP interface

All requests require a loopback Host. Mutations require same-origin requests. Read operations do not submit APKs.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/v1/dynamic/providers` | Cached normalized health (60 seconds) |
| POST | `/api/v1/dynamic/doctor` | Fresh read-only setup check |
| GET | `/api/v1/dynamic/devices?provider=firebase_test_lab` | Live normalized device catalog |
| GET | `/api/v1/scans/<scan-id>/dynamic` | Durable jobs/results and local retention status |
| POST | `/api/v1/scans/<scan-id>/dynamic/artifact` | Attach exact original APK locally (raw bytes) |
| POST | `/api/v1/scans/<scan-id>/dynamic` | Submit with JSON `confirm_cloud_upload: true` and provider |
| POST | `/api/v1/scans/<scan-id>/dynamic/<job-id>/cancel` | Request cancellation; JSON `{}` |
| POST | `/api/v1/scans/<scan-id>/dynamic/<job-id>/artifact` | Fetch selected artifact/page by stored artifact ID |

Artifact requests carry `artifact_id`, optional `offset` and `limit`. They can only reference artifacts stored for that scan/job, never arbitrary URLs or local paths. Static upload adds optional `retain_dynamic=true`; it is local retention, not remote consent.

## Verification

```bash
python3 -m unittest discover -s tests -q
node --check web/app.js
node --check web/dynamic.js
```

Normal tests use mock Firebase transports and local HTTP only; they never consume quota. Optional pytest tests are explicitly named `tests/firebase_integration.py`, outside normal `test_*.py` discovery, marked `firebase` and skipped unless `APKTRUST_FTL_INTEGRATION_TEST=1`. See the provider guide for separate live-upload consent.

## Remaining work

- Confirm the adapter with a live Google project/CLI version and a deliberately chosen test APK.
- Add a fully API-backed submission client behind the existing transport boundary.
- Add trustworthy structured activity/permission/network observations when available; preserve coverage gaps.
- Add split-package installation, retention cleanup controls, whole-log indexed search and optional streamed video access.
- Add other providers without making Firebase mandatory.

Compatibility also checks known Android installation targetSdk floors: [Android 14/15 low-target restrictions](https://developer.android.com/about/versions/15/behavior-changes-all). An older saved scan without SDK metadata must be rescanned locally before remote submission. Device choice attempts compatibility; actual install/runtime success still depends on Firebase outcomes.

## Upload pipeline integration

The web upload form can consent to cloud dynamic execution before the scan starts. Consent is unchecked for each new file. A consented standalone APK is retained temporarily, verified against its static SHA-256, then submitted through the configured DynamicProvider. Execution-only local copies are deleted after the pipeline finishes unless the user separately requests local retention.

Static checks run first, then hash reputation, dynamic collection/correlation, and finally AI synthesis of allowlisted evidence aggregates. The final report waits for all stages to reach a terminal state. Unconfigured, incompatible, timed-out or failed dynamic execution creates an explicit gap and does not invalidate the static findings. Progress uses stage states and actual elapsed time, without invented percentages.

For API upload clients, `auto_dynamic=true` requires `confirm_cloud_upload=true` in the upload query. `auto_ai=true` and `auto_reputation=true` select the corresponding enrichment. API defaults remain static-only for backward compatibility. Report endpoints reject requests while the pipeline is running. Refreshing the browser resumes monitoring; application restart resumes persisted remote jobs without duplicating uploads. Interrupted AI/hash requests are not silently repeated.
