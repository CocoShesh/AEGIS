# Firebase Test Lab Robo provider

Firebase Test Lab executes an Android app on a Google cloud device without a local emulator. It is a cloud app testing platform, not a complete malware sandbox. Every APK upload requires explicit APKTrust consent.

## Setup

Install the [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) outside the APKTrust repository. Use a Google Cloud/Firebase project with Test Lab access, suitable IAM permissions, enabled Cloud Testing/Tool Results services and permission to read the results bucket. Availability, billing and quota depend on your project; APKTrust does not prescribe quota values.

Run locally:

```bash
gcloud components update
gcloud auth login
gcloud config set project PROJECT_ID
gcloud firebase test android models list --project PROJECT_ID
gcloud firebase test android versions list --project PROJECT_ID
```

Package-manager installations of gcloud may require their package manager for updates. Google documents setup, roles and prerequisites in [Start testing with gcloud](https://firebase.google.com/docs/test-lab/android/command-line). APKTrust does not install gcloud or enable APIs/billing automatically.

The CLI account authenticates the controller on this machine; **it is never logged into the tested app**. Robo always runs with `--no-auto-google-login`. No account credentials, Robo directives, login scripts, APKTrust API keys or credential files are passed to the tested app. Dedicated synthetic test-account support is not implemented.

## APKTrust configuration

From the APKTrust project directory:

```bash
cp dynamic-config.example.json dynamic-config.json
```

Set `dynamic.enabled` to `true` and `dynamic.firebase_test_lab.project_id` to your project ID. Keep model/version null for discovery. Alternatively add these lines to `.env` beside `server.py` (or export them in the server terminal):

```dotenv
APKTRUST_DYNAMIC_ENABLED=true
APKTRUST_FTL_PROJECT_ID=PROJECT_ID
# Optional device override; empty means discover a compatible virtual device.
APKTRUST_FTL_DEVICE_MODEL=
APKTRUST_FTL_ANDROID_VERSION=
APKTRUST_FTL_TIMEOUT_SECONDS=300
APKTRUST_FTL_JOB_TIMEOUT_SECONDS=900
```

Required to run: the enable switch, project ID and an authenticated installed gcloud. Model/version are optional. Locale defaults to `en`, orientation to `portrait`. File configuration controls logs/screenshots/video collection. `no_auto_google_login` must be true. `retain_remote_results` must be true: this MVP does not implement remote deletion.

Robo timeout defaults to 300 seconds. APKTrust's whole-job deadline defaults to 900 seconds and must be at least 120 seconds longer than the Robo timeout. Submission is bounded to 180 seconds, catalog commands to 45 seconds, token retrieval to 30 seconds and HTTP requests to 30 seconds. Artifact collection has a separate maximum 180-second remaining-budget window. Command output is capped at 1 MiB; excessive output becomes a collection gap.

Configuration is reloaded for new jobs; running jobs keep their snapshot. A health result is cached for 60 seconds; **Check setup** / `config doctor` refreshes it. No `.env` credentials are sent to the browser. Do not put service-account keys in the project. `.gitignore` excludes `.env`, `service-account.json`, `credentials.json`, `*.key.json` and `.data/`. Use existing gcloud authentication. Standard service-account gcloud configurations may work but CI authentication deployment is not validated in this MVP.

## Verify configuration

```bash
./apktrust config doctor
./apktrust dynamic providers
./apktrust dynamic devices --provider firebase_test_lab
```

Doctor checks installed gcloud, an active authenticated account, configured/accessibile project, live Android models/versions and usable devices. It prints booleans and normalized errors, never account names, access tokens or credential content. It does not reserve a test or prove available quota. READY means the checks passed with dynamic enabled; actual submission may still be rejected by permissions/quota/device availability.

Selection uses the configured model/version if available and compatible; otherwise an available stable virtual model with a recent supported API level. Native ABI compatibility and minSdk are checked. Models/versions are discovered each run, never hardcoded. Unknown manifest metadata, split APKs, XAPK/APKS and incompatible devices are NOT_RUN, not passed.

## Run a deliberately selected test APK

One command for a fresh static scan and opt-in cloud execution:

```bash
./apktrust scan /absolute/path/test.apk --dynamic firebase_test_lab
```

The interactive question defaults to No. For explicitly authorized non-interactive execution:

```bash
./apktrust scan /absolute/path/test.apk \
  --dynamic firebase_test_lab --confirm-cloud-upload
```

For an existing scan (replace SCAN_ID with the static scan's printed ID):

```bash
./apktrust dynamic run SCAN_ID --provider firebase_test_lab \
  --apk /absolute/path/original.apk --confirm-cloud-upload
```

Omit `--apk` if that exact APK was already retained. Without non-interactive confirmation the command prints `Cloud upload requires explicit --confirm-cloud-upload.` CLI uses the same database/provider/correlation service as the web application. Do not run these cloud commands on private APKs unless their upload is intended and permitted.

## Transport and outcomes

[gcloud's official run command](https://docs.cloud.google.com/sdk/gcloud/reference/firebase/test/android/run) is built as an argument list with `shell=False`, `--async`, `--type robo`, project, selected device, timeout, sanitized matrix label and `--no-auto-google-login`. No user field is interpreted by a shell. Only the exact managed scan artifact with the recorded SHA-256 can be submitted.

Asynchronous JSON submission returns a TestMatrix identifier. Monitoring and cancellation use the documented [Cloud Testing TestMatrix API](https://firebase.google.com/docs/test-lab/reference/testing/rest/v1/projects.testMatrices); a gcloud `matrices describe` command is not assumed. Structured issues/durations use [Tool Results steps](https://firebase.google.com/docs/test-lab/reference/toolresults/rest/v1beta3/projects.histories.executions.steps). GCS object metadata and bounded ranged downloads use Cloud Storage JSON endpoints. The adapter obtains a transient access token through the active gcloud account and holds it only for each request. Redirects and non-Google endpoints are rejected. Raw CLI stderr, command environment, raw matrix specifications and tokens never enter the report/database.

Legacy gcloud outcomes: 0 success, 1 general error, 2 invalid arguments, 10 failed tests, 15 inconclusive, 18 unsupported environment, 19 cancelled, 20 infrastructure error. Since `--async` returns before execution, a zero submission exit does not mean the test completed. Matrix `state` and `outcomeSummary` determine final outcomes. Unknown results are INCONCLUSIVE. Artifact fetch failures add explicit gaps instead of asserting a clean execution.

## Optional live tests

Install pytest in your development environment if needed. Default execution skips live access:

```bash
python3 -m pytest tests/firebase_integration.py -m firebase -q
```

Read-only live health/catalog check:

```bash
APKTRUST_FTL_INTEGRATION_TEST=1 \
  python3 -m pytest tests/firebase_integration.py -m firebase -q
```

A live Robo test additionally requires a consciously selected APK and separate cloud-upload consent; this consumes project quota:

```bash
APKTRUST_FTL_INTEGRATION_TEST=1 \
APKTRUST_FTL_CONFIRM_CLOUD_UPLOAD=1 \
APKTRUST_FTL_TEST_APK=/absolute/path/test.apk \
  python3 -m pytest tests/firebase_integration.py -m firebase -q
```

## Limitations

No live project is provisioned by APKTrust. Robo may fail to reach authenticated flows and cannot establish complete behavioral coverage. Screens explored are not estimated from screenshot count. Generic issue metadata cannot prove microphone access, network destinations or install intents. Absent artifacts remain MISSING; unavailable instrumentation is NOT_AVAILABLE. There is no secure verdict derived from Robo success.

Detailed results follow Google's [result storage policies](https://firebase.google.com/docs/test-lab/android/analyzing-results), including configured bucket lifecycle rules. The retain flag preserves references and requests no deletion; it does not promise indefinite storage. Large videos remain remote. Firebase is one replaceable optional implementation, not a required part of the APKTrust static scanner.

Compatibility also checks known Android installation targetSdk floors: [Android 14/15 low-target restrictions](https://developer.android.com/about/versions/15/behavior-changes-all). An older saved scan without SDK metadata must be rescanned locally before remote submission. Device choice attempts compatibility; actual install/runtime success still depends on Firebase outcomes.


## Device-selection troubleshooting

Provider READY confirms access to the catalog; each APK still needs a compatible
SDK, ABI and device configuration. ARM virtual device IDs contain a period
(for example `MediumPhone.arm`). APKTrust accepts these official catalog IDs
while rejecting shell metacharacters, path separators and device-argument commas.
Version-specific `preview`, `beta`, `deprecated` and `reduced_stability` tags are
applied only to their tagged Android versions; automatic selection uses stable,
compatible virtual configurations from the current catalog.

A NOT_RUN job collected no runtime evidence. It is shown as "Execution not
started", with NOT_RUN coverage and no execution duration. Failed historical
jobs are not automatically resubmitted. After updating APKTrust, restart its
server, refresh the browser, then explicitly consent to a new run from Dynamic.
Reattach the exact original APK locally if the scan did not retain it.


### Required APIs and validation failures

Device catalog access alone does not prove that remote execution is configured.
APKTrust checks the enabled service list before upload and requires both
`testing.googleapis.com` (Cloud Testing API) and `toolresults.googleapis.com`
(Cloud Tool Results API). Enable them in your own configured project:

```bash
gcloud services enable testing.googleapis.com toolresults.googleapis.com --project YOUR_PROJECT_ID
./apktrust config doctor
```

`SERVICE_NOT_ACTIVATED` means a required cloud API is disabled, not an APK malware
finding. Firebase may reject a matrix during validation after upload. The adapter
recovers the existing matrix identifier from gcloud's fixed validation diagnostic,
reads its structured status and records `API_DISABLED`; it never resubmits the APK
as part of recovery. If the status read fails, the saved matrix can be polled later.
Robo duration excludes local preparation, upload, queueing and result collection.
Enabling APIs requires appropriate Google project permissions. APKTrust does not
change Google services automatically. See the [official API requirements](https://firebase.google.com/docs/test-lab/android/continuous#requirements).
