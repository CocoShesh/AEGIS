# Optional VirusTotal APK upload

APKTrust can upload a standalone APK for fresh VirusTotal analysis, in addition to existing SHA-256 lookups. In New scan, select **Request fresh VirusTotal analysis for this public APK**. The checkbox starts unchecked and resets when the file changes. The server independently enforces `confirm_vt_upload=true`; enabling a key alone never authorizes a file upload.

VirusTotal submissions can be included in its dataset and made available to its community. This option is for files the user has explicitly chosen to share. APKTrust does not implement VT Private Scanning. See [official upload documentation](https://docs.virustotal.com/reference/files-scan).

## Setup and workflow

Set `VT_API_KEY` in the local `.env`, restart `./start.sh` in the existing configured terminal, then hard-refresh the browser. Upload an APK, check the VT consent option and start the investigation. No extra key is required.

The pipeline completes static analysis and checks the SHA-256 in VT first. When the file exists, it requests [reanalysis of the existing file](https://docs.virustotal.com/reference/files-analyse) without uploading APK bytes. Only an explicit HTTP 404 triggers upload of the exact SHA-256-verified bytes with consent. Authentication, quota, network errors and rejected reanalysis never trigger an upload fallback. APKTrust then polls the returned analysis ID, performs URLhaus hash lookup, runs consented Firebase execution if selected, and generates the AI synthesis last. The final report waits until selected stages complete or record a gap. The result card distinguishes fresh reanalysis without upload, fresh analysis after upload, and an existing hash report. Reanalysis uses the same consented fresh-analysis option; ordinary hash lookups do not request reanalysis. Reanalysis is subject to provider access and quota.

The upload streams in 1 MiB chunks with a fixed multipart filename. APKTrust uses the [large-file upload URL](https://docs.virustotal.com/reference/files-upload-url) above 32 MiB, validates an HTTPS VT destination, never follows upload redirects, and retains no upload URL or API key in reports. APKTrust's own file limit remains 256 MiB. Remote analysis IDs, hash and submission/completion timestamps persist; a saved remote ID resumes polling after restart without another upload. If interrupted before the remote ID is saved, the stage records an interruption instead of blindly resubmitting.

Polling occurs at 30-second intervals with a 15-minute local deadline. Quota, authentication, unsupported files and timeouts create an explicit analysis gap. Static evidence remains available. Upload-only local copies are removed after the pipeline; retention explicitly selected for dynamic analysis is separate.

## Limits

Fresh file submission currently supports standalone APK only. XAPK/APKS retain static coverage and hash-lookup behavior; the checkbox is disabled for them. VT network relationships remain a separate bounded lookup because access and report availability vary. Completed engine analysis does not guarantee behavior relationships exist. No zero-detection result is labelled SAFE, CLEAN or NO MALWARE.

Tests mock all remote requests and consume no quota. This implementation has not uploaded a real APK as part of development verification.


Large APK upload destinations are obtained from the authenticated official
`/api/v3/files/upload_url` endpoint. HTTPS uploads accept only the exact
`www.virustotal.com` or `bigfiles.virustotal.com` host and `/_ah/upload/` route.
Other domains, userinfo, nonstandard ports and redirects remain blocked. Upload
URLs are single-use and are not persisted in reports or diagnostic output.
