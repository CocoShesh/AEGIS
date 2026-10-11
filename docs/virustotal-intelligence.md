# VirusTotal evidence → AI intelligence

New scans with reputation selected automatically collect accessible VT evidence after the hash lookup or consented fresh APK analysis. AI runs after this collection and any consented Firebase execution. The UI preserves the original olive/cream palette and restores the three upload capability blocks.

Collected categories:

- File metadata, individual engine results, submission history, reputation/votes, Android Androguard metadata, signing metadata, tags, threat classifications, YARA/IDS/Sigma matches and characterization fields when present.
- Merged sandbox behavior summary: API/command activity, process/file/service actions, DNS/IP/HTTP/TLS observations, signatures and MITRE techniques when supplied.
- Individual sandbox reports and artifact availability flags.
- Contacted domains/IPs/URLs, dropped/bundled files, embedded domains/IPs/URLs.

This is 11 endpoint categories, not a claim to retrieve every VT resource. API plan, quota, report existence and bounded-response limits determine what is available. No PCAP, malware binary, screenshots, HTML sandbox report or arbitrary linked content is downloaded automatically. Each category records AVAILABLE, NO_DATA, ACCESS_DENIED, RATE_LIMITED, UNAVAILABLE or NOT_QUERIED. Rate limiting stops remaining calls. Pagination references are recorded as truncation, never followed blindly.

Calls are sequential and paced at 16 seconds by default; `APKTRUST_VT_REQUEST_INTERVAL_SECONDS` can configure 0–60 seconds. This is local request pacing, not a guaranteed provider quota. A normal collection can add about three minutes, plus provider latency. Each request has the existing bounded response and timeout rules.

All collected categories reach AI as normalized, source-labelled evidence with category IDs, states and explicit limits. VT public package identity, metadata and sanitized observables may now be included. API credentials, authorization/cookies, request bodies, raw source and APK bytes are excluded. URL queries/fragments and configured secrets are removed. Large lists/detail blocks are limited for the model context; full saved normalized metadata remains inspectable in the UI and JSON export. This is a substantive evidence report, not a promise to send unlimited raw provider JSON.

AI provides an executive summary plus evidence-referenced sections for detections, Android capabilities, runtime/network, cross-source correlation and gaps. It cannot alter deterministic static findings. VT sandbox observations remain external VT evidence, separate from Firebase runtime evidence and static references. Absent behavior and zero detections cannot establish safety.

For older scans, select **Intelligence → Refresh evidence & intelligence**. That queries the hash and accessible VT categories, then automatically regenerates the AI assessment. This does not re-upload the APK.

Restart `./start.sh` in the existing configured terminal and hard-refresh the browser to load the updated pipeline. Existing API keys remain unchanged.

References: [file objects](https://docs.virustotal.com/reference/files), [Androguard](https://docs.virustotal.com/reference/file-object-androguard), [behavior summary](https://docs.virustotal.com/reference/file-all-behaviours-summary), [behavior attributes](https://docs.virustotal.com/reference/file-behaviour-summary). Live cloud collection was not run during development; tests mock provider responses and browser fixtures do not persist to real history.
