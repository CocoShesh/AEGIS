# APKTrust — Android Security

The Android investigation module in the unified [AEGIS repository](../README.md). Open it from the landing hub or directly at `/android/`.

## Capabilities

- Local static evidence for APK, XAPK and APKS inputs.
- Permissions, findings, coverage and package investigation history.
- Optional VirusTotal/URLhaus intelligence and Groq/OpenRouter/Gemini synthesis.
- Optional consent-based Firebase Test Lab uploads and remote execution.

## Run

For the complete suite, follow the [AEGIS setup](../README.md#quick-start), run `./start.sh` at the repository root and open http://127.0.0.1:8797/android/.

The original Android-only server and CLI remain available from the root:

```bash
./start-android.sh --port 8765
./apktrust scan /absolute/path/to/app.apk
```

The standalone Android server requires Python 3.11+ and Unix `fcntl`; the combined AEGIS runtime requires Python 3.12+. Maximum browser package upload is 256 MiB. Replace the example package path with a real input.

## Files, configuration and history

`index.html`, `style.css` and `app.js` are the Android frontend; `../server.py` is the backend. Credentials live in the root `.env`; the empty `.env.example` lists supported entries. Android reports stay in `.data/scans.sqlite3`, separately from repository history.

Provider requests and dynamic uploads keep their Android-specific consent behavior. AI configuration is shared with RepoSentinel, whose automatic review policy is described in its module guide. Static findings are not safety guarantees.

See the [full Android configuration guide](../docs/apktrust-guide.md), [root privacy/data flow](../README.md#ai-and-data-sharing) and [RepoSentinel guide](../repository/README.md).
