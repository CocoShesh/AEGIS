# AEGIS integration

AEGIS is the product shell for the existing APKTrust Android analyzer and the RepoSentinel repository analyzer. Engine identifiers remain intact in evidence and exports so historical reports retain their provenance.

## Run

```bash
./start.sh
```

Open http://127.0.0.1:8797/ and choose **Android Security** or **Repository Security** on the landing page. Use **Analysis hub** to return from either sidebar. Repository deep link: http://127.0.0.1:8797/repository/.

This local checkout links `.venv` to the previously installed RepoSentinel runtime. For an extracted source bundle, install an independent environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -r repository/requirements.txt -r repository/requirements-scanners.txt
./start.sh
```

Python 3.12+ is required. The archive contains the compiled repository UI. To rebuild, use `npm ci --prefix repository` followed by `npm run build --prefix repository`. The compiled base is `/repository/`.

The standalone Android CLI remains `./apktrust`. The original Android-only server launcher is `./start-android.sh`. Existing `.env` and `.data` remain in this checkout; they are excluded from the source archive.

## Architecture and boundaries

`sentinel.py` owns the loopback origin. It mounts the repository FastAPI app at `/repository` and supervises the existing Android HTTP server on an automatically assigned private loopback port. Android requests are forwarded only to that fixed local process. The gateway rejects unexpected hosts, cross-origin requests and cross-site browser requests. Repository mutations still require the repository session token. Android upload limits and per-provider upload-consent checks remain in the Android server. The gateway caps uploads at 256 MiB; repository intake retains its stricter 80 MB limit.

Gateway shutdown terminates its supervised Android server and closes the repository process pool. Other already-running standalone apps are independent.

Android reports remain in `.data/scans.sqlite3`; repository reports and reviews are in `.data/repositories/scans.sqlite`. No historical Android report is converted to a repository report. Each workspace keeps its own investigation history. The integration does not add a combined cross-engine verdict or transfer repository content to Android AI/cloud providers.

## Design scope

The product title is **AEGIS**. Both workspaces use a shield/check symbol and the same workspace labels. Both operating workspaces now use the shared midnight-blue navigation, pale-blue selection and white evidence panels defined in `shared/theme.css`. Active workspace links use `aria-current=page`. Mobile menus expose the Analysis hub link, and the Android topbar stays above its open drawer so the navigation toggle remains operable. Underlying analyzer names in findings represent evidence provenance.

## Verification

- Android offline suite: 180 tests passed.
- Repository suite: 25 tests passed.
- Gateway boundary/mount/adapter suite: 5 tests passed.
- TypeScript/Vite production build and Android JavaScript syntax checks passed.
- Actual synthetic Android upload through the gateway returned manifest evidence; all external enrichment flags were disabled.
- Browser verification: workspace switching, real repository sample analysis with independent scanner provenance, saved review, four export formats, desktop/mobile layouts and mobile drawer opening/closing.

The integration retains each analyzer's existing limits. Repository reports remain PARTIAL. Missing engines, undecompiled Android code and unvisited runtime behavior remain explicitly incomplete evidence.

## AEGIS identity

AEGIS expands to **Android Evidence & Git Inspection System**. The meaning appears below the sidebar logo. New scan follows the identity block, then a separated Analysis hub link. Desktop and mobile use the same order.

## Landing page and intro

The landing page presents actual Android and repository capabilities, optional Android providers, an explicitly synthetic evidence example, and current analysis limits. Every visit or reload at `/` shows a full-viewport AEGIS introduction lasting approximately 6.8 seconds. Its percentage follows the welcome animation, not loading or scan readiness. Skip remains available, JavaScript-disabled pages stay usable, and reduced motion removes animated reveal and exit effects. It never starts an analysis or contacts a provider. Michroma is self-hosted with its OFL license. No third-party runtime font or analytics request is made.

Verified browser flows: intro completion, root reload repetition, Skip, both workspace entries and hub returns; equal computed sidebar backgrounds; desktop1440 and mobile390 without document overflow. Production build and five gateway tests passed.

## Module identity and shared AI

AEGIS names the hub. Android pages use APKTrust — Android Security; repository pages use RepoSentinel — Repository Security. RepoSentinel static analysis does not require AI. Its optional AI explanation tab reuses APKTrust's configured Groq, OpenRouter and Gemini providers via the gateway. No keys are copied or exposed to the browser. Starting a scan authorizes automatic summary review. Manual retries require explicit consent and the repository session token. Outbound evidence is bounded to finding IDs/titles, severity/confidence, engine/rule labels, coverage counts and limitations; repository identity and paths are excluded; unsupported-text review sends bounded redacted content, which may include embedded URLs. AI output is commentary, does not alter scanner findings, and is stored separately in local SQLite and included as commentary in exports. Provider errors retain static evidence and surface a retry/setup message.

Validation: production build and eight integration tests passed; AI response transport was tested with a mocked provider and an actual configured provider using only synthetic sample findings. Browser generation returned a summary.

## Sidebar and module marks

RepoSentinel history lives in the main Scan history view; the sidebar has no recent-scan list. Sample entry controls were removed and synthetic demo records cleared from the current local database without deleting actual scans. Desktop navigation is 264px wide, with adapted tablet/mobile widths. APKTrust uses an original constructed A with a verification cut; RepoSentinel uses an open source bracket and R branch. Both are single-color path SVGs used in navigation, landing entry links and favicons.

## Extended scanner release

Ten static engines are connected: RepoSentinel plus Semgrep, Bandit, Trivy, OSV-Scanner, Gitleaks, Syft, Grype, zizmor and YARA-X. RepoSentinel is the first-party engine; the nine external engines have distinct provenance. See `repository/docs-engines.md` for pinned versions, installation, network behavior and bounded coverage. Newly installed engines require a new scan; historical reports retain their original results. AI availability uses the shared gateway provider configuration and consent remains required.

## Automatic AI assessment

Starting a URL or archive scan through AEGIS automatically reviews the bounded static findings with shared APKTrust providers. Repository identity and paths are excluded. Unsupported-text review sends bounded redacted text that can contain embedded URLs. The workbench and exports wait for both static engines and AI to finish. Provider failure releases static evidence with a visible AI failure. The assessment enum is HIGH_RISK, REVIEW_REQUIRED, NO_HIGH_RISK_IDENTIFIED or INCONCLUSIVE; these are AI opinions, not runtime safety certificates. Old reports are not automatically regenerated. Manual retry still requires its per-request consent.

Unsupported-text review: up to 24 readable unsupported objects, 8,000 characters per object, and 48,000 characters total. Truncated objects are AI partial, unreadable/over-budget objects AI skipped, provider/schema failures AI failed. Validated per-object reviews are saved in AI commentary and attached to file rows on retrieval. Original static statuses and inspected percentages do not change.
