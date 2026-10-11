# APKTrust UI/UX audit — 11 October 2026

## Direction and design references
Retained APKTrust’s navy/blue identity. Applied a single UI type family, 28px page titles, 24px brief titles, 16px panel titles, 13px controls/body tables and 11–12px metadata. Code uses a dedicated monospace stack. Controls share padding, height, focus and hover behavior.

References: [Carbon dark-theme layering](https://www.carbondesignsystem.com/building-blocks/foundations/color/overview) and [Carbon chart palettes](https://v10.carbondesignsystem.com/data-visualization/color-palettes/). These informed surface layering and readable chart colors; no external runtime dependencies or analytics were added.

## Changes across the product
- Overview: restored real severity distribution and analyzer completion donut. Numeric labels and textual legends accompany colors. No fabricated behavioral graphs or safety score.
- Search: keyboard-accessible modal, live matching, empty state, Enter opens a finding drawer, Escape closes, explicit All findings action preserves query. Available without a selected scan with a clear empty state.
- Components: unified buttons, icon sizing, badges, notices, tables, modals, drawers, filters, typography and theme tokens. Fixed the old body.dark specificity conflict and mobile header overflow.
- Footer: aligned brand/version, privacy context and functional System health action; follows content and sits at the bottom of short pages.
- Network and Artifacts: search and 40-row pages, navigation and meaningful empty states. Network separates static references from VT report relationships.
- Provider visuals: consistent vector scan/network identifiers with readable provider names; these are UI identifiers, not claimed official brand logos.
- All scan and configuration sections use shared dark surfaces, borders, muted text, states and focus colors. Cloud upload consent stays unchecked.

## VirusTotal scope
The existing hash lookup also saves allowlisted file type and submission metadata when supplied. Network offers an explicit bounded read-only lookup of contacted domains, IPs and URLs: at most three requests, up to 40 items per relationship. Provider next links are never followed. Rate limiting stops remaining requests. Access denied, no data, unavailable, not queried and truncated results are distinct.

References: [VT file objects](https://docs.virustotal.com/reference/files), [contacted domains](https://docs.virustotal.com/reference/file-object-contacted-domains), [API access tiers](https://docs.virustotal.com/reference/public-vs-premium-api). Access can vary by API entitlement and available report. These observations belong to VT’s existing analysis, not an APKTrust runtime capture. No APK is uploaded to VT. Existing scans gain submission metadata after a new hash lookup; network relationships can be loaded separately. AI synthesis currently does not ingest raw relationship observables.

## Verification
117 unit/API tests passed, all external requests mocked. Browser checks covered nine scan tabs and workspace/configuration navigation at 1440, 768 and 390px in both themes. Checked modal search → finding drawer, inventory filtering/pagination, export modal, upload consent default, real chart widths and strict CSP. No real provider test, APK upload or quota consumption was performed. Firebase live execution remains outside this UI audit.

## Apply
Restart the server in the same terminal/environment to enable the new reputation/network endpoint, then hard-refresh the browser. Frontend-only changes are read directly from disk. Do not replace an authenticated server with a process missing its environment configuration.
