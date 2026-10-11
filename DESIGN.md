---
name: AEGIS
description: Evidence before trust, across Android and repository investigations.
colors:
  accent: "#315ec0"
  accent-hover: "#244ba2"
  midnight: "#172f59"
  nav-hover: "#234472"
  nav-selected: "#2b4879"
  ink-ground: "#091326"
  ice-ground: "#f5f7fb"
  surface: "#fff"
  text: "#182a43"
  muted: "#53647c"
  border: "#dce4ef"
  pale: "#eaf0ff"
  ice-action: "#d9e7ff"
  presentation-text: "#f1f5fc"
  presentation-muted: "#b8c7df"
  presentation-line: "#263951"
  signal: "#9bbfff"
  surface-subtle: "#f0f4f9"
  hover: "#eaf0f8"
  chart-track: "#e5ebf3"
  chart-info: "#758ca9"
  danger-text: "#ac342f"
  danger-bg: "#fff0ef"
  warning-text: "#805a13"
  warning-bg: "#fff5df"
  success-text: "#216647"
  success-bg: "#edf7f2"
typography:
  display:
    fontFamily: "Michroma, system-ui, sans-serif"
    fontSize: "clamp(64px, 12.5vw, 164px)"
    lineHeight: 1.2
    letterSpacing: "0.055em"
  headline:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "clamp(28px, 3vw, 40px)"
    fontWeight: 550
    lineHeight: 1.22
    letterSpacing: "-0.03em"
  workspace-title:
    fontSize: "24px"
    fontWeight: 650
    letterSpacing: "-0.025em"
  evidence-title:
    fontSize: "14px"
    fontWeight: 650
  body:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "14px"
    lineHeight: 1.5
  presentation-body:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "16px"
    lineHeight: 1.7
  label:
    fontSize: "12px"
  code:
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace"
    fontSize: "12px"
    lineHeight: 1.8
rounded:
  tag: "4px"
  control: "6px"
  entry: "8px"
  panel: "10px"
  dialog: "14px"
spacing:
  compact: "8px"
  control: "12px"
  group: "16px"
  panel: "20px"
  reading: "24px"
  section-gutter: "48px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface}"
    rounded: "{rounded.control}"
    padding: "8px 12px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "8px 12px"
  workspace-entry:
    backgroundColor: "{colors.ice-action}"
    rounded: "{rounded.entry}"
    padding: "18px 22px"
  navigation-selected:
    backgroundColor: "{colors.nav-selected}"
    textColor: "{colors.surface}"
    rounded: "{rounded.control}"
    padding: "12px"
  evidence-panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
  tag:
    backgroundColor: "{colors.pale}"
    rounded: "{rounded.tag}"
    padding: "4px 7px"
  input:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.control}"
    padding: "11px 12px"
---

# Design System: AEGIS

## Overview

**Creative North Star: "Research index"**

AEGIS carries the approved Research index blue world into one analysis hub and two operating workspaces. Midnight navigation anchors white evidence surfaces; the presentation surface deepens the same family into an ink ground with pale signal geometry. The user-pinned BeatWave reference informs the oversized identity and brief introduction, while the built interface retains restrained evidence rows and explicit investigation choices.

Michroma gives the project name a distinct engineered silhouette. Reading and operating text use platform UI stacks, and source evidence uses monospace. Authored shield and path geometry connects the identity to the evidence workflow without decorative raster imagery.

**Key Characteristics:**
- Midnight navigation and blue actions across both workspaces.
- Spacious presentation typography paired with compact evidence rows.
- Flat surfaces separated by borders and tonal selection.
- Outline SVG geometry and legible source excerpts.

## Colors

The palette connects a dark presentation surface to light operational reading surfaces through a shared blue accent.

### Primary
- **Investigation Blue** (`accent`): primary workspace actions, selected tabs, links and analysis symbols.
- **Ice Action** (`ice-action`): the main presentation entry and new-scan action against dark navigation.
- **Signal Blue** (`signal`): shield outlines, focus on the dark presentation surface and connective geometry.

### Neutral
- **Midnight** (`midnight`): both fixed workspace navigation rails and the secondary presentation entry.
- **Ink Ground** (`ink-ground`): presentation and introduction ground.
- **Ice Ground** (`ice-ground`): workspace canvas around white evidence surfaces.
- **Surface** (`surface`): evidence, forms and operational headers.
- **Reading Ink / Muted Ink** (`text`, `muted`): primary text and metadata on light surfaces.
- **Presentation Text / Muted Text** (`presentation-text`, `presentation-muted`): identity and supporting reading on the ink ground.
- **Border / Presentation Line** (`border`, `presentation-line`): reading boundaries in their respective light and dark contexts.

Severity colors are semantic rather than extra brand accents. The documented danger, warning and success pairs come from the Android semantic variables; repository badges retain their own corresponding severity implementation.

**The Shared Blue Rule.** Navigation, primary actions and selection belong to the same blue family on both operating surfaces.

**The Evidence State Rule.** Risk, confidence and coverage remain separate text-backed states; color supplements their labels.

## Typography

**Display Font:** Michroma, locally served from the shared font asset.
**Body Font:** Inter-first platform UI stack in Android; platform UI stack in the repository and presentation.
**Label/Mono Font:** UI monospace, with SFMono-Regular and Consolas in Android.

The display face is confined to project identity. Workspaces use compact, plainly readable headings and labels; source paths and excerpts carry a distinct monospace voice. No single modular type ratio exists across the three surfaces.

### Hierarchy
- **Display:** the fluid project wordmark; the introduction uses a separate observed clamp from 64px to 220px (16vw on small mobile screens).
- **Headline:** the presentation statement uses the frontmatter clamp; section titles use 38px, reducing to 29–30px on narrow screens.
- **Workspace title:** repository artifact heading at 24px; Android global headings use 25px and the upload heading uses 27px.
- **Evidence title:** compact 14px finding titles, with detail headings around 19–20px.
- **Body:** 13–14px operational reading, with 14–16px presentation prose and a 67ch capability-reading limit.
- **Label:** 12px metadata is the recurring operational annotation scale; source code uses the documented code role.

**The Identity Type Rule.** Use Michroma for AEGIS identity; use the reading stacks for controls, findings and explanatory text.

## Layout

The presentation uses a centered maximum width of 1320px with 48px desktop gutters. Sections use 88px vertical padding, a two-column capability ledger and border-separated rows. At 800px, gutters reduce to 24px and major content grids stack; at 520px, the two entry actions stack vertically. These are presentation rules, not a required composition for every future surface.

Android has a 224px fixed navigation rail, a 1600px content maximum and 34px desktop content gutters. Repository navigation is 232px at full width and contracts through tablet widths; the evidence workbench uses file, finding and detail columns. Below 1200px its file tree is hidden in the finding view; at 650px navigation becomes an off-canvas drawer and findings stack above detail. Android exposes its mobile menu at 800px and adjusts its drawer beneath the sticky top bar at 700px.

The repeated working rhythm is 8–24px within controls and panels, with larger gaps reserved for presentation sections. Preserve source scrolling for long code rather than widening the page.

## Elevation & Depth

Resting content is mostly flat. Thin borders, selected-row tones and contrasting navigation create hierarchy. The presentation evidence example has tonal source and finding regions; Android panels use rounded bounded surfaces, while the repository separates contiguous columns with lines.

### Shadow Vocabulary
- **Repository dialog:** `0 18px 65px #14284835` separates an overlay from the evidence workspace.
- **Android dialog:** `0 20px 90px #14231030` is the existing diffuse overlay shadow.
- **Mobile repository drawer:** `20px 0 60px #11284850` distinguishes navigation from the covered content.

**The Flat Evidence Rule.** Evidence stays on flat reading surfaces; diffuse elevation belongs to overlays and temporary navigation.

## Shapes

Controls and navigation selections use gently rounded corners; tags are tighter, panels and presentation examples are broader. Thin one-pixel borders define boundaries. The rounded scale records observed recurring values, not a requirement that every component use one radius: Android dialogs are 12px while repository dialogs are 14px.

Shield silhouettes, branch paths, source-code brackets and directional arrows are outlined SVG. Diagram nodes and small status dots use circles; these devices are native to this technical world.

## Components

### Buttons

Compact and explicit. Operational primary actions use blue and white; secondary buttons use white with a border. Android uses the documented compact padding and 36px minimum height; repository buttons use 10px 14px and a 37px minimum. Hover deepens blue or lightly tones secondary surfaces. Keyboard focus uses a visible blue outline; disabled controls reduce opacity and change the cursor.

### Chips

Small labels identify providers, samples and states. Neutral chips use pale blue with compact padding; severity chips preserve semantic background/text pairs. Chips are descriptive unless a component explicitly implements a filter state.

### Cards / Containers

Android panels group evidence with a thin border and 10px corners, generally 18–24px internal padding. Repository evidence columns stay rectangular and contiguous. The presentation example uses a 10px bounded container and distinct source region. Apply the Flat Evidence Rule rather than adding a shadow to every group.

### Inputs / Fields

White fields use thin borders, 6px corners and the documented input padding in the repository. Android uses 9px 11px in its base fields. Visible focus outlines, clear labels, resizing textareas and disabled states remain functional treatments, not decoration.

### Navigation

Midnight rails contain the module identity (APKTrust or RepoSentinel) and its security subtitle, a pale new-scan action, an Analysis hub return link and workspace-specific destinations. Selected destinations use the documented blue selected tone. Both rails scroll when needed and become drawers on mobile. RepoSentinel has no recent-scan block; its desktop rail is 264px, tablet rail 210px, and module wordmark is 22px (18px on tablet). Module marks are original single-color path SVGs: APKTrust A/verification and RepoSentinel source-bracket/R. Navigation grouping labels are navigation structure, not above-heading promotional kickers.

### Workspace Entry

Presentation entry links are substantial 8px-radius actions with an outlined input icon, title, input-type annotation and authored SVG direction arrow. The first uses ice action and the second midnight with an outlined boundary. Hover lifts by 3px; narrow screens stack them.

### Interface Introduction

The full-viewport introduction centers the project identity and acronym, with a large percentage at bottom right and a thin full-width track near the bottom. Every root visit or reload plays a 5.8-second visual progress sequence, a 200ms hold and an 800ms fade/slide exit (about 6.8 seconds total). Skip is always available; reduced motion disables reveal and exit animation. Progress describes the welcome sequence, never analysis or interface readiness. Entry links name APKTrust (Android Security) and RepoSentinel (Repository Security).

## Do's and Don'ts

### Do:
- **Do** keep workspace actions and navigation in the shared blue family.
- **Do** pair semantic color with risk, confidence and coverage labels.
- **Do** reserve the display face for AEGIS identity.
- **Do** preserve flat evidence surfaces, source excerpts and responsive stacking.
- **Do** use SVG geometry for the shield, diagrams and direction icons.

### Don't:
- **Don't** present interface preparation progress as analysis completion.
- **Don't** turn an absent detection or incomplete coverage into a visual safety verdict.
- **Don't** inherit legacy olive theme remnants as the AEGIS brand palette.

Not canonized or repaired: Android scanHeader still emits the above-heading “Package investigation” eyebrow, and VT disclosures still use plus/minus glyphs; these craft defects are not tokens for future surfaces. Legacy olive and dark CSS residue is overridden or unreachable under the shipped single shared palette, so it is not an alternate AEGIS theme. Documentation owns only this record; source correction belongs to the implementation review.

Evidence: shared/theme.css; landing/index.html, style.css and app.js; web/index.html, style.css and app.js (served at /android/); repository/index.html and repository/web/src/main.tsx and styles.css. PRODUCT.md and docs/landing-surface.md establish the approved lineage. Desktop/mobile landing, intro and unified workspace captures were sampled; the final Android capture confirms the upload kicker was removed and the shared subtle/chart variables use blue values.
