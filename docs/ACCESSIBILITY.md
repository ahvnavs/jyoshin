# Kazeshini Web UI Accessibility Checklist (WCAG 2.2 AA)

Because headless build environments may lack a desktop web browser or automated Lighthouse CLI runner, Kazeshini provides this manual accessibility verification checklist.

## 1. Keyboard Navigation & Visible Focus
- [x] **Tab Order:** All interactive controls (links, buttons, inputs) receive focus in logical reading order.
- [x] **Skip Link:** A top hidden skip link `<a href="#main-content" class="skip-link">Skip to main content</a>` appears on first Tab focus and skips directly to the main content container.
- [x] **Visible Focus Ring:** `:focus-visible` defines an unmistakable 2px outline with high-contrast lavender (`#B9A7FF`) and 2px offset.
- [x] **Keyboard Trapping & Dismissal:** Modals (Command Palette, Help, Token, Technical Summary, Glossary) close cleanly on `Escape` key without trapping keyboard users.

## 2. ARIA Landmarks & Semantics
- [x] `<aside>` with `aria-label="Main Navigation"` for the rail menu.
- [x] `<main id="main-content" role="main">` for primary content area.
- [x] `<header role="banner">` for top metrics and status bar.
- [x] `<div aria-live="polite">` on live update pulse regions so screen readers announce dynamic changes without jarring speech interruptions.
- [x] ASCII art logo (`風死 · KAZESHINI`) marked with `aria-hidden="true"`, accompanied by `<span class="sr-only">Kazeshini Server Truth Engine</span>`.

## 3. Visual & Cognitive Accessibility
- [x] **Zoom & Reflow:** Supports 200% zoom and displays cleanly down to 320px screen width without two-dimensional scrolling or overlapping text (`@media (max-width: 600px)` reflows columns to single stacked column).
- [x] **Color Independence:** Status badges never rely on color alone; every severity and certainty is paired with a distinct text tag and glyph (`[✓] HEALTHY`, `[▲] CRITICAL`, `[!] HIGH`, `[?] UNKNOWN`).
- [x] **High Contrast:** Supports `@media (forced-colors: active)` with native `ButtonText` and `Highlight` outlines.
- [x] **Reduced Motion:** Supports `@media (prefers-reduced-motion: reduce)` which zeroes animations and transitions.

## 4. Plain Language & Readability
- [x] User-facing summary sentences tested to ensure Flesch-Kincaid Grade Level <= 8.0.
- [x] No raw hex addresses, unformatted JSON, or unexplained technical jargon at the Summary level.
- [x] Interactive `<dfn data-glossary="...">` elements allow non-technical operators to inspect definitions without navigating away.

