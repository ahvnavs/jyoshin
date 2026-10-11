# Kazeshini Design System Specification

## Aesthetic
Minimal, modular, dark cyber-retro ASCII. Box-drawing panels on a strict character grid.
Pastel neon used **only** to carry semantic meaning. Glow only on hover and critical state.

## Typography
- **Font Stack**: `'JetBrains Mono', 'DejaVu Sans Mono', 'Ubuntu Mono', monospace` (embedded local fallback, 0 external CDN requests).
- **Scale**:
  - `12px` (subtext, badges, timestamps)
  - `14px` (body, tables, tree paths)
  - `16px` (panel subheaders, stats)
  - `20px` (panel headers, verdict lead)
  - `28px` (ASCII logo banner, Chaos Index number)
- **Line Height**: `1.5`
- **Spacing Grid**: `8px` (`8px`, `16px`, `24px`, `32px`)

## Token Palette
- `--bg`: `#0B0C10` (Background canvas)
- `--panel`: `#11131A` (Box-drawing panel background)
- `--panel-border`: `#1E2230` (Character boundary outline)
- `--text`: `#D8DEE9` (Standard foreground text)
- `--dim`: `#767D8E` (Muted labels, metadata, secondary proof; brightened from #6B7280 to satisfy WCAG AA 4.5:1 on #0B0C10)
- `--mint`: `#8FFFC8` (Healthy, low risk, verified observed facts)
- `--cyan`: `#8FE9FF` (Informational, structural relationships, telemetry)
- `--lavender`: `#B9A7FF` (Focus indicator, interactive highlights)
- `--peach`: `#FFB89A` (Warning, medium consequence, moderate waste)
- `--rose`: `#FF9EC7` (Critical severity, urgent exposure, high risk)

## Rules of Engagement
1. **Never Color Alone**: Always pair status colors with glyphs (`[✓]`, `[!]`, `[▲]`, `[●]`) and text badges.
2. **WCAG AA Compliance**: All text contrast ratios exceed 4.5:1 against `--bg` and `--panel`.
3. **Motion**: Respects `@media (prefers-reduced-motion: reduce)` with zero animation transitions.
4. **Keyboard Navigable**: Visible focus states using `--lavender` on all interactive disclosure toggles and tabs.

