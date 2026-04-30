# Revelio Brand Guide

Design reference for the Revelio CLI project. The full interactive brand exploration is at [`docs/brand.html`](brand.html).

## Color Palette

| Token | Hex | Role |
|---|---|---|
| Background | `#0E1116` | Page / terminal background |
| Surface 1 | `#161B22` | Cards, panels, terminal body |
| Surface 2 | `#1F2630` | Logo segment (dark) |
| Surface 3 | `#252C38` | Logo segment (light), dividers |
| **Purple** | `#7B5BE6` | Primary accent — logo ring, section headers, links |
| **Green** | `#2EB872` | Success / checkmark — positive outcomes |
| Cream | `#F7F4EC` | Primary text |
| Muted | `#8B8FA8` | Secondary text, labels |
| Border | `#21262d` | Subtle dividers |

## Logo

SVG source: [`assets/logo.svg`](../assets/logo.svg)

- Circle with 6 equal triangular segments alternating `#1F2630` / `#252C38`
- Center circle (r=22) filled `#2EB872` with a white checkmark
- Outer ring stroke `#7B5BE6`, stroke-width=2
- ViewBox: `0 0 200 200`

Meaning: six segments = the six manager ecosystems audited; checkmark = clean bill of health; purple ring = revelio encircles the whole host.

## Typography

- **Primary**: Inter (Google Fonts) — weights 400, 500, 600, 700
- **Monospace**: JetBrains Mono — weights 400, 500
- **Fallback**: `-apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif`

## CLI ANSI Color Mapping

Defined in `lib/core.sh`. Cleared automatically when `NO_COLOR` is set or stdout is not a tty.

| Variable | ANSI | Brand color | Use |
|---|---|---|---|
| `_C_GREEN` | `\033[92m` | `#2EB872` | Success output, `◉` logo mark |
| `_C_PURPLE` | `\033[35m` | `#7B5BE6` | Section headers, separator rule |
| `_C_RED` | `\033[91m` | — | Errors, CRITICAL severity |
| `_C_YELLOW` | `\033[33m` | — | Warnings, HIGH/MEDIUM severity |
| `_C_BOLD` | `\033[1m` | — | Table headers, title |
| `_C_DIM` | `\033[2m` | — | Separator dashes, run path, segment art |
| `_C_CRIT` | `\033[91m` | — | Severity: critical |
| `_C_HIGH` | `\033[31m` | — | Severity: high |
| `_C_MED` | `\033[33m` | — | Severity: medium |
| `_C_LOW` | `\033[36m` | — | Severity: low |

## ASCII Logo Mark (CLI)

Used as a startup banner in `revelio.sh` and as the report header symbol in `lib/security.sh`.

```
  ╲  │  ╱        ← dim  (segment lines)
───╴◉╶──          ← purple ring · green ◉
  ╱  │  ╲        ← dim
```

## Assets

| File | Purpose |
|---|---|
| `assets/logo.svg` | Standalone logo — used in README header |
| `assets/social-preview.svg` | Social card source (1280×640) |
| `assets/social-preview.png` | Social card PNG — upload to GitHub Settings → Social preview (requires public repo) |
| `docs/brand.html` | Full interactive brand exploration (standalone HTML, self-contained) |
| `docs/index.html` | GitHub Pages landing page |

## Landing Page

`docs/index.html` is deployed via `.github/workflows/pages.yml` to GitHub Pages on every push to `main` that touches `docs/`.

**To activate:** GitHub → repo Settings → Pages → Source → **GitHub Actions** → Save.
