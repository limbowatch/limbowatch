# limbo.watch design system (Phase 8, step 2)

The site's look, as tokens and components. Everything lives in `packages/core/src/limbowatch/publish/site.py`: the
tokens are Python dicts (`LIGHT`, `DARK`, `SCALE`) written into the stylesheet's `:root`, so one set of values styles
every page. The brand is unchanged: the hourglass mark, an amber accent, and dark ink on warm paper (decision C).

## Colour

One token set per theme, with the same names. The dark set is used when the visitor's system prefers dark (unless they
chose light with the theme button), when they chose dark, and always for the home page's hero.

| Token | Light | Dark | Use |
|---|---|---|---|
| `bg` | #F7F6F2 | #0F1218 | page |
| `surface` | #FCFCFB | #161A22 | cards, tables, inputs |
| `sunk` | #EFEDE6 | #1B2029 | wells, notes, hover |
| `ink` | #0F1218 | #F3F1EA | text, headings |
| `ink2` | #4A4D55 | #C3C2B7 | secondary text |
| `muted` | #646871 | #9A998F | labels, meta |
| `soft` | #555861 | #A9A8A0 | captions |
| `faint` | #646871 | #848994 | placeholders |
| `amber-text` | #8F5A00 | #F4A62A | links on hover, accent text |
| `mark` | #B87400 | #F4A62A | the accent: bars, dots, borders, large numbers (not body text in light) |
| `line`, `line2`, `border` | #E1E0D9, #ECEBE5, #C9C7BD | #2A303B, #232833, #3A404C | rules and borders |
| `pill-bg` / `pill-ink` | #F6E7C8 / #5E3B00 | #3A2A0A / #F7C66B | status pills |
| `code-bg` / `code-ink` | #0F1218 / #F3F1EA | #0A0C10 / #F3F1EA | code blocks |
| `btn-bg` / `btn-ink` / `btn-hover` | #0F1218 / #F7F6F2 / #2A303B | #F3F1EA / #0F1218 / #FFFFFF | primary buttons |

**Contrast.** Every text token (`ink`, `ink2`, `muted`, `soft`, `faint`, `amber-text`) has at least 4.5:1 (WCAG AA)
against `bg`, `surface` and `sunk`, in both themes, and so do the pill, button and code pairs.
`tests/test_site.py::test_text_colours_meet_wcag_aa_in_both_themes` checks it. The pass on 2026-11-12 darkened light
`muted`/`faint` (#6B6F78 → #646871; it was 4.30:1 on `sunk`) and dark `faint` (#7C818C → #848994; 4.46:1 on
`surface`), and moved the brand name's amber from `mark` (3.5:1 in light) to `amber-text`. `mark` stays for graphics
and display-size numbers, where 3:1 applies.

## Type

System fonts (`--sans`, `--mono`), tabular numbers everywhere. One scale for text up to 22px; display sizes (hero,
page titles, big numbers) stay with their component.

| Token | Size | Use |
|---|---|---|
| `fs-xs` | 13px | table headers, small print, mono IDs |
| `fs-s` | 14px | meta, captions, card details |
| `fs-m` | 15px | navigation, controls, dense body |
| `fs-b` | 16px | body |
| `fs-l` | 18px | lede, long-form body, quotes |
| `fs-xl` | 20px | small headings |
| `fs-2xl` | 22px | stat values |

Headings: h2 32px (26px on phones), page titles 44px (34px), the hero `clamp(40px, 5.6vw, 78px)`.
`test_css_uses_the_scale` fails if a size up to 22px is written outside the tokens.

## Shape and space

- Radii: `r-s` 8px (badges, menu items), `r-m` 10px (buttons, inputs, code), `r-l` 14px (cards, panels), `r-pill`.
- Spacing steps: 8, 16, 24, 32, 48, 64, 88px (`sp-1` … `sp-7`); sections are 88px apart (64px on phones), the page
  gutter 24px (16px on phones).
- Touch targets at least 44px high.

## Components

| Component | Class | Where |
|---|---|---|
| Header with Learn menu | `.bar`, `details.learn` | every page; phones get the `.menu` panel |
| Hero result pair | `.pair`, `.res`, `.res.loud` | home |
| Example card | `.ex`, `.exc`, `.sev` | home (live examples) |
| Fix banner | `.fixbar` | advisory pages, scan |
| Timeline (days) | `.gap`, `.lane`, `.track` | home |
| Compliance clocks | `.clocks`, `.clock` | compliance |
| Framework cards | `.fw` | compliance |
| Stats | `.facts3`, `.stats3`, `.sevs` | home, scan, tracker |
| Tabs | `.ci` with `role=tablist` | home (CI), scan (GitHub, GitLab, Gitea and Forgejo, command line) |
| Code block | `pre`, `pre.light` | everywhere |
| Table, collapsing to cards on phones | `.tbl` | tracker |
| Screenshot, dark and light | `figure.shot` | scan, home |
| Note | `.note` | scan, check, feed |

Tabs, the Learn menu and the timeline work without JavaScript: every tab panel shows under its name, the menu is a
`<details>`, and the timeline lists its events.

## Checks

At 390px (phone) and 1440px, light and dark: no horizontal scroll on home, tracker, scan, compliance, an advisory page
and methodology (checked 2026-11-12 with Chrome's device emulation).
