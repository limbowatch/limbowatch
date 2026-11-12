"""Pure helpers of the static site: the queue chart and the CSV."""

from __future__ import annotations

import re

from limbowatch.csvsafe import cell
from limbowatch.publish import site


def test_queue_heights_are_exact() -> None:
    # 100 advisories, 45 critical or high, in week 0; 5 in week 1; nothing else
    cols = [(100, 45), (5, 0)] + [(0, 0)] * site.QUEUE_WEEKS
    shapes, _, _ = site.queue_svg(cols, "label")
    groups = re.findall(r'<g style="--c:(\d+)">(.*?)</g>', shapes)
    heights = {int(c): [float(h) for h in re.findall(r'height="([\d.]+)"', g)] for c, g in groups}
    unit, grain = site.QUEUE_UNIT, 10
    # two full squares (80) and a half-height one for the remaining 20, never a whole square
    assert heights[0] == [grain, grain, grain * (100 - 2 * unit) / unit]
    assert heights[1] == [max(2.0, grain * 5 / unit)]
    assert heights[2] == []
    solid = re.findall(r"<rect[^>]*/>", groups[0][1])
    assert sum("fill-opacity" not in r for r in solid) == 1  # round(45 / 40) = 1 solid square


def test_csv_cells_cannot_start_a_formula() -> None:
    assert cell("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert cell("= 1.2.3") == "'= 1.2.3"
    assert cell("@SUM(1+1)*cmd|' /C calc'!A0") == "'@SUM(1+1)*cmd|' /C calc'!A0"
    assert cell("+cmd|x") == "'+cmd|x"
    # nothing to call: left as entered
    assert cell("@scope/pkg") == "@scope/pkg"
    assert cell("@sync-in/server; syncin/server") == "@sync-in/server; syncin/server"
    assert cell("-1") == "-1"
    assert cell("lodash") == "lodash"
    assert cell(">= 1.0, < 2.0") == ">= 1.0, < 2.0"


def test_screenshots_match_their_files() -> None:
    """Every scan-page screenshot exists in dark and light, at the size the page declares (docs/SCREENSHOTS.md)."""
    import struct
    from pathlib import Path

    from limbowatch.publish.site import LIGHT_SCREENS, SCREENS

    shots = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
    for name, (w, h, _alt) in SCREENS.items():
        for file in [name] + ([f"{name}-light"] if name in LIGHT_SCREENS else []):
            head = (shots / f"{file}.png").read_bytes()[:24]
            assert head[:8] == b"\x89PNG\r\n\x1a\n", file
            assert struct.unpack(">II", head[16:24]) == (w, h), file


def test_github_and_gitlab_links_open_in_a_new_tab() -> None:
    from limbowatch.publish.site import new_tab

    html = (
        '<a href="https://github.com/marketplace/actions/limbowatch">a</a>'
        '<a class="x" href="https://gitlab.com/explore/catalog/limbowatch/limbowatch-component">b</a>'
        '<a href="/scan/">c</a><a href="https://limbo.watch/feed/">d</a>'
        '<a href="https://github.com.evil.example/">e</a><a href="https://github.com/x" target="_self">f</a>'
    )
    out = new_tab(html)
    assert out.count('target="_blank" rel="noopener"') == 2
    assert '<a href="/scan/">c</a>' in out and '<a href="https://limbo.watch/feed/">d</a>' in out
    assert '<a href="https://github.com.evil.example/">e</a>' in out  # only github.com and gitlab.com themselves
    assert '<a href="https://github.com/x" target="_self">f</a>' in out  # an explicit target is kept


def test_home_timeline_and_ci_steps() -> None:
    """The home page's timeline lists its events in order, within its 60 days; the CI steps pin the release."""
    days = [d for d, _, _ in site.GAP_EVENTS]
    assert days == sorted(days) and days[0] == 0 and days[-1] <= site.GAP_DAYS
    assert site.REVIEW_MEDIAN in days and site.REVIEW_MEDIAN + site.POLICY_DAYS in days
    gap = site.gap_figure()
    assert gap.count("<li data-day=") == len(days) and f'max="{site.GAP_DAYS}"' in gap
    # segments never run past the end of the track
    for left, width in re.findall(r"left:([\d.]+)%;width:([\d.]+)%", gap + site.clocks()):
        assert float(left) + float(width) <= 100.001
    ci = site.ci_tabs()
    assert f"limbowatch-action@v{site.RELEASE}" in ci and f"limbowatch@{site.COMPONENT}" in ci
    assert site.MARKETPLACE_URL in ci and site.CATALOG_URL in ci


def test_pages_turn_off_cloudflare_email_obfuscation() -> None:
    """CI refs like limbowatch-action@v0.1.0a6 look like email addresses to Cloudflare, which would hide them."""
    html = site.page("t", "d", f"<pre>uses: limbowatch/limbowatch-action@v{site.RELEASE}</pre>")
    body = html.split("<body>", 1)[1]
    assert body.index(site.EMAIL_OFF) < body.index("limbowatch-action@") < body.index(site.EMAIL_ON)


def _luminance(hex_: str) -> float:
    c = [int(hex_[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def test_text_colours_meet_wcag_aa_in_both_themes() -> None:
    for theme in (site.LIGHT, site.DARK):
        assert set(theme) == set(site.LIGHT)  # the same tokens in both
        for fg in site.TEXT_TOKENS:
            for bg in ("bg", "surface", "sunk"):
                a, b = sorted((_luminance(theme[fg]), _luminance(theme[bg])))
                assert (b + 0.05) / (a + 0.05) >= 4.5, (fg, bg, theme[fg], theme[bg])
        for fg, bg in (("pill-ink", "pill-bg"), ("btn-ink", "btn-bg"), ("code-ink", "code-bg")):
            a, b = sorted((_luminance(theme[fg]), _luminance(theme[bg])))
            assert (b + 0.05) / (a + 0.05) >= 4.5, (fg, bg)


def test_css_uses_the_scale() -> None:
    """Font sizes up to 22px and radii come from the tokens, so the scale stays one scale."""
    assert not re.search(r"font-size:(1\d|2[0-2])(\.\d)?px", site.CSS)
    assert not re.search(r"border-radius:(6|8|1[0-8])px", site.CSS)


def test_home_count_is_sized_from_its_column() -> None:
    """The big count scales with its column, so "10,239" (later "100,000") never runs past it on any screen."""
    assert ".now-n{min-width:0;container-type:inline-size}" in site.CSS
    assert re.search(r"\.huge\{[^}]*font-size:min\(196px,24cqi\)", site.CSS)
