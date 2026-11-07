"""Pure helpers of the static site: the queue chart and the CSV."""

from __future__ import annotations

import re

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
    assert site._cell("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert site._cell("= 1.2.3") == "'= 1.2.3"
    assert site._cell("@SUM(1+1)*cmd|' /C calc'!A0") == "'@SUM(1+1)*cmd|' /C calc'!A0"
    assert site._cell("+cmd|x") == "'+cmd|x"
    # nothing to call: left as entered
    assert site._cell("@scope/pkg") == "@scope/pkg"
    assert site._cell("@sync-in/server; syncin/server") == "@sync-in/server; syncin/server"
    assert site._cell("-1") == "-1"
    assert site._cell("lodash") == "lodash"
    assert site._cell(">= 1.0, < 2.0") == ">= 1.0, < 2.0"
