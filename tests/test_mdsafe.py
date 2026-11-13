"""Advisory fields in Markdown: shown as typed, never links, mentions or broken tables (FINDINGS F-164)."""

import re

from limbowatch.mdsafe import advisory_link, code
from limbowatch.watch import issues, output, state, trackers
from test_output import finding, report

# Shapes maintainers really type (F-164), and what a hostile one could
REAL = ">=4.1.0, <=4.1.13 || >=5.0.0, <5.1.1"
HOSTILE = "< 2.0` see [the fix](https://example.invalid/x) and @octocat <img src=x> -->`"


def outside_code(md: str) -> str:
    """The Markdown with every code span removed: what's left is what renders as Markdown."""
    return re.sub(r"(`+)(?!`).*?(?<!`)\1(?!`)", "", md)


def test_code_spans() -> None:
    assert code("1.2.3", table=False) == "`1.2.3`"
    assert code(REAL, table=True) == "`>=4.1.0, <=4.1.13 \\|\\| >=5.0.0, <5.1.1`"  # a | would end the table cell
    assert code(REAL, table=False) == f"`{REAL}`"  # outside a table, \\| would show the backslash
    assert code("`1.9.0` at `abc`", table=False) == "`` `1.9.0` at `abc` ``"  # longer fence, padded
    assert code("a ``b`` c", table=False) == "```a ``b`` c```"
    assert code("a\nb\r\nc", table=False) == "`a b c`"  # a line break would end the row or list item
    assert code("", table=True) == ""


def test_advisory_link() -> None:
    gid = "GHSA-2223-f22x-24cq"
    assert advisory_link(gid, f"https://github.com/wintercms/winter/security/advisories/{gid}") == (
        f"[{gid}](https://github.com/wintercms/winter/security/advisories/{gid})"
    )
    assert advisory_link(gid, f"https://github.com/advisories/{gid}") == f"[{gid}](https://github.com/advisories/{gid})"
    for bad in ("https://example.invalid/", f"https://github.com/o/r/security/advisories/{gid})[x](https://e.x",
                "https://github.com/o/r/security/advisories/GHSA-aaaa-bbbb-cccc", None):  # fmt: skip
        assert advisory_link(gid, bad) == f"`{gid}`"
    assert advisory_link("GHSA-x](https://e.x)", "https://github.com/advisories/GHSA-x") == "`GHSA-x](https://e.x)`"


def test_issue_body_shows_advisory_fields_as_typed() -> None:
    for rng, fixed in ((REAL, "5.1.1"), (HOSTILE, "2.0 | [x](https://example.invalid) @octocat -->")):
        upd = {"vulnerable_range": rng, "fixed": fixed, "affected": None, "evidence": HOSTILE}
        f = finding().model_copy(update=upd)
        cur = state.entries([f], "t")
        e = cur[f.key] | {"key": f.key}
        text = issues.body(e, f.model_dump(mode="json"))
        rendered = outside_code(text.split("<!-- limbowatch")[0])
        assert "example.invalid" not in rendered and "@octocat" not in rendered and "<img" not in rendered
        row = next(ln for ln in text.splitlines() if ln.startswith("| Affected versions |"))
        assert row.count(" | ") == 1 and row.replace("\\|", "").count("|") == 3  # one cell, the whole range
        # the marker: one comment, read back exactly
        hidden = text[text.index("<!-- limbowatch") :]
        assert hidden.count("-->") == 1 and hidden.rstrip().endswith("-->")
        assert trackers.read_marker(text) == {"key": f.key, "ghsa_id": f.ghsa_id, "ecosystem": "npm",
                                               "package": "lodash", "range": rng, "fixed": fixed}  # fmt: skip


def test_old_markers_still_read() -> None:
    assert trackers.read_marker('x\n<!-- limbowatch {"key":"k","range":"<1.0"} -->') == {"key": "k", "range": "<1.0"}


def test_markdown_report_shows_advisory_fields_as_typed() -> None:
    f = finding(fixed="[2.0](https://example.invalid) @octocat").model_copy(update={"vulnerable_range": HOSTILE})
    md = output.markdown(report(f))
    rendered = outside_code(md)
    assert "example.invalid" not in rendered and "@octocat" not in rendered
    row = next(ln for ln in md.splitlines() if ln.startswith("| high |"))
    assert row.replace("\\|", "").count("|") == 8  # seven cells
