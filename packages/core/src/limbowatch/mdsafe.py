"""Markdown-safe text for advisory fields. Pure.

Version ranges, fixed versions and package names are typed by maintainers, and they hold backticks, `|`, `[`, `<`
and `@` (FINDINGS F-164). In an issue, a comment or a job summary that could end a code span, split a table cell,
or render a link or an @mention in a body the user's own bot posted. Only a code span stops a mention on GitHub
(a backslash or `&#64;` doesn't), so every such field goes into one, with a fence longer than any run of backticks
inside it.
"""

from __future__ import annotations

import re

_TICKS = re.compile(r"`+")
GHSA_ID = re.compile(r"GHSA(?:-[0-9a-z]{4}){3}", re.I)  # letters, digits and dashes: nothing to inject
_ADVISORY_URL = re.compile(
    r"https://github\.com/(?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/security/advisories|advisories)/(GHSA[-a-z0-9]+)", re.I
)


def code(value: object, *, table: bool) -> str:
    """`value` as an inline code span: shown as typed, never Markdown or HTML. `table`: inside a table cell, where a
    `|` would end the cell even in a code span unless escaped (GitHub, GitLab and Gitea all read `\\|` there)."""
    s = " ".join(str(value).split())  # no line breaks: they'd end a table row or a list item
    if not s:
        return ""
    if table:
        s = s.replace("|", "\\|")
    fence = "`" * (max((len(m) for m in _TICKS.findall(s)), default=0) + 1)
    pad = " " if s[0] in "` " or s[-1] in "` " else ""  # one space each side is stripped when rendered
    return f"{fence}{pad}{s}{pad}{fence}"


def advisory_link(ghsa_id: str, url: str | None) -> str:
    """`[GHSA-…](url)` when the URL is the ID's own page on GitHub (its repository advisory, or the global page);
    otherwise the ID as code, not linked."""
    m = _ADVISORY_URL.fullmatch(url or "")
    if GHSA_ID.fullmatch(ghsa_id or "") and m and m.group(1).upper() == ghsa_id.upper():
        return f"[{ghsa_id}]({url})"
    return code(ghsa_id, table=True)
