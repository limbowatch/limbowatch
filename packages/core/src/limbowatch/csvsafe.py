"""Spreadsheet-safe CSV cells. Pure.

Spreadsheets treat a cell starting with = + - @ as a formula. Advisory fields are typed by maintainers, so a
cell starting with = gets a leading ', and so does one starting with + - @ that could call anything (a function,
a link, DDE). npm scopes like `@scope/pkg; other` and numbers like -1 stay as entered.
"""

from __future__ import annotations

import re

_CALLS = re.compile(r"[()|!\"'&\[\]{}$\t\r\n]")  # what a formula needs to call a function, a link or DDE


def cell(v: str) -> str:
    if v[:1] in ("=", "\t", "\r") or (v[:1] in ("+", "-", "@") and _CALLS.search(v)):
        return f"'{v}"
    return v
