"""The org-wide report (`limbowatch watch`): one line per project, then each affected project's findings.
Pure: the CLI writes the files.

Formats: table, json and markdown. Each project's part is the same as `limbowatch scan` would give
(watch.output), so the JSON nests the per-project document unchanged.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from limbowatch import __version__
from limbowatch.hosts import Listing, Project, Skip
from limbowatch.watch import output
from limbowatch.watch.output import ATTRIBUTION, PARTIAL, Paint, Report

SCHEMA_VERSION = 1


@dataclass
class Entry:
    project: Project
    report: Report | None  # None: couldn't be cloned or inventoried
    commit: str | None = None
    error: str | None = None


@dataclass
class OrgReport:
    entries: list[Entry]
    listings: list[Listing]
    skipped: list[tuple[Project, Skip]]
    stats: dict[str, int] = field(default_factory=dict)
    feed_generated_at: str | None = None
    generated_at: str = ""
    fail_on: str = "low"

    @property
    def failing(self) -> list[Entry]:
        return [e for e in self.entries if e.report is not None and e.report.failed]

    @property
    def errors(self) -> list[str]:
        return [ls.error for ls in self.listings if ls.error]

    @property
    def broken(self) -> list[Entry]:
        return [e for e in self.entries if e.report is None]

    @property
    def exit_code(self) -> int:
        """2 when the run's scope is unknown (a source couldn't be listed) or nothing could be checked; else 1 if
        a project's findings meet --fail-on; else 0."""
        if self.errors or (self.entries and len(self.broken) == len(self.entries)):
            return 2
        return 1 if self.failing else 0


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else many or one + 's'}"


def verdict(r: OrgReport) -> tuple[str, str]:
    """("FAILED" | "PASSED" | "ERROR", one line saying why)."""
    n = len(r.entries)
    if r.errors:
        return "ERROR", f"{_plural(len(r.errors), 'source')} couldn't be listed, so some projects may be missing."
    if r.entries and len(r.broken) == n:
        return "ERROR", f"none of the {_plural(n, 'project')} could be checked."
    failing = r.failing
    if failing:
        names = ", ".join(e.project.name for e in failing[:5]) + (", …" if len(failing) > 5 else "")
        return "FAILED", (f"{_plural(len(failing), 'project')} with findings at or above {r.fail_on} "
                          f"(--fail-on {r.fail_on}): {names}.")  # fmt: skip
    affected = sum(1 for e in r.entries if e.report and e.report.active)
    if affected and r.fail_on == "none":
        return "PASSED", f"{_plural(affected, 'project')} with findings; --fail-on none never fails the run."
    if affected:
        return "PASSED", f"{_plural(affected, 'project')} with findings, none at or above {r.fail_on}."
    return "PASSED", f"No dependency in {_plural(n - len(r.broken), 'project')} is affected by an advisory in limbo."


def _findings_cell(rep: Report) -> str:
    act = rep.active
    if not act:
        return "–"
    c = output.counts(act)
    return f"{len(act):,} ({', '.join(f'{v} {k}' for k, v in c.items() if v)})"


def _changes_cell(rep: Report) -> str:
    if not rep.changes:
        return ""
    c = Counter(ch.kind.value for ch in rep.changes)
    return ", ".join(f"{v} {k}" for k, v in c.items())


def _unchecked(rep: Report) -> int:
    return sum(1 for u in rep.unresolved if u.reason not in PARTIAL)


def _upstream_line(s: dict[str, int]) -> str:
    if "repos" not in s:
        return ""
    line = (f"Source repos: {s['repos']:,} across all projects; {s.get('repos_on_watchlist', 0):,} recently checked "
            f"by the tracker, {s.get('repos_polled', 0):,} polled once for every project")  # fmt: skip
    if s.get("repos_not_polled"):
        line += f", {s['repos_not_polled']:,} not polled (GitHub rate limit)"
    return line + "."


def table(r: OrgReport, verbose: bool = False, paint: Paint | None = None) -> str:
    p = paint or Paint()
    head = (f"limbowatch {__version__} · watch · {_plural(len(r.listings), 'source')}, "
            f"{_plural(len(r.entries), 'project')} checked")  # fmt: skip
    if r.feed_generated_at:
        head += f" · limbo feed of {r.feed_generated_at[:16].replace('T', ' ')} UTC"
    out = [p("2", head), ""]
    rows = [("PROJECT", "DEPENDENCIES", "FINDINGS", "UNCHECKED", "SINCE LAST RUN")]
    for e in r.entries:
        if e.report is None:
            continue
        rep = e.report
        rows.append((e.project.name, f"{rep.stats.get('dependencies', 0):,}", _findings_cell(rep),
                     f"{_unchecked(rep):,}" if _unchecked(rep) else "", _changes_cell(rep)))  # fmt: skip
    if len(rows) > 1:
        w = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
        for i, row in enumerate(rows):
            cells = [row[0].ljust(w[0]), row[1].rjust(w[1]), row[2].ljust(w[2]), row[3].rjust(w[3]), row[4]]
            line = "  ".join(cells).rstrip()
            out.append(p("2", line) if i == 0 else line)
    if r.broken:
        out += ["", p("1", f"Couldn't be checked ({len(r.broken):,}):")]
        out += [f"  {e.project.name}  " + p("2", e.error or "") for e in r.broken]
    if r.skipped:
        out += ["", f"Not checked ({len(r.skipped):,}):"]
        out += [f"  {pr.name}  " + p("2", why.value) for pr, why in r.skipped]
    if r.errors:
        out += ["", p("1;31", f"Sources that couldn't be listed ({len(r.errors):,}):")]
        out += [f"  {err}" for err in r.errors]
    if up := _upstream_line(r.stats):
        out += ["", p("2", up)]
    for e in r.entries:
        if e.report is None or not (e.report.active or e.report.changes or (verbose and e.report.unresolved)):
            continue
        out += ["", "", p("1", f"━━ {e.project.name}") + "  " + p("2", e.project.web_url), ""]
        out.append(output.table(e.report, verbose, p, embedded=True).rstrip("\n"))
    word, why = verdict(r)
    color = {"FAILED": "1;31", "PASSED": "1;32", "ERROR": "1;31"}[word]
    out += ["", p("2", ATTRIBUTION), "", p(color, word) + "  " + why]
    return "\n".join(out) + "\n"


def as_json(r: OrgReport) -> str:
    word, why = verdict(r)
    sev: Counter[str] = Counter()
    for e in r.entries:
        if e.report:
            sev.update(output.counts(e.report.active))
    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "limbowatch", "version": __version__, "mode": "watch"},
        "generated_at": r.generated_at or None,
        "feed_generated_at": r.feed_generated_at,
        "summary": {
            "projects": len(r.entries),
            "checked": len(r.entries) - len(r.broken),
            "couldnt_be_checked": len(r.broken),
            "not_checked": len(r.skipped),
            "with_findings": sum(1 for e in r.entries if e.report and e.report.active),
            "findings": sum(len(e.report.active) for e in r.entries if e.report),
            "by_severity": dict(sev),
        },
        "gate": {"fail_on": r.fail_on, "result": word.lower(), "exit_code": r.exit_code, "message": why},
        "stats": r.stats,
        "sources": [
            {
                "source": ls.source,
                "kind": ls.kind.value,
                "projects": len(ls.projects),
                "not_checked": len(ls.skipped),
                "error": ls.error,
            }
            for ls in r.listings
        ],
        "projects": [
            {
                "project": e.project.name,
                "url": e.project.web_url,
                "kind": e.project.kind.value,
                "commit": e.commit,
                "error": e.error,
                "report": json.loads(output.as_json(e.report)) if e.report else None,
            }
            for e in r.entries
        ],
        "not_checked": [{"project": pr.name, "url": pr.web_url, "reason": why.value} for pr, why in r.skipped],
        "attribution": ATTRIBUTION,
    }
    return json.dumps(doc, indent=1) + "\n"


def markdown(r: OrgReport) -> str:
    word, why = verdict(r)
    md = output._md
    out = [f"## Advisories in limbo across {_plural(len(r.entries), 'project')}", "",
           f"**{word.capitalize()}.** {md(why)}", ""]  # fmt: skip
    out += ["| Project | Dependencies | Findings | Unchecked | Since last run |", "|---|---:|---|---:|---|"]
    for e in r.entries:
        if e.report is None:
            continue
        rep = e.report
        out.append(f"| [{md(e.project.name)}]({e.project.web_url}) | {rep.stats.get('dependencies', 0):,} | "
                   f"{md(_findings_cell(rep))} | {_unchecked(rep) or ''} | {md(_changes_cell(rep))} |")  # fmt: skip
    if r.broken:
        out += ["", f"**Couldn't be checked ({len(r.broken):,}):**", ""]
        out += [f"- [{md(e.project.name)}]({e.project.web_url}): {md(e.error or '')}" for e in r.broken]
    if r.skipped:
        out += ["", f"<details><summary>Not checked ({len(r.skipped):,})</summary>", ""]
        out += [f"- [{md(pr.name)}]({pr.web_url}): {md(why.value)}" for pr, why in r.skipped]
        out += ["", "</details>"]
    if r.errors:
        out += ["", f"**Sources that couldn't be listed ({len(r.errors):,}):**", ""]
        out += [f"- {md(err)}" for err in r.errors]
    if up := _upstream_line(r.stats):
        out += ["", up]
    for e in r.entries:
        if e.report is None or not (e.report.active or e.report.changes):
            continue
        body = output.markdown(e.report).split("\n")[1:]  # without its "## Advisories in limbo" heading
        body = [("#" + ln) if ln.startswith("### ") else ln for ln in body if not ln.startswith(f"_{ATTRIBUTION}")]
        out += ["", f"### [{md(e.project.name)}]({e.project.web_url})", *body]
    out += ["", f"_{ATTRIBUTION}_", ""]
    return "\n".join(out)


Formatter = Callable[[OrgReport], str]
FORMATS: dict[str, Formatter] = {"table": table, "json": as_json, "markdown": markdown}
