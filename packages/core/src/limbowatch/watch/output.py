"""Scan results in every output format, plus the CI gate. Pure: the CLI writes the files.

Formats (FORMATS): table (terminal), json (schema 1), markdown, html, sarif (2.1.0), codequality (GitLab
Code Quality), junit, csv, cyclonedx (1.6, with vulnerabilities) and github (workflow annotations).
Every format carries the attribution GHSA data requires (CC BY 4.0).
"""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import re
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import quote

from limbowatch import __version__
from limbowatch.csvsafe import cell
from limbowatch.ecosystems import info
from limbowatch.models import Finding, MatchKind, Unchecked, UnresolvedDependency
from limbowatch.versions import applicable_fix, fixed_versions, highest
from limbowatch.watch.state import Change

ATTRIBUTION = (
    "Advisory data: GitHub repository security advisories and the GitHub Advisory Database "
    "(https://github.com/advisories, CC BY 4.0), via the limbo feed (https://limbo.watch, CC BY 4.0)."
)
SEVERITIES = ("critical", "high", "medium", "low")
PARTIAL = (Unchecked.NO_REPO, Unchecked.REPO_NOT_POLLED)
SCHEMA_VERSION = 1  # of the JSON output; bumped only for changes that break readers
WHY = "Published by maintainers on GitHub, not yet in GitHub’s reviewed database or OSV, so scanners that read them don’t report these yet."


@dataclass
class Report:
    """Everything an output needs: the scan, the gate and what changed."""

    findings: list[Finding]
    unresolved: list[UnresolvedDependency]
    stats: dict[str, int]
    tool: str
    feed_generated_at: str | None = None
    changes: list[Change] | None = None
    ignored: set[str] = field(default_factory=set)  # GHSA or CVE IDs accepted by the user
    base: str = ""  # the scanned directory relative to the repo root, for SARIF and Code Quality paths
    fail_on: str = "low"  # critical, high, medium, low or none
    fail_on_unknown: bool = True
    generated_at: str = ""  # when the scan ran, ISO 8601
    target: str = "."  # what was scanned, as given

    def path(self, f: Finding) -> str:
        """The lockfile's path from the repo root: Code Quality and SARIF resolve paths there, not from
        the scanned directory, so a scan of `services/api` must report `services/api/go.mod`."""
        src = f.dependency.source.removeprefix("./")
        return f"{self.base.strip('/')}/{src}" if self.base.strip("/.") else src

    def is_ignored(self, f: Finding) -> bool:
        ids = {f.ghsa_id.upper(), *(c.upper() for c in f.cves)}
        return bool(ids & {i.upper() for i in self.ignored})

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if not self.is_ignored(f)]

    def gated(self, f: Finding) -> bool:
        """This finding fails the build: at or above --fail-on, or unscored with --fail-on-unknown."""
        if self.fail_on == "none" or self.is_ignored(f):
            return False
        s = _sev(f)
        if s in SEVERITIES:
            return SEVERITIES.index(s) <= SEVERITIES.index(self.fail_on)
        return self.fail_on_unknown

    @property
    def failed(self) -> bool:
        return any(self.gated(f) for f in self.active)


def gate(r: Report, fail_on: str = "low", fail_on_unknown: bool = True) -> bool:
    """True if CI should fail at this threshold."""
    return replace(r, fail_on=fail_on, fail_on_unknown=fail_on_unknown).failed


# --- shared ------------------------------------------------------------------------------------------


def _sev(f: Finding) -> str:
    s = (f.severity or "unknown").lower()
    return s if s in SEVERITIES else "unknown"


def _rank(f: Finding) -> tuple[int, str, str]:
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return order.get(_sev(f), 9), f.dependency.name.lower(), f.ghsa_id


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else many or one + 's'}"


def _fix(f: Finding) -> str:
    """The fixed version for this dependency, or what the advisory says."""
    one = applicable_fix(f.dependency.ecosystem, f.dependency.version, f.fixed)
    if one:
        return one
    fv = fixed_versions(f.fixed)
    return ", ".join(fv) if fv else (f.fixed or "none listed")


def _cve(f: Finding) -> str:
    if not f.cves:
        return "–"
    return f.cves[0] + (f" +{len(f.cves) - 1}" if len(f.cves) > 1 else "")


def _label(f: Finding) -> str:
    return _sev(f).upper() + ("" if f.affected is True and f.match is MatchKind.PACKAGE else "?")


def counts(findings: list[Finding]) -> dict[str, int]:
    c = Counter(_sev(f) for f in findings)
    return {s: c.get(s, 0) for s in (*SEVERITIES, "unknown")}


def _breakdown(findings: list[Finding]) -> str:
    return ", ".join(f"{n:,} {s}" for s, n in counts(findings).items() if n)


def summary(r: Report) -> dict[str, Any]:
    act = r.active
    full = [u for u in r.unresolved if u.reason not in PARTIAL]
    return {
        "findings": len(act),
        "advisories": len({f.ghsa_id for f in act}),
        "packages": len({(f.dependency.ecosystem, f.dependency.name) for f in act}),
        "by_severity": counts(act),
        "possibly_affected": sum(1 for f in act if f.affected is not True or f.match is not MatchKind.PACKAGE),
        "accepted": len(r.findings) - len(act),
        "dependencies": r.stats.get("dependencies", 0),
        "unchecked": len(full),
        "checked_by_name_only": len(r.unresolved) - len(full),
    }


def gate_result(r: Report) -> dict[str, Any]:
    return {
        "fail_on": r.fail_on,
        "fail_on_unknown": r.fail_on_unknown,
        "failed": r.failed,
        "failing_findings": sum(1 for f in r.active if r.gated(f)),
        "message": verdict(r)[1],
    }


def verdict(r: Report) -> tuple[bool, str]:
    """(failed, one line saying why), for the end of a CI log."""
    act = r.active
    failing = [f for f in act if r.gated(f)]
    if failing:
        return True, (
            f"{_plural(len(failing), 'finding')} at or above {r.fail_on} (--fail-on {r.fail_on}): {_breakdown(failing)}."
        )
    if not act:
        return False, "No dependency is affected by an advisory in limbo."
    if r.fail_on == "none":
        return False, f"{_plural(len(act), 'finding')}; --fail-on none never fails the build."
    return False, f"{_plural(len(act), 'finding')}, none at or above {r.fail_on} (--fail-on {r.fail_on})."


@dataclass(frozen=True)
class Upgrade:
    """One installed package and the version that clears its advisories in limbo."""

    ecosystem: str
    name: str
    installed: str
    to: str | None  # None: no fixed version can be named for every advisory
    advisories: tuple[str, ...]
    fixed_by_to: int  # how many of them `to` fixes
    where: str
    worst: str


def upgrades(r: Report) -> list[Upgrade]:
    groups: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
    for f in r.active:
        groups[(f.dependency.ecosystem, f.dependency.name, f.dependency.version)].append(f)
    out = []
    for (eco, name, ver), fs in groups.items():
        fix_by_id = {f.ghsa_id: x for f in fs if (x := applicable_fix(eco, ver, f.fixed))}  # one advisory, many files
        known = list(fix_by_id.values())
        to = known[0] if known and len(set(known)) == 1 else highest(eco, known) if known else None
        worst = min((_sev(f) for f in fs), key=lambda s: (*SEVERITIES, "unknown").index(s))
        where = f"{r.path(fs[0])}:{fs[0].dependency.line}"
        out.append(Upgrade(eco, name, ver, to, tuple(sorted({f.ghsa_id for f in fs})), len(known), where, worst))
    order = (*SEVERITIES, "unknown")
    return sorted(out, key=lambda u: (order.index(u.worst), -len(u.advisories), u.name.lower()))


def _upgrade_note(u: Upgrade) -> str:
    n = len(u.advisories)
    if u.to is None:
        return "no fixed version listed; see the advisories"
    if u.fixed_by_to == n:
        return f"clears {_plural(n, 'advisory', 'advisories')}"
    return f"clears {u.fixed_by_to:,} of {n:,} advisories; check the rest"


def _unchecked_line(full: int, part: int) -> str:
    dep = "dependency" if full == 1 else "dependencies"
    was = "was" if part == 1 else "were"
    return f"{full:,} {dep} can't be checked; {part:,} {was} checked by name only."


# --- table (terminal) --------------------------------------------------------------------------------

_SGR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "unknown": "35"}


class Paint:
    """ANSI colour and OSC 8 links, or plain text."""

    def __init__(self, color: bool = False, links: bool = False) -> None:
        self.color, self.links = color, links

    def __call__(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.color and text else text

    def sev(self, s: str, text: str) -> str:
        return self(_SGR.get(s, "0"), text)

    def link(self, url: str, text: str) -> str:
        return f"\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\" if self.links and url else text


ROWS_PER_PACKAGE = 3  # without -v, a package shows its critical, high and failing findings, and at least this many


def _shown_rows(r: Report, fs: list[Finding]) -> int:
    """How many of a package's findings (sorted worst first) the table shows: every one that fails the build or is
    critical or high, at least ROWS_PER_PACKAGE, and all of them when only one more would be left over."""
    must = sum(1 for f in fs if r.gated(f) or _sev(f) in ("critical", "high"))
    n = max(must, ROWS_PER_PACKAGE)
    return len(fs) if len(fs) - n <= 1 else n


def table(r: Report, verbose: bool = False, paint: Paint | None = None) -> str:
    p = paint or Paint()
    act = r.active
    head = f"limbowatch {__version__} · {_plural(r.stats.get('dependencies', 0), 'dependency', 'dependencies')} scanned ({r.tool})"
    if r.feed_generated_at:
        head += f" · limbo feed of {r.feed_generated_at[:16].replace('T', ' ')} UTC"
    out = [p("2", head), ""]
    if not act:
        out.append("No dependency is affected by an advisory in limbo.")
    else:
        n_adv = len({f.ghsa_id for f in act})
        n_pkg = len({(f.dependency.ecosystem, f.dependency.name) for f in act})
        out.append(p("1", f"{_plural(n_adv, 'advisory', 'advisories')} in limbo affect {_plural(n_pkg, 'package')}.")
                   + " Scanners that read OSV or GitHub’s database don’t report these yet.")  # fmt: skip
        cols = ("SEVERITY", "PACKAGE", "INSTALLED", "FIXED IN", "ADVISORY", "CVE")
        rows: list[tuple[Finding, tuple[str, ...]]] = [
            (f, (_label(f), f.dependency.name, f.dependency.version, _fix(f), f.ghsa_id, _cve(f))) for f in act
        ]
        widths = [max(len(c), *(len(cells[i]) for _, cells in rows)) for i, c in enumerate(cols)]
        by_file: dict[str, list[tuple[Finding, tuple[str, ...]]]] = defaultdict(list)
        for f, cells in rows:
            by_file[r.path(f)].append((f, cells))
        for path in sorted(by_file):
            out += [
                "",
                p("1", path),
                "  " + p("2", "  ".join(c.ljust(w) for c, w in zip(cols, widths, strict=True)).rstrip()),
            ]
            # One package at a time, worst first; a package with many advisories is cut to the ones that matter
            groups: dict[tuple[str, str], list[tuple[Finding, tuple[str, ...]]]] = defaultdict(list)
            for f, cells in by_file[path]:
                groups[(f.dependency.name, f.dependency.version)].append((f, cells))
            indent = "  " + " " * (widths[0] + 2)
            for g in sorted(
                groups.values(), key=lambda g: (min(_rank(f) for f, _ in g)[0], g[0][0].dependency.name.lower())
            ):
                g.sort(key=lambda fc: _rank(fc[0]))
                shown = g if verbose else g[: _shown_rows(r, [f for f, _ in g])]
                for f, cells in shown:
                    padded = [c.ljust(w) for c, w in zip(cells, widths, strict=True)]
                    padded[0] = p.sev(_sev(f), padded[0])
                    padded[4] = p.link(f.url, padded[4])
                    out.append(("  " + "  ".join(padded)).rstrip())
                    if verbose:
                        out.append(indent + p("2", f.url))
                        out.append(indent + p("2", f"affected: {f.vulnerable_range or 'not stated'}; {f.cve.value}"))
                    if verbose or f.affected is not True or f.match is MatchKind.REPOSITORY:
                        note = "possibly affected: " if f.affected is not True else ""
                        out.append(indent + p("2", f"{note}{f.evidence}"))
                rest = [f for f, _ in g[len(shown) :]]
                if rest:
                    d = rest[0].dependency
                    out.append(
                        indent
                        + p("2", f"+{len(rest):,} more for {d.name} {d.version} ({_breakdown(rest)}); -v lists them")
                    )
        ups = upgrades(r)
        fix_rows = [(u.name, f"{u.installed} → {u.to or '?'}", _upgrade_note(u), u.where) for u in ups]
        w = [max(len(row[k]) for row in fix_rows) for k in range(3)]
        out += ["", p("1", f"To fix: upgrade {_plural(len(ups), 'package')}")]
        for name, move, note, where in fix_rows:
            out.append(f"  {name.ljust(w[0])}  {move.ljust(w[1])}  {note.ljust(w[2])}  " + p("2", where))
        if any(f.affected is not True or f.match is not MatchKind.PACKAGE for f in act):
            out += [
                "",
                p(
                    "2",
                    "? possibly affected: the advisory’s range couldn’t be evaluated exactly. See the note under it.",
                ),
            ]
        if not verbose:
            out.append(p("2", "Links and evidence for every finding: limbowatch scan -v"))
    accepted = [f for f in r.findings if r.is_ignored(f)]
    if accepted:
        out += ["", f"Accepted (ignored): {', '.join(sorted({f.ghsa_id for f in accepted}))}"]
    if r.changes:
        c = Counter(ch.kind.value for ch in r.changes)
        out += ["", "Since the last scan: " + ", ".join(f"{n} {k}" for k, n in c.items()) + "."]
        if verbose:
            out += [
                f"  {ch.kind.value}: {ch.ghsa_id} {ch.package} {'; '.join(ch.details)}".rstrip() for ch in r.changes
            ]
    full = [u for u in r.unresolved if u.reason not in PARTIAL]
    part = [u for u in r.unresolved if u.reason in PARTIAL]
    if full or part:
        out += ["", _unchecked_line(len(full), len(part))]
        for x in full if not verbose else [*full, *part]:
            what = f"{x.name} {x.version}".strip() or "(whole file)"
            out.append(
                f"  {x.source}:{x.line}  {what}  {p('2', x.reason.value + (': ' + x.detail if x.detail else ''))}"
            )
        if part and not verbose:
            out.append(p("2", "  (-v lists the ones checked by name only)"))
    failed, why = verdict(r)
    out += ["", p("2", ATTRIBUTION), "", (p("1;31", "FAILED") if failed else p("1;32", "PASSED")) + "  " + why]
    return "\n".join(out) + "\n"


# --- json --------------------------------------------------------------------------------------------


def as_json(r: Report) -> str:
    doc = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "limbowatch", "version": __version__, "inventory": r.tool},
        "target": r.target,
        "generated_at": r.generated_at or None,
        "feed_generated_at": r.feed_generated_at,
        "summary": summary(r),
        "gate": gate_result(r),
        "stats": r.stats,
        "findings": [
            f.model_dump(mode="json") | {"path": r.path(f), "ignored": r.is_ignored(f), "fails_build": r.gated(f)}
            for f in sorted(r.findings, key=_rank)
        ],
        "upgrades": [
            {
                "ecosystem": u.ecosystem,
                "package": u.name,
                "installed": u.installed,
                "to": u.to,
                "advisories": list(u.advisories),
                "fixed_by_to": u.fixed_by_to,
                "where": u.where,
            }
            for u in upgrades(r)
        ],
        "unresolved": [u.model_dump(mode="json") for u in r.unresolved],
        "changes": [
            {"key": c.key, "kind": c.kind.value, "ghsa_id": c.ghsa_id, "package": c.package, "details": c.details}
            for c in r.changes or []
        ],
        "attribution": ATTRIBUTION,
    }
    return json.dumps(doc, indent=1) + "\n"


# --- markdown ----------------------------------------------------------------------------------------


def _md(s: str) -> str:
    """Safe inside a Markdown table cell: pipes escaped, no line breaks, no stray HTML."""
    return html.escape(s.replace("\n", " "), quote=False).replace("|", "\\|")


MD_OPEN_ROWS = 20  # above this, the Markdown report folds the full table


def markdown(r: Report) -> str:
    act = r.active
    failed, why = verdict(r)
    out = ["## Advisories in limbo", "", f"**{'Failed' if failed else 'Passed'}.** {_md(why)}", ""]
    if act:
        n_adv = len({f.ghsa_id for f in act})
        out += [
            f"{_plural(n_adv, 'advisory', 'advisories')} in limbo affect this project ({_breakdown(act)}). {WHY}",
            "",
            "### To fix",
            "",
        ]
        out += [
            f"- `{_md(u.name)}` {_md(u.installed)} → **{_md(u.to or '?')}**: {_upgrade_note(u)} (`{_md(u.where)}`)"
            for u in upgrades(r)
        ]

        def rows(fs: list[Finding]) -> list[str]:
            head = [
                "| Severity | Advisory | Package | Installed | Fixed in | CVE | Where |",
                "|---|---|---|---|---|---|---|",
            ]
            return head + [
                f"| {_sev(f)}{'' if f.affected is True and f.match is MatchKind.PACKAGE else ' (possibly)'} | "
                f"[{f.ghsa_id}]({f.url}) | `{_md(f.dependency.ecosystem)}:{_md(f.dependency.name)}` | "
                f"{_md(f.dependency.version)} | {_md(_fix(f))} | {_md(', '.join(f.cves) or '–')} | "
                f"`{_md(r.path(f))}:{f.dependency.line}` |"
                for f in sorted(fs, key=_rank)
            ]

        if len(act) <= MD_OPEN_ROWS:
            out += ["", "### Findings", "", *rows(act)]
        else:  # a long table buries the point: show what fails the build, fold the rest
            failing = [f for f in act if r.gated(f)]
            if failing:
                out += ["", f"### Findings that fail the build ({len(failing):,})", "", *rows(failing)]
            out += ["", f"<details><summary>All {len(act):,} findings</summary>", "", *rows(act), "", "</details>"]
    if r.changes:
        out += ["", "**Since the last scan:** " + "; ".join(
            f"{c.kind.value}: {c.ghsa_id} (`{_md(c.package)}`)" for c in r.changes)]  # fmt: skip
    accepted = sorted({f.ghsa_id for f in r.findings if r.is_ignored(f)})
    if accepted:
        out += ["", f"Accepted (ignored): {', '.join(accepted)}"]
    full = [u for u in r.unresolved if u.reason not in PARTIAL]
    part = len(r.unresolved) - len(full)
    if full or part:
        out += ["", f"<details><summary>{_unchecked_line(len(full), part)}</summary>", ""]
        out += [f"- `{_md(u.source)}:{u.line}` {_md(f'{u.name} {u.version}'.strip() or '(whole file)')}: {_md(u.reason.value)}"
                for u in full]  # fmt: skip
        out += ["", "</details>"]
    out += ["", f"_{ATTRIBUTION}_", ""]
    return "\n".join(out)


# --- html --------------------------------------------------------------------------------------------

_HTML_CSS = """:root{color-scheme:light dark;--bg:#F7F6F2;--fg:#0F1218;--mute:#5F636C;--line:#E1E0D9;--card:#FCFCFB;--amber:#B87400}
@media (prefers-color-scheme:dark){:root{--bg:#0F1218;--fg:#F3F1EA;--mute:#9A998F;--line:#2A303B;--card:#161A22;--amber:#F4A62A}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 20px 48px}h1{margin:0;font-size:28px;letter-spacing:-.01em}
h2{margin:36px 0 10px;font-size:17px;overflow-wrap:anywhere}.meta,.mute{color:var(--mute)}.meta{margin:6px 0 0;font-size:14px}
.verdict{margin:24px 0 0;padding:14px 16px;border-radius:10px;border:1px solid var(--line);background:var(--card);font-weight:600}
.verdict.failed{border-color:#C0392B}.verdict.passed{border-color:#2E8B57}.verdict b{margin-right:8px}
.verdict.failed b{color:#C0392B}.verdict.passed b{color:#2E8B57}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{width:100%;border-collapse:collapse;font-size:14px}th{text-align:left;font-weight:500;color:var(--mute)}
th,td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}tr:last-child td{border-bottom:0}
code,.id{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.sev{display:inline-block;min-width:68px;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;text-transform:capitalize;text-align:center}
.critical{background:#7B1C1C;color:#fff}.high{background:#C0392B;color:#fff}.medium{background:#E0A526;color:#1B1405}
.low{background:#3B6E8F;color:#fff}.unknown{background:#6B6F78;color:#fff}
ul{padding-left:20px}li{margin:4px 0}a{color:inherit}footer{margin-top:40px;font-size:13px;color:var(--mute)}"""


def as_html(r: Report) -> str:
    e = html.escape
    act = r.active
    failed, why = verdict(r)
    when = (r.generated_at or "")[:16].replace("T", " ")
    meta = (f"limbowatch {e(__version__)} · {_plural(r.stats.get('dependencies', 0), 'dependency', 'dependencies')} in "
            f"{e(r.target)} · {e(r.tool)}" + (f" · {e(when)} UTC" if when else ""))  # fmt: skip
    body = [f'<header><h1>Advisories in limbo</h1><p class="meta">{meta}</p></header>',
            f'<p class="verdict {"failed" if failed else "passed"}"><b>{"Failed" if failed else "Passed"}</b>{e(why)}</p>']  # fmt: skip
    if act:
        body.append(f"<p>{e(WHY)}</p>")
        items = "".join(
            f"<li><strong>{e(u.name)}</strong> <code>{e(u.installed)}</code> → <code>{e(u.to or '?')}</code>: "
            f"{e(_upgrade_note(u))} <span class=mute>{e(u.where)}</span></li>"
            for u in upgrades(r)
        )
        body.append(f"<h2>To fix</h2><ul>{items}</ul>")
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for f in act:
            by_file[r.path(f)].append(f)
        for path in sorted(by_file):
            rows = "".join(
                f'<tr><td><span class="sev {_sev(f)}">{e(_sev(f))}</span>'
                f"{'' if f.affected is True and f.match is MatchKind.PACKAGE else ' <span class=mute>possibly</span>'}</td>"
                f"<td><strong>{e(f.dependency.name)}</strong> <span class=mute>{e(f.dependency.ecosystem)}</span></td>"
                f"<td><code>{e(f.dependency.version)}</code></td><td><code>{e(_fix(f))}</code></td>"
                f'<td><a class="id" href="{e(f.url)}">{e(f.ghsa_id)}</a></td><td class="id">{e(", ".join(f.cves) or "–")}</td>'
                f"<td><code>{e(f.vulnerable_range or 'not stated')}</code></td><td>{f.dependency.line}</td></tr>"
                for f in sorted(by_file[path], key=_rank)
            )
            body.append(
                f'<h2><code>{e(path)}</code></h2><div class="wrap"><table><thead><tr><th>Severity</th><th>Package</th>'
                "<th>Installed</th><th>Fixed in</th><th>Advisory</th><th>CVE</th><th>Affected</th><th>Line</th></tr></thead>"
                f"<tbody>{rows}</tbody></table></div>"
            )
    accepted = sorted({f.ghsa_id for f in r.findings if r.is_ignored(f)})
    if accepted:
        body.append(f"<h2>Accepted (ignored)</h2><p class=id>{e(', '.join(accepted))}</p>")
    full = [u for u in r.unresolved if u.reason not in PARTIAL]
    if full or len(r.unresolved) > len(full):
        lis = "".join(
            f"<li><code>{e(u.source)}:{u.line}</code> {e(f'{u.name} {u.version}'.strip() or '(whole file)')}: "
            f"<span class=mute>{e(u.reason.value)}</span></li>"
            for u in full
        )
        body.append(
            f"<h2>Not checked</h2><p>{e(_unchecked_line(len(full), len(r.unresolved) - len(full)))}</p><ul>{lis}</ul>"
        )
    body.append(f"<footer>{e(ATTRIBUTION)}</footer>")
    title = f"Limbowatch: {_plural(len(act), 'finding')}" if act else "Limbowatch: no findings"
    return (
        f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
        f'content="width=device-width, initial-scale=1"><title>{e(title)}</title><style>{_HTML_CSS}</style></head>'
        f"<body><main>{''.join(body)}</main></body></html>\n"
    )


# --- sarif -------------------------------------------------------------------------------------------

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0"}


def sarif(r: Report) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in sorted(r.active, key=_rank):
        sev = _sev(f)
        rules.setdefault(f.ghsa_id, {
            "id": f.ghsa_id,
            "name": "AdvisoryInLimbo",
            "shortDescription": {"text": f"{f.ghsa_id}: published advisory not yet in GitHub's database or OSV"},
            "helpUri": f.url,
            "help": {"text": f"{f.url}\n\n{ATTRIBUTION}", "markdown": f"[{f.ghsa_id}]({f.url})\n\n_{ATTRIBUTION}_"},
            # GitLab files a SARIF finding as dependency scanning when a tag is a CVE, as SAST otherwise; it keeps
            # 10 tags per rule (F-106)
            "properties": {"security-severity": _SARIF_SCORE.get(sev, "5.0"),
                           "tags": ["security", "dependency", "limbo", *(f"cve-{c[4:]}" for c in f.cves[:7])],
                           "precision": "high" if f.affected is True else "medium"},
        })  # fmt: skip
        results.append({
            "ruleId": f.ghsa_id,
            "level": _SARIF_LEVEL.get(sev, "warning"),
            "message": {"text": f"{f.dependency.ecosystem}:{f.dependency.name} {f.dependency.version} is "
                                f"{'affected' if f.affected else 'possibly affected'} by {f.ghsa_id} ({sev}), "
                                f"fixed in {_fix(f)}. {f.evidence}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": r.path(f)},
                                                "region": {"startLine": f.dependency.line}}}],
            "partialFingerprints": {"limbowatch/v1": f.key},
        })  # fmt: skip
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "limbowatch", "version": __version__, "semanticVersion": __version__,
                                "informationUri": "https://limbo.watch", "rules": list(rules.values())}},
            "invocations": [{"executionSuccessful": True}],
            "results": results,
            "properties": {"attribution": ATTRIBUTION},
        }],
    }  # fmt: skip
    return json.dumps(doc, indent=1) + "\n"


# --- GitLab Code Quality -----------------------------------------------------------------------------

_CQ_SEVERITY = {"critical": "blocker", "high": "critical", "medium": "major", "low": "minor"}


def codequality(r: Report) -> str:
    """GitLab Code Quality: a JSON array; each item needs description, check_name, fingerprint,
    severity, location.path and location.lines.begin (FINDINGS F-079)."""
    items = []
    for f in sorted(r.active, key=_rank):
        loc = f"{r.path(f)}:{f.dependency.line}"
        items.append({
            "description": f"{f.ghsa_id} ({_sev(f)}{', possibly' if not f.affected else ''}): "
                           f"{f.dependency.name} {f.dependency.version} is in an advisory not yet in GitHub's "
                           f"database or OSV; fixed in {_fix(f)}. {f.url} · Data: GitHub, CC BY 4.0, via limbo.watch",
            "check_name": "limbowatch/advisory-in-limbo",
            "fingerprint": hashlib.sha256(f"{f.key}|{loc}".encode()).hexdigest()[:32],
            "severity": _CQ_SEVERITY.get(_sev(f), "major"),
            "location": {"path": r.path(f), "lines": {"begin": f.dependency.line}},
        })  # fmt: skip
    return json.dumps(items, indent=1) + "\n"


# --- junit -------------------------------------------------------------------------------------------

_XML_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _x(s: object) -> str:
    """Text for XML: characters XML forbids removed, then escaped (attributes too)."""
    return html.escape(_XML_BAD.sub("", str(s)), quote=True)


def junit(r: Report) -> str:
    """JUnit XML: one test suite per lockfile, one test case per finding. A finding that fails the build is a
    failure; one below --fail-on, or accepted, is skipped. GitLab shows this in merge requests on every tier."""
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in r.findings:
        by_file[r.path(f)].append(f)
    suites, totals = [], Counter[str]()
    for path in sorted(by_file):
        cases, c = [], Counter[str]()
        for f in sorted(by_file[path], key=_rank):
            name = f"{f.ghsa_id} ({_sev(f)}): {f.dependency.name} {f.dependency.version}"
            # GitLab shows classname as the suite and keeps only the first of duplicate names (FINDINGS F-094)
            attrs = (f'name="{_x(name)}" classname="{_x(path)}" '
                     f'file="{_x(path)}" line="{f.dependency.line}" time="0"')  # fmt: skip
            detail = (f"{f.dependency.name} {f.dependency.version} is {'affected' if f.affected else 'possibly affected'} "
                      f"by {f.ghsa_id} ({_sev(f)}). Affected: {f.vulnerable_range or 'not stated'}. Fixed in: {_fix(f)}. "
                      f"CVE: {', '.join(f.cves) or 'none'}. {f.url}\n{f.evidence}\n{ATTRIBUTION}")  # fmt: skip
            if r.is_ignored(f):
                inner, kind = '<skipped message="accepted (ignored)"/>', "skipped"
            elif r.gated(f):
                msg = f"{f.ghsa_id} ({_sev(f)}): upgrade {f.dependency.name} to {_fix(f)}"
                inner, kind = f'<failure type="{_x(_sev(f))}" message="{_x(msg)}">{_x(detail)}</failure>', "failures"
            else:
                inner, kind = f'<skipped message="{_x(f"reported, below --fail-on {r.fail_on}")}"/>', "skipped"
            c[kind] += 1
            c["tests"] += 1
            cases.append(f"<testcase {attrs}>{inner}<system-out>{_x(detail)}</system-out></testcase>")
        totals.update(c)
        suites.append(f'<testsuite name="{_x(path)}" tests="{c["tests"]}" failures="{c["failures"]}" errors="0" '
                      f'skipped="{c["skipped"]}" time="0">{"".join(cases)}</testsuite>')  # fmt: skip
    if not suites:
        totals["tests"] = 1
        suites.append('<testsuite name="limbowatch" tests="1" failures="0" errors="0" skipped="0" time="0">'
                      '<testcase name="No dependency is affected by an advisory in limbo" classname="limbowatch" time="0"/>'
                      "</testsuite>")  # fmt: skip
    stamp = f' timestamp="{_x(r.generated_at)}"' if r.generated_at else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuites name="limbowatch" tests="{totals["tests"]}" failures="{totals["failures"]}" errors="0" '
        f'skipped="{totals["skipped"]}" time="0"{stamp}>\n' + "\n".join(suites) + "\n</testsuites>\n"
    )


# --- csv ---------------------------------------------------------------------------------------------

CSV_COLUMNS = ["severity", "fails_build", "advisory", "cves", "cve_state", "ecosystem", "package", "installed",
               "fixed_in", "affected_range", "possibly", "file", "line", "url", "published", "accepted"]  # fmt: skip


def as_csv(r: Report) -> str:
    """One row per finding (accepted ones too, marked), for spreadsheets. UTF-8 with a byte-order mark."""
    buf = io.StringIO()
    buf.write("﻿")
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for f in sorted(r.findings, key=_rank):
        row = [_sev(f), "yes" if r.gated(f) else "no", f.ghsa_id, " ".join(f.cves), f.cve.value, f.dependency.ecosystem,
               f.dependency.name, f.dependency.version, _fix(f), f.vulnerable_range or "", "no" if f.affected is True else "yes",
               r.path(f), str(f.dependency.line), f.url, f.published_at.date().isoformat() if f.published_at else "",
               "yes" if r.is_ignored(f) else "no"]  # fmt: skip
        w.writerow([cell(v) for v in row])
    return buf.getvalue()


# --- CycloneDX ---------------------------------------------------------------------------------------


def _purl(f: Finding) -> str | None:
    d = f.dependency
    if d.purl:
        return d.purl.split("?", 1)[0]
    t = info(d.ecosystem).purl_type
    if not t:
        return None
    name = d.name.replace(":", "/") if t == "maven" else d.name
    return f"pkg:{t}/{quote(name, safe='/')}@{quote(d.version, safe='')}"


def cyclonedx(r: Report) -> str:
    """CycloneDX 1.6 JSON: the affected components and their advisories in limbo (a vulnerability disclosure
    report), for tools that ingest CycloneDX. Accepted findings are left out."""
    comps: dict[str, dict[str, Any]] = {}
    vulns: dict[str, dict[str, Any]] = {}
    for f in sorted(r.active, key=_rank):
        purl = _purl(f)
        ref = purl or f"limbowatch:{f.dependency.ecosystem}/{f.dependency.name}@{f.dependency.version}"
        comps.setdefault(ref, {"type": "library", "bom-ref": ref, "name": f.dependency.name,
                               "version": f.dependency.version} | ({"purl": purl} if purl else {}))  # fmt: skip
        v = vulns.setdefault(f.ghsa_id, {
            "bom-ref": f"vuln:{f.ghsa_id}",
            "id": f.ghsa_id,
            "source": {"name": "GitHub repository security advisory", "url": f.url},
            "references": [{"id": c, "source": {"name": "CVE", "url": f"https://www.cve.org/CVERecord?id={c}"}}
                           for c in f.cves],
            "ratings": [{"severity": _sev(f), "method": "other",
                         "source": {"name": "Maintainer (GitHub repository security advisory)"}}],
            "advisories": [{"title": "Repository security advisory", "url": f.url}],
            "recommendation": f"Upgrade {f.dependency.name} to {_fix(f)}.",
            "affects": [],
            "properties": [{"name": "limbowatch:status", "value": "in limbo: not yet in GitHub's reviewed database or OSV"},
                           {"name": "limbowatch:cve_state", "value": f.cve.value}],
        } | ({"published": f.published_at.isoformat().replace("+00:00", "Z")} if f.published_at else {}))  # fmt: skip
        if f.vulnerable_range:
            v["properties"].append({"name": "limbowatch:affected_range", "value": f.vulnerable_range})
        v["affects"].append({"ref": ref, "versions": [{"version": f.dependency.version,
                                                       "status": "affected" if f.affected is True else "unknown"}]})  # fmt: skip
    for v in vulns.values():
        v["references"] = v["references"] or [{"id": v["id"], "source": {"name": "GitHub", "url": v["source"]["url"]}}]
    seed = "|".join(sorted(f.key for f in r.active)) + (r.generated_at or "")
    doc = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'https://limbo.watch/scan/' + seed)}",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "limbowatch", "version": __version__,
                                      "externalReferences": [{"type": "website", "url": "https://limbo.watch"}]}]},
            "properties": [{"name": "limbowatch:attribution", "value": ATTRIBUTION}],
        } | ({"timestamp": r.generated_at} if r.generated_at else {}),
        "components": list(comps.values()),
        "vulnerabilities": list(vulns.values()),
    }  # fmt: skip
    return json.dumps(doc, indent=1) + "\n"


# --- GitHub workflow annotations ---------------------------------------------------------------------


def _gh_data(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _gh_prop(s: str) -> str:
    return _gh_data(s).replace(":", "%3A").replace(",", "%2C")


def github(r: Report) -> str:
    """GitHub Actions workflow commands: one annotation per affected package, on its lockfile line, shown in the pull
    request's changed files. Works without code scanning. GitHub keeps at most 10 annotations of each level per step
    (FINDINGS F-096), so findings are grouped by package: error if one fails the build, else warning for medium and
    above, else notice."""
    groups: dict[tuple[str, str, str, str, int], list[Finding]] = defaultdict(list)
    for f in r.active:
        d = f.dependency
        groups[(r.path(f), d.ecosystem, d.name, d.version, d.line)].append(f)
    ups = {(u.ecosystem, u.name, u.installed): u for u in upgrades(r)}
    order = (*SEVERITIES, "unknown")
    lines = []
    for (path, eco, name, version, line), fs in sorted(
        groups.items(), key=lambda kv: (min(_rank(f) for f in kv[1])[0], kv[0])
    ):
        fs.sort(key=_rank)
        worst = min((_sev(f) for f in fs), key=order.index)
        level = "error" if any(r.gated(f) for f in fs) else "warning" if order.index(worst) <= 2 else "notice"
        u = ups.get((eco, name, version))
        fix = (
            f"Upgrade to {u.to}: {_upgrade_note(u)}." if u and u.to else "No fixed version listed; see the advisories."
        )
        title = f"{name} {version}: {_plural(len(fs), 'advisory', 'advisories')} in limbo ({_breakdown(fs)})"
        ids = ", ".join(f.ghsa_id for f in fs[:8]) + (f" and {len(fs) - 8:,} more" if len(fs) > 8 else "")
        msg = (f"{fix} Not yet in GitHub's reviewed database or OSV, so Dependabot doesn't report these. {ids}. "
               f"Worst: {fs[0].url}")  # fmt: skip
        lines.append(f"::{level} file={_gh_prop(path)},line={line},title={_gh_prop(title)}::{_gh_data(msg)}")
    return "".join(f"{x}\n" for x in lines)


Formatter = Callable[[Report], str]
FORMATS: dict[str, Formatter] = {
    "table": table,
    "json": as_json,
    "markdown": markdown,
    "html": as_html,
    "sarif": sarif,
    "codequality": codequality,
    "junit": junit,
    "csv": as_csv,
    "cyclonedx": cyclonedx,
    "github": github,
}
