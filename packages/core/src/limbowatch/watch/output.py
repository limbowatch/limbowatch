"""Scan results as table, JSON, Markdown, SARIF 2.1.0 and GitLab Code Quality, plus the CI gate. Pure.

Every format carries the attribution GHSA data requires (CC BY 4.0).
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from limbowatch import __version__
from limbowatch.models import Finding, MatchKind, Unchecked, UnresolvedDependency
from limbowatch.versions import fixed_versions
from limbowatch.watch.state import Change

ATTRIBUTION = (
    "Advisory data: GitHub repository security advisories and the GitHub Advisory Database "
    "(https://github.com/advisories, CC BY 4.0), via the limbo feed (https://limbo.watch, CC BY 4.0)."
)
SEVERITIES = ("critical", "high", "medium", "low")
PARTIAL = (Unchecked.NO_REPO, Unchecked.REPO_NOT_POLLED)


@dataclass
class Report:
    """Everything an output needs: the scan, the gate's inputs and what changed."""

    findings: list[Finding]
    unresolved: list[UnresolvedDependency]
    stats: dict[str, int]
    tool: str
    feed_generated_at: str | None = None
    changes: list[Change] | None = None
    ignored: set[str] = field(default_factory=set)  # GHSA or CVE IDs accepted by the user

    def is_ignored(self, f: Finding) -> bool:
        ids = {f.ghsa_id.upper(), *(c.upper() for c in f.cves)}
        return bool(ids & {i.upper() for i in self.ignored})

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if not self.is_ignored(f)]


def gate(r: Report, fail_on: str = "low", fail_on_unknown: bool = True) -> bool:
    """True if CI should fail: an active finding at or above `fail_on`, or one with no severity."""
    if fail_on == "none":
        return False
    limit = SEVERITIES.index(fail_on)
    for f in r.active:
        sev = (f.severity or "").lower()
        if sev in SEVERITIES:
            if SEVERITIES.index(sev) <= limit:
                return True
        elif fail_on_unknown:
            return True
    return False


def _fix(f: Finding) -> str:
    """The fixed version for this dependency's release line when the advisory lists one per line."""
    fv = fixed_versions(f.fixed)
    if not fv:
        return f.fixed or "no fixed version"
    line = f.dependency.version.lstrip("v").split(".")[:2]
    same = [x for x in fv if x.lstrip("v").split(".")[:2] == line]
    if len(fv) > 1 and len(same) == 1:
        return f"{same[0]} (for {'.'.join(line)}.x)"
    return ", ".join(fv)


def _sev(f: Finding) -> str:
    return (f.severity or "unknown").lower()


def _groups(findings: list[Finding]) -> dict[str, list[Finding]]:
    g: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        g[f.key].append(f)
    order = {s: i for i, s in enumerate(SEVERITIES)}

    def rank(kv: tuple[str, list[Finding]]) -> tuple[int, str, str]:
        f = kv[1][0]
        return order.get(_sev(f), 9), f.ghsa_id, f.dependency.name

    return dict(sorted(g.items(), key=rank))


def table(r: Report, verbose: bool = False) -> str:
    head = f"limbowatch {__version__} · {r.stats.get('dependencies', 0):,} dependencies ({r.tool})"
    if r.feed_generated_at:
        head += f" · limbo feed of {r.feed_generated_at[:16].replace('T', ' ')} UTC"
    out = [head]
    active = [f for f in r.findings if not r.is_ignored(f)]
    groups = _groups(active)
    pkgs = {(f.dependency.ecosystem, f.dependency.name) for f in active}
    out.append("")
    if not groups:
        out.append("No dependency is affected by an advisory in limbo.")
    else:
        n_adv = len({f.ghsa_id for f in active})
        out.append(
            f"{n_adv:,} advisor{'y' if n_adv == 1 else 'ies'} in limbo affect {len(pkgs):,} "
            f"package{'' if len(pkgs) == 1 else 's'}. "
            "Scanners that read OSV or GitHub's database don't report these yet."
        )
    for fs in groups.values():
        f = fs[0]
        label = _sev(f).upper() if f.affected else f"{_sev(f).upper()}?"
        versions = ", ".join(sorted({x.dependency.version for x in fs}))
        locs = ", ".join(sorted({f"{x.dependency.source}:{x.dependency.line}" for x in fs}))
        out += [
            "",
            f"  {label:<9} {f.ghsa_id}  {f.dependency.ecosystem} {f.dependency.name} {versions}",
            f"            {f.cve.value} · affected: {f.vulnerable_range or 'not stated'} · fixed in {_fix(f)}",
            f"            {locs}",
            f"            {f.url}",
        ]
        if verbose or f.affected is not True or f.match is MatchKind.REPOSITORY:
            out.append(f"            {'possibly affected: ' if f.affected is not True else ''}{f.evidence}")
    accepted = [f for f in r.findings if r.is_ignored(f)]
    if accepted:
        out += ["", f"Accepted (ignored): {', '.join(sorted({f.ghsa_id for f in accepted}))}"]
    if r.changes:
        counts: dict[str, int] = defaultdict(int)
        for c in r.changes:
            counts[c.kind.value] += 1
        out += ["", "Since the last scan: " + ", ".join(f"{n} {k}" for k, n in counts.items()) + "."]
        if verbose:
            out += [f"  {c.kind.value}: {c.ghsa_id} {c.package} {'; '.join(c.details)}".rstrip() for c in r.changes]
    full = [u for u in r.unresolved if u.reason not in PARTIAL]
    part = [u for u in r.unresolved if u.reason in PARTIAL]
    if full or part:
        out += ["", f"{len(full):,} dependencies can't be checked; {len(part):,} were checked by name only."]
        for u in full if not verbose else [*full, *part]:
            what = f"{u.name} {u.version}".strip() or "(whole file)"
            out.append(f"  {u.source}:{u.line}  {what}  {u.reason.value}{': ' + u.detail if u.detail else ''}")
        if part and not verbose:
            out.append("  (--verbose lists the ones checked by name only)")
    out += ["", ATTRIBUTION]
    return "\n".join(out) + "\n"


def as_json(r: Report) -> str:
    doc = {
        "tool": {"name": "limbowatch", "version": __version__, "inventory": r.tool},
        "feed_generated_at": r.feed_generated_at,
        "stats": r.stats,
        "findings": [f.model_dump(mode="json") | {"ignored": r.is_ignored(f)} for f in r.findings],
        "unresolved": [u.model_dump(mode="json") for u in r.unresolved],
        "changes": [
            {"key": c.key, "kind": c.kind.value, "ghsa_id": c.ghsa_id, "package": c.package, "details": c.details}
            for c in r.changes or []
        ],
        "attribution": ATTRIBUTION,
    }
    return json.dumps(doc, indent=1) + "\n"


def markdown(r: Report) -> str:
    active = r.active
    out = ["## Advisories in limbo", ""]
    if not active:
        out.append("No dependency is affected by an advisory in limbo.")
    else:
        out += [
            "Published by maintainers on GitHub but not yet in GitHub's reviewed database or OSV, so scanners "
            "that read them don't report these.",
            "",
            "| Severity | Advisory | Package | Version | CVE | Fixed in | Where |",
            "|---|---|---|---|---|---|---|",
        ]
        for fs in _groups(active).values():
            f = fs[0]
            sev = _sev(f) + ("" if f.affected else " (possibly)")
            versions = ", ".join(sorted({x.dependency.version for x in fs}))
            locs = "<br>".join(sorted({f"`{x.dependency.source}:{x.dependency.line}`" for x in fs}))
            out.append(f"| {sev} | [{f.ghsa_id}]({f.url}) | `{f.dependency.ecosystem}:{f.dependency.name}` | "
                       f"{versions} | {f.cve.value} | {_fix(f)} | {locs} |")  # fmt: skip
    if r.changes:
        out += ["", "**Since the last scan:** " + "; ".join(
            f"{c.kind.value}: {c.ghsa_id} (`{c.package}`)" for c in r.changes)]  # fmt: skip
    full = [u for u in r.unresolved if u.reason not in PARTIAL]
    part = len(r.unresolved) - len(full)
    if full or part:
        out += ["", f"{len(full):,} dependencies can't be checked; {part:,} were checked by name only."]
    out += ["", f"_{ATTRIBUTION}_", ""]
    return "\n".join(out)


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0"}


def sarif(r: Report) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in r.active:
        sev = _sev(f)
        rules.setdefault(f.ghsa_id, {
            "id": f.ghsa_id,
            "name": "AdvisoryInLimbo",
            "shortDescription": {"text": f"{f.ghsa_id}: published advisory not yet in GitHub's database or OSV"},
            "helpUri": f.url,
            "help": {"text": f"{f.url}\n\n{ATTRIBUTION}"},
            "properties": {"security-severity": _SARIF_SCORE.get(sev, "5.0"), "tags": ["security", "limbo"]},
        })  # fmt: skip
        results.append({
            "ruleId": f.ghsa_id,
            "level": _SARIF_LEVEL.get(sev, "warning"),
            "message": {"text": f"{f.dependency.ecosystem}:{f.dependency.name} {f.dependency.version} is "
                                f"{'affected' if f.affected else 'possibly affected'} by {f.ghsa_id} ({sev}), "
                                f"fixed in {_fix(f)}. {f.evidence}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.dependency.source},
                                                "region": {"startLine": f.dependency.line}}}],
            "partialFingerprints": {"limbowatch/v1": f.key},
        })  # fmt: skip
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "limbowatch", "version": __version__, "informationUri": "https://limbo.watch",
                                "rules": list(rules.values())}},
            "results": results,
            "properties": {"attribution": ATTRIBUTION},
        }],
    }  # fmt: skip
    return json.dumps(doc, indent=1) + "\n"


_CQ_SEVERITY = {"critical": "blocker", "high": "critical", "medium": "major", "low": "minor"}


def codequality(r: Report) -> str:
    """GitLab Code Quality: a JSON array; each item needs description, check_name, fingerprint,
    severity, location.path and location.lines.begin (FINDINGS F-079)."""
    items = []
    for f in r.active:
        loc = f"{f.dependency.source}:{f.dependency.line}"
        items.append({
            "description": f"{f.ghsa_id} ({_sev(f)}{', possibly' if not f.affected else ''}): "
                           f"{f.dependency.name} {f.dependency.version} is in an advisory not yet in GitHub's "
                           f"database or OSV; fixed in {_fix(f)}. {f.url} · Data: GitHub, CC BY 4.0, via limbo.watch",
            "check_name": "limbowatch/advisory-in-limbo",
            "fingerprint": hashlib.sha256(f"{f.key}|{loc}".encode()).hexdigest()[:32],
            "severity": _CQ_SEVERITY.get(_sev(f), "major"),
            "location": {"path": f.dependency.source.removeprefix("./"), "lines": {"begin": f.dependency.line}},
        })  # fmt: skip
    return json.dumps(items, indent=1) + "\n"


FORMATS = {"table": table, "json": as_json, "markdown": markdown, "sarif": sarif, "codequality": codequality}
