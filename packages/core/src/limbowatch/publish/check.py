"""The package checker on limbo.watch/check/: its index and its script.

The checker runs in the visitor's browser. It asks deps.dev for a package's resolved dependency tree and checks
every package in it against the advisories in limbo, by name and version, the way `limbowatch scan` matches a
dependency (watch/match.py). Everything that needs Limbowatch's range parser is decided here, in Python, with the
same functions the watcher uses: each package entry carries the parsed alternatives (`versions.alternatives`), both
readings of an `A .. B` range, and the plain fixed versions. The browser only compares versions, with ports of the
orderings `univers` uses (check.js); tests/test_check.py runs that script under Node against univers and the
watcher's own verdicts.

Ecosystems: the four deps.dev resolves dependency trees for (npm, PyPI, crates.io, Maven; FINDINGS F-118).
"""

from __future__ import annotations

from importlib.resources import files
from typing import Any

from limbowatch.ecosystems import package_name
from limbowatch.models import Status
from limbowatch.publish import ATTRIBUTION, Item
from limbowatch.versions import alternatives, dotdot_readings, fixed_versions, norm_name, per_line_bounds

# GHSA ecosystem key → deps.dev system, for the ecosystems deps.dev resolves dependency trees for
SYSTEMS = {"npm": "npm", "pip": "pypi", "rust": "cargo", "maven": "maven"}

SCRIPT = files("limbowatch.publish").joinpath("check.js").read_text(encoding="utf-8")


def _alts(eco: str, rng: str | None) -> list[list[list[str]]] | None:
    alts = alternatives(eco, rng)
    return None if alts is None else [[[op, v] for op, v in cons] for cons in alts]


def entry(eco: str, p_range: str | None, patched: str | None) -> dict[str, Any]:
    """What the browser needs to decide one advisory package the way watch.match._version does."""
    e: dict[str, Any] = {"a": _alts(eco, p_range), "r": p_range, "f": patched, "x": fixed_versions(patched)}
    if p_range and (readings := dotdot_readings(p_range)):
        e["d"] = [_alts(eco, r) for r in readings]
    if bounds := per_line_bounds(eco, p_range):  # one bound per release line: the gap rule (versions.line_gap)
        e["b"] = [[lb.bound, lb.names_line] for lb in bounds]
    return e


def index(items: list[Item], generated_at: str) -> dict[str, Any]:
    """Advisories in limbo by ecosystem and normalized package name: the data the checker matches against."""
    by_eco: dict[str, dict[str, list[dict[str, Any]]]] = {eco: {} for eco in SYSTEMS}
    count = 0
    for i in sorted(items, key=lambda i: i.adv.ghsa_id):
        if i.assessment.status is not Status.LIMBO:
            continue
        adv, f = i.adv, i.facts
        seen = False
        for p in adv.packages:
            if p.ecosystem not in SYSTEMS:
                continue
            n = package_name(p.ecosystem, p.name)
            if n is None or not n.valid:
                continue  # an unusable name can't match by name; `limbowatch scan` matches those by source repo
            e = entry(p.ecosystem, p.vulnerable_version_range, p.patched_versions)
            e |= {
                "g": adv.ghsa_id,
                "n": n.name,
                "s": adv.severity or "unknown",
                "p": adv.published_at.isoformat().replace("+00:00", "Z") if adv.published_at else None,
                "c": sorted({c for c in [f.cited_cve, *f.uncited_cves] if c}),
            }
            by_eco[p.ecosystem].setdefault(norm_name(p.ecosystem, n.name), []).append(e)
            seen = True
        count += seen
    return {
        "generated_at": generated_at,
        "advisories": count,
        "ecosystems": by_eco,
        "attribution": ATTRIBUTION,
        "license": "CC BY 4.0",
    }
