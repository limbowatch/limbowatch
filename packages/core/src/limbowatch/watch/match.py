"""Matching a dependency to advisories in limbo (PHASE0_PLAN §5). Pure: no I/O.

1. **Package:** the advisory names this package (after the feed's name cleaning) and the version
   is in its range. A range that can't be evaluated, or that contradicts the advisory's own fixed
   version (F-051), gives a *possible* finding, never a silent pass. Go `/vN` variants are a
   different module (F-052), so they're possible, not certain.
2. **Repository:** the advisory comes from this package's source repo but names no usable package
   in its ecosystem (an invalid name, F-069/F-077). An advisory that names a *different* valid
   package of the same repo (a monorepo) is not a match.
"""

from __future__ import annotations

import hashlib

from limbowatch.ecosystems import package_name
from limbowatch.models import AdvisoryPackage, Dependency, Finding, MatchKind
from limbowatch.versions import affected, already_fixed, go_relation, norm_name
from limbowatch.watch.candidates import Candidate, Index


def key(dep: Dependency, ghsa_id: str) -> str:
    """Stable per ecosystem, package and advisory, so an upgrade within the range keeps the same issue."""
    raw = f"{dep.ecosystem}:{norm_name(dep.ecosystem, dep.name)}:{ghsa_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _version(dep: Dependency, p: AdvisoryPackage) -> tuple[bool | None, str]:
    """Is dep.version affected per this package entry? (verdict, evidence)."""
    rng = p.vulnerable_version_range
    hit = affected(dep.ecosystem, dep.version, rng)
    if hit is False:
        return False, ""
    if hit is None:
        return None, f"the advisory's range “{rng or ''}” can't be evaluated exactly"
    fixed = already_fixed(dep.ecosystem, dep.version, p.patched_versions)
    if fixed:
        return None, (
            f"{dep.version} is in the range “{rng}”, but at or after the fixed version “{p.patched_versions}”"
        )
    return True, f"{dep.version} is in the range “{rng}”"


def _finding(dep: Dependency, c: Candidate, p: AdvisoryPackage | None, hit: bool | None, kind: MatchKind,
             evidence: str) -> Finding:  # fmt: skip
    a = c.adv
    return Finding(
        key=key(dep, a.ghsa_id),
        dependency=dep,
        ghsa_id=a.ghsa_id,
        url=a.html_url,
        repo=a.repo,
        severity=a.severity,
        cve=c.cve,
        cves=c.cves,
        published_at=a.published_at,
        affected=hit,
        match=kind,
        advisory_package=(p.name or "") if p else "",
        vulnerable_range=p.vulnerable_version_range if p else None,
        fixed=p.patched_versions if p else None,
        evidence=evidence,
        source=c.source,
    )


def match(
    dep: Dependency, index: Index, dep_repo: str | None, go_candidates: list[Candidate] | None = None
) -> list[Finding]:
    """Findings for one dependency: by package name first, then by its source repo."""
    out: dict[str, Finding] = {}
    by_name = list(index.by_name.get((dep.ecosystem, norm_name(dep.ecosystem, dep.name)), []))
    if dep.ecosystem == "go":
        by_name += go_candidates or []
    for c in by_name:
        for p in c.adv.packages:
            if p.ecosystem != dep.ecosystem:
                continue
            n = package_name(p.ecosystem, p.name)
            if n is None or not n.valid:
                continue
            rel = _relation(dep, n.name)
            if rel is None:
                continue
            hit, why = _version(dep, p)
            if rel == "major_version_variant":
                hit, why = None, f"the advisory names {n.name}, a different major version of {dep.name}"
            if hit is False:
                continue
            f = _finding(dep, c, p, hit, MatchKind.PACKAGE, why)
            if f.ghsa_id not in out or out[f.ghsa_id].affected is not True:
                out[f.ghsa_id] = f
    if dep_repo:
        for c in index.by_repo.get(dep_repo, []):
            if c.adv.ghsa_id in out:
                continue
            same_eco = [p for p in c.adv.packages if p.ecosystem == dep.ecosystem]
            usable = [p for p in same_eco if (n := package_name(p.ecosystem, p.name)) is not None and n.valid]
            if usable:
                continue  # it names a real package of this ecosystem; if it were this one, step 1 found it
            entry = same_eco[0] if same_eco else None
            if entry is not None:
                hit, why = _version(dep, entry)
                if hit is False:
                    continue
            else:
                hit, why = None, "the advisory names no package in this ecosystem"
            entered = (entry.name if entry else "") or ""
            why = f"from {dep_repo}, this package's source repo; its package name “{entered}” can't be matched. {why}"
            out[c.adv.ghsa_id] = _finding(dep, c, entry, hit, MatchKind.REPOSITORY, why)
    return sorted(out.values(), key=lambda f: f.ghsa_id)


def _relation(dep: Dependency, advisory_name: str) -> str | None:
    a, d = norm_name(dep.ecosystem, advisory_name), norm_name(dep.ecosystem, dep.name)
    if dep.ecosystem == "go":
        return go_relation(a, d)
    return "same" if a == d else None
