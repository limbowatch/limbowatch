"""The popular projects the home page counts: their dependencies, matched against the day's feed (FINDINGS F-203).

Pure: `scripts/showcase.py` lists each project's dependencies (a daily workflow); here they go through the watcher's
own matching (`watch.match`) against the feed records the site publishes, so the numbers agree with that feed and with
what `limbowatch scan` reports by package name. Only certain findings with a fixed version count.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from typing import Any

from limbowatch.models import Dependency
from limbowatch.versions import applicable_fix, highest, no_fix
from limbowatch.watch.candidates import Candidate, Index, from_feed_record
from limbowatch.watch.match import match

SERIOUS = ("critical", "high")
ORDER = ("critical", "high", "medium", "low", "unknown")


@dataclass(frozen=True)
class Project:
    repo: str  # owner/name on GitHub
    commit: str | None
    dependencies: int
    ids: frozenset[str]
    serious: frozenset[str]
    error: str | None = None


@dataclass(frozen=True)
class Package:
    """One package, at the affected versions the projects pin."""

    ecosystem: str  # GHSA key: npm, pip, go, ...
    name: str
    versions: tuple[str, ...]  # as pinned, in no particular order (versions aren't compared as strings)
    projects: tuple[str, ...]
    ids: frozenset[str]
    serious: frozenset[str]
    worst: str  # severity
    worst_id: str  # the advisory to link: the worst, then the longest public
    fix: str | None  # the version that clears every one of them at every pinned version, if one can be named
    oldest: datetime | None  # when the longest-public of them was published


@dataclass(frozen=True)
class Showcase:
    scanned_at: str
    tool: str
    projects: tuple[Project, ...]
    packages: tuple[Package, ...]  # those with a critical or high advisory first, then the most widely pinned

    @property
    def ids(self) -> frozenset[str]:
        return frozenset().union(*(p.ids for p in self.projects))

    @property
    def serious(self) -> frozenset[str]:
        return frozenset().union(*(p.serious for p in self.projects))

    @property
    def read(self) -> tuple[Project, ...]:
        return tuple(p for p in self.projects if p.error is None)

    @property
    def affected(self) -> tuple[Project, ...]:
        return tuple(p for p in self.projects if p.ids)


def _go_key(path: str) -> str:
    return "/".join(path.split("/")[:3])


def _age(ghsa: str, dated: Mapping[str, datetime]) -> tuple[bool, float, str]:
    """Sort key: the longest public first, undated last."""
    return (ghsa not in dated, dated[ghsa].timestamp() if ghsa in dated else 0.0, ghsa)


def counts(records: Iterable[Mapping[str, Any]], data: Mapping[str, Any]) -> Showcase:
    index = Index()
    for r in records:
        index.add(from_feed_record(dict(r)))
    # A Go dependency can match an advisory on a package inside its module or another major version; those share the
    # host/owner/repo prefix, so only that bucket is tried (scan.py tries every Go advisory, for one project).
    go: dict[str, list[Candidate]] = defaultdict(list)
    for cs in index.by_repo.values():
        for c in cs:
            keys = {_go_key(p.module or p.name or "") for p in c.adv.packages if p.ecosystem == "go"}
            for k in keys - {""}:
                go[k].append(c)
    projects: list[Project] = []
    pkg: dict[tuple[str, str], dict[str, Any]] = {}
    for proj in data.get("projects") or []:
        repo = str(proj["repo"])
        if proj.get("error"):
            projects.append(Project(repo, None, 0, frozenset(), frozenset(), str(proj["error"])))
            continue
        ids: dict[str, str] = {}
        for eco, name, version, source in proj.get("dependencies") or []:
            dep = Dependency(ecosystem=eco, name=name, version=version, source=source)
            for f in match(dep, index, None, go.get(_go_key(name), []) if eco == "go" else None):
                if f.affected is not True or no_fix(f.fixed):
                    continue
                level = (f.severity or "unknown").lower()
                ids[f.ghsa_id] = level
                p = pkg.setdefault((eco, name), {"versions": {}, "projects": set(), "sev": {}, "fixes": {}, "pub": {}})
                p["versions"][version] = None
                p["projects"].add(repo)
                p["sev"][f.ghsa_id] = level
                p["fixes"][(version, f.ghsa_id)] = applicable_fix(eco, version, f.fixed)
                p["pub"][f.ghsa_id] = f.published_at
        projects.append(
            Project(
                repo,
                proj.get("commit"),
                len(proj.get("dependencies") or []),
                frozenset(ids),
                frozenset(g for g, s in ids.items() if s in SERIOUS),
            )
        )
    packages = []
    for (eco, name), p in pkg.items():
        sev: dict[str, str] = p["sev"]
        worst = min(sev.values(), key=lambda s: ORDER.index(s) if s in ORDER else len(ORDER))
        dated = {g: d for g, d in p["pub"].items() if d is not None}
        worst_id = min((g for g, s in sev.items() if s == worst), key=partial(_age, dated=dated))
        fixes = list(p["fixes"].values())
        known = [x for x in fixes if x]
        fix = None if len(known) < len(fixes) else known[0] if len(set(known)) == 1 else highest(eco, known)
        packages.append(
            Package(
                ecosystem=eco,
                name=name,
                versions=tuple(p["versions"]),
                projects=tuple(sorted(p["projects"])),
                ids=frozenset(sev),
                serious=frozenset(g for g, s in sev.items() if s in SERIOUS),
                worst=worst,
                worst_id=worst_id,
                fix=fix,
                oldest=min(dated.values()) if dated else None,
            )
        )
    packages.sort(key=lambda k: (not k.serious, -len(k.projects), -len(k.serious), -len(k.ids), k.name.lower()))
    return Showcase(str(data.get("scanned_at") or ""), str(data.get("tool") or ""), tuple(projects), tuple(packages))
