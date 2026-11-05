"""A dependency's source repo: from a Go module path, else from deps.dev (PHASE0_PLAN §5, FINDINGS F-020).

Attested provenance is preferred over unverified metadata. Packages that map to no GitHub repo are
returned with the reason, never dropped.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import quote

from limbowatch.ecosystems import info
from limbowatch.http import HttpClient
from limbowatch.models import Dependency

DEPS_DEV = "https://api.deps.dev/v3"


@dataclass(frozen=True)
class Mapped:
    repo: str | None  # owner/name on GitHub, lower case
    method: str  # how it was found, or why not


def go_repo(module: str) -> str | None:
    parts = module.split("/")
    if parts[0] == "github.com" and len(parts) >= 3:
        return f"{parts[1]}/{parts[2]}".lower()
    return None


async def repo_of(http: HttpClient, dep: Dependency) -> Mapped:
    if dep.ecosystem == "go" and (repo := go_repo(dep.name)):
        return Mapped(repo, "go module path")
    system = info(dep.ecosystem).depsdev
    if system is None:
        return Mapped(None, f"no mapper for {dep.ecosystem}")
    url = f"{DEPS_DEV}/systems/{system}/packages/{quote(dep.name, safe='')}/versions/{quote(dep.version, safe='')}"
    r = await http.get(url)
    if not r.ok or not isinstance(r.body, dict):
        return Mapped(None, f"deps.dev {r.status}")
    rel = [p for p in r.body.get("relatedProjects") or [] if p.get("relationType") == "SOURCE_REPO"]
    rel.sort(key=lambda p: p.get("relationProvenance") == "UNVERIFIED_METADATA")  # attested first
    for p in rel:
        pid = str(p.get("projectKey", {}).get("id", ""))
        if pid.startswith("github.com/"):
            return Mapped(pid.split("/", 1)[1].lower(), f"deps.dev {p.get('relationProvenance', '').lower()}")
    if rel:
        host = str(rel[0].get("projectKey", {}).get("id", "")).split("/")[0]
        return Mapped(None, f"source repo on {host}, not GitHub")
    return Mapped(None, "deps.dev has no source repo")


async def map_all(http: HttpClient, deps: list[Dependency]) -> dict[tuple[str, str, str], Mapped]:
    """(ecosystem, name, version) -> Mapped, one lookup per distinct package version."""
    unique = {(d.ecosystem, d.name, d.version): d for d in deps}
    results = await asyncio.gather(*(repo_of(http, d) for d in unique.values()))
    return dict(zip(unique, results, strict=True))
