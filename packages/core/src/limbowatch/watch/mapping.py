"""A dependency's source repo: from a Go module path or the registry (RubyGems), else from deps.dev
(PHASE0_PLAN §5, FINDINGS F-020, F-085).

Attested provenance is preferred over unverified metadata. Packages that map to no GitHub repo are
returned with the reason, never dropped.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from limbowatch.ecosystems import info
from limbowatch.http import HttpClient
from limbowatch.models import Dependency

DEPS_DEV = "https://api.deps.dev/v3"
RUBYGEMS = "https://rubygems.org/api/v1"


@dataclass(frozen=True)
class Mapped:
    repo: str | None  # owner/name on GitHub, lower case
    method: str  # how it was found, or why not


def go_repo(module: str) -> str | None:
    parts = module.split("/")
    if parts[0] == "github.com" and len(parts) >= 3:
        return f"{parts[1]}/{parts[2]}".lower()
    return None


_GITHUB_URL = re.compile(r"https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$", re.I)


def github_repo(url: str | None) -> str | None:
    m = _GITHUB_URL.match((url or "").strip())
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


async def _rubygems(http: HttpClient, name: str) -> Mapped | None:
    """rubygems.org's own metadata, first in the chain: deps.dev has no source repo for most gems (F-085)."""
    r = await http.get(f"{RUBYGEMS}/gems/{quote(name, safe='')}.json")
    if not r.ok or not isinstance(r.body, dict):
        return None
    urls = [r.body.get(k) for k in ("source_code_uri", "homepage_uri", "bug_tracker_uri")]
    for u in urls:
        if repo := github_repo(u):
            return Mapped(repo, "rubygems.org metadata")
    host = next((urlsplit(u).hostname for u in urls if isinstance(u, str) and "://" in u), None)
    return Mapped(None, f"source repo on {host}, not GitHub") if host else None


async def repo_of(http: HttpClient, dep: Dependency) -> Mapped:
    if dep.ecosystem == "go" and (repo := go_repo(dep.name)):
        return Mapped(repo, "go module path")
    if dep.ecosystem == "rubygems" and (m := await _rubygems(http, dep.name)) is not None:
        return m
    system = info(dep.ecosystem).depsdev
    if system is None:
        return Mapped(None, f"no mapper for {dep.ecosystem}")
    version = dep.version
    if dep.ecosystem == "go" and not version.startswith("v"):
        version = "v" + version  # OSV-Scanner drops Go's "v"; deps.dev needs it (F-085)
    url = f"{DEPS_DEV}/systems/{system}/packages/{quote(dep.name, safe='')}/versions/{quote(version, safe='')}"
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
