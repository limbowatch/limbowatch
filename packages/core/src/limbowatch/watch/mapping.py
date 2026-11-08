"""A dependency's source repo (PHASE0_PLAN §5, FINDINGS F-020, F-085, F-103).

- Go and Swift: the module path or package URL names the repo.
- RubyGems: rubygems.org metadata. Composer: Packagist metadata. Hex, Pub: ecosyste.ms.
- Everything else: deps.dev; for Maven, when deps.dev names no GitHub repo, the POM's `<scm>`, following
  parent POMs.

Attested provenance is preferred over unverified metadata. Packages that map to no GitHub repo are
returned with the reason, never dropped.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

from limbowatch.ecosystems import info
from limbowatch.http import HttpClient
from limbowatch.models import Dependency

DEPS_DEV = "https://api.deps.dev/v3"
RUBYGEMS = "https://rubygems.org/api/v1"
PACKAGIST = "https://repo.packagist.org/p2"
ECOSYSTEMS = "https://packages.ecosyste.ms/api/v1/registries"
MAVEN_CENTRAL = "https://repo1.maven.org/maven2"
ECOSYSTEMS_REGISTRY = {"erlang": "hex.pm", "pub": "pub.dev"}  # registries deps.dev doesn't cover
POM_PARENTS = 4  # how far up the parent chain to look for <scm>


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


def _url_or_host(urls: list[object], how: str) -> Mapped | None:
    for u in urls:
        if isinstance(u, str) and (repo := github_repo(u)):
            return Mapped(repo, how)
    host = next((urlsplit(u).hostname for u in urls if isinstance(u, str) and "://" in u), None)
    return Mapped(None, f"source repo on {host}, not GitHub") if host else None


async def _packagist(http: HttpClient, name: str) -> Mapped | None:
    """Packagist's metadata for the package: the source URL of its newest version."""
    if name.count("/") != 1:
        return None
    r = await http.get(f"{PACKAGIST}/{quote(name.lower(), safe='/')}.json")
    if not r.ok or not isinstance(r.body, dict):
        return None
    versions = (r.body.get("packages") or {}).get(name.lower()) or []
    if not versions or not isinstance(versions[0], dict):
        return None
    v = versions[0]
    return _url_or_host([(v.get("source") or {}).get("url"), v.get("homepage")], "packagist.org metadata")


async def _ecosystems(http: HttpClient, registry: str, name: str) -> Mapped | None:
    """ecosyste.ms's record of the package, for registries deps.dev doesn't cover (Hex, Pub)."""
    r = await http.get(f"{ECOSYSTEMS}/{registry}/packages/{quote(name, safe='')}")
    if not r.ok or not isinstance(r.body, dict):
        return None
    return _url_or_host([r.body.get("repository_url"), r.body.get("homepage")], f"ecosyste.ms ({registry})")


_POM_SCM = re.compile(r"<scm>(.*?)</scm>", re.S)
_POM_PARENT = re.compile(r"<parent>(.*?)</parent>", re.S)
_POM_TAG = {
    t: re.compile(rf"<{t}>\s*([^<\s]+)\s*</{t}>") for t in ("url", "connection", "groupId", "artifactId", "version")
}


def _tag(xml: str, tag: str) -> str | None:
    m = _POM_TAG[tag].search(xml)
    return m.group(1) if m else None


def pom_scm(pom: str) -> tuple[list[str], tuple[str, str, str] | None]:
    """URLs from a POM's <scm> and its <parent> coordinates. Pattern matching, not an XML parser, so a
    hostile POM can't expand entities."""
    urls: list[str] = []
    if m := _POM_SCM.search(pom):
        for t in ("url", "connection"):
            if v := _tag(m.group(1), t):
                urls.append(re.sub(r"^scm:git:", "", v).replace("git@github.com:", "https://github.com/"))
    parent = None
    if p := _POM_PARENT.search(pom):
        g, a, v = (_tag(p.group(1), t) for t in ("groupId", "artifactId", "version"))
        parent = (g, a, v) if g and a and v and "${" not in v else None
    return urls, parent


async def _maven_scm(http: HttpClient, name: str, version: str) -> Mapped | None:
    """The POM's <scm>, following parent POMs up to POM_PARENTS levels (netty-codec-http inherits it, F-103)."""
    if name.count(":") != 1 or not version:
        return None
    group, artifact = name.split(":")
    for _ in range(POM_PARENTS + 1):
        url = f"{MAVEN_CENTRAL}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"
        r = await http.get(url)
        if r.status != 200 or not isinstance(r.body, str):
            return None
        urls, parent = pom_scm(r.body)
        if found := _url_or_host(list(urls), "maven pom <scm>"):
            return found
        if parent is None:
            return None
        group, artifact, version = parent
    return None


async def repo_of(http: HttpClient, dep: Dependency) -> Mapped:
    if dep.ecosystem == "go" and (repo := go_repo(dep.name)):
        return Mapped(repo, "go module path")
    if dep.ecosystem == "swift" and (repo := go_repo(dep.name.removeprefix("https://")) or github_repo(dep.name)):
        return Mapped(repo, "swift package URL")
    if dep.ecosystem == "rubygems" and (m := await _rubygems(http, dep.name)) is not None:
        return m
    if dep.ecosystem == "composer" and (m := await _packagist(http, dep.name)) is not None:
        return m
    if (reg := ECOSYSTEMS_REGISTRY.get(dep.ecosystem)) and (m := await _ecosystems(http, reg, dep.name)) is not None:
        return m
    system = info(dep.ecosystem).depsdev
    if system is None:
        return Mapped(None, f"no mapper for {dep.ecosystem}")
    version = dep.version
    if dep.ecosystem == "go" and not version.startswith("v"):
        version = "v" + version  # OSV-Scanner drops Go's "v"; deps.dev needs it (F-085)
    url = f"{DEPS_DEV}/systems/{system}/packages/{quote(dep.name, safe='')}/versions/{quote(version, safe='')}"
    r = await http.get(url)
    found = _deps_dev(r.body) if r.ok and isinstance(r.body, dict) else Mapped(None, f"deps.dev {r.status}")
    if found.repo is None and dep.ecosystem == "maven" and (pom := await _maven_scm(http, dep.name, dep.version)):
        return pom  # a GitHub repo, or the host it's on instead: either says more than "no source repo"
    return found


def _deps_dev(body: dict[str, Any]) -> Mapped:
    """The source repo deps.dev names for a version: attested provenance first, then unverified metadata."""
    rel = [
        p for p in body.get("relatedProjects") or [] if isinstance(p, dict) and p.get("relationType") == "SOURCE_REPO"
    ]
    rel.sort(key=lambda p: p.get("relationProvenance") == "UNVERIFIED_METADATA")
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
