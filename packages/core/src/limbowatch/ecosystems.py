"""Ecosystem registry: GHSA ecosystem name -> OSV ecosystem, purl type, review support.

Adding an ecosystem means adding one entry here (and, for version evaluation, a comparator in
versions.py). Everything else looks ecosystems up through `info()`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class EcosystemInfo:
    ghsa: str  # GHSA / GitHub Advisory Database ecosystem name
    osv: str | None  # OSV ecosystem name (None: OSV has no equivalent)
    purl_type: str | None
    reviewable: bool  # GitHub reviews advisories for this ecosystem (FINDINGS F-015, F-023)
    name_rule: str = r".+"  # what a well-formed package name looks like, after cleaning
    name_style: str = ""  # "pep503" / "lower": the canonical spelling scanners compare; "url": a path, not a URL
    depsdev: str | None = None  # deps.dev system, for mapping a package to its source repo


_REGISTRY: dict[str, EcosystemInfo] = {
    e.ghsa: e
    for e in (
        # Name rules follow each registry's documented naming (FINDINGS F-069)
        EcosystemInfo("npm", "npm", "npm", True, r"(?:@[A-Za-z0-9~-][\w.~-]*/)?[A-Za-z0-9~-][\w.~-]*", depsdev="npm"),
        EcosystemInfo("pip", "PyPI", "pypi", True, r"[a-z0-9]+(?:-[a-z0-9]+)*", "pep503", depsdev="pypi"),
        EcosystemInfo(
            "go", "Go", "golang", True, r"stdlib|toolchain|[a-z0-9.-]+\.[a-z]{2,}(?:/[\w.~+-]+)*", "url", depsdev="go"
        ),
        EcosystemInfo("rust", "crates.io", "cargo", True, r"[A-Za-z0-9_-]+", depsdev="cargo"),
        EcosystemInfo("maven", "Maven", "maven", True, r"[\w.-]+:[\w.-]+", depsdev="maven"),
        EcosystemInfo("nuget", "NuGet", "nuget", True, r"[\w.-]+", depsdev="nuget"),
        EcosystemInfo(
            "composer",
            "Packagist",
            "composer",
            True,
            r"[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*",
            "lower",
        ),
        EcosystemInfo("rubygems", "RubyGems", "gem", True, r"[\w.-]+", depsdev="rubygems"),
        EcosystemInfo("erlang", "Hex", "hex", True, r"[a-z][a-z0-9_]*"),
        EcosystemInfo("actions", "GitHub Actions", "githubactions", True, r"[\w.-]+/[\w.-]+(?:/[\w./-]+)?", "url"),
        EcosystemInfo("pub", "Pub", "pub", True, r"[a-z_][a-z0-9_]*"),
        EcosystemInfo("swift", "SwiftURL", "swift", True, r"[a-z0-9.-]+\.[a-z]{2,}(?:/[\w.-]+){2,}", "url"),
    )
}


def info(ghsa_ecosystem: str | None) -> EcosystemInfo:
    """Registry entry; unknown, empty or free-text ecosystems are not reviewable."""
    key = (ghsa_ecosystem or "").strip().lower()
    return _REGISTRY.get(key) or EcosystemInfo(key or "other", None, None, False)


def reviewable(ghsa_ecosystem: str | None) -> bool:
    return info(ghsa_ecosystem).reviewable


_BY_OSV = {e.osv: e for e in _REGISTRY.values() if e.osv}
_BY_PURL = {e.purl_type: e for e in _REGISTRY.values() if e.purl_type}


def by_osv(osv_ecosystem: str) -> EcosystemInfo | None:
    """Registry entry for an OSV ecosystem name such as "PyPI" or "crates.io" (or "Debian:12")."""
    return _BY_OSV.get(osv_ecosystem.split(":", 1)[0])


def by_purl_type(purl_type: str) -> EcosystemInfo | None:
    return _BY_PURL.get(purl_type.lower())


# OSV's ecosystem list (https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt, 2026-10-31).
# OSV-Scanner's offline mode fails the whole scan when an ecosystem it needs has no zip, so the feed
# serves one for each, and the watcher's inventory step uses an empty one for each (F-074, F-078).
OSV_ECOSYSTEMS = (
    "AlmaLinux", "Alpaquita", "Alpine", "Android", "Azure Linux", "BellSoft Hardened Containers", "Bitnami", "CRAN",
    "Chainguard", "CleanStart", "Debian", "Echo", "GHC", "GIT", "GSD", "GitHub Actions", "Go", "Hackage", "Hex",
    "Julia", "Linux", "Mageia", "Maven", "MinimOS", "NuGet", "OSS-Fuzz", "Packagist", "Pub", "PyPI", "Red Hat",
    "Red Hat Lightwell", "Rocky Linux", "Root", "RubyGems", "SUSE", "SwiftURL", "TuxCare", "UVI", "Ubuntu", "VSCode",
    "Wolfi", "crates.io", "npm", "opam", "openEuler", "openSUSE",
)  # fmt: skip
# Offline, OSV-Scanner also needs a database for ecosystems it reads lockfiles of but OSV doesn't list: conan.lock's
# packages are "ConanCenter", and without a zip for it the whole scan fails (FINDINGS F-137).
OFFLINE_ECOSYSTEMS = (*OSV_ECOSYSTEMS, "ConanCenter")


@dataclass(frozen=True)
class PackageName:
    name: str  # the name to publish and match on
    raw: str  # as the maintainer entered it
    valid: bool  # well-formed for its ecosystem; an invalid name can't match any real package

    @property
    def cleaned(self) -> bool:
        return self.name != self.raw


_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def package_name(ghsa_ecosystem: str | None, raw: str | None) -> PackageName | None:
    """A maintainer-entered package name, cleaned only where the result is certain (FINDINGS F-069).

    Scanners compare names exactly (PyPI and Composer after canonicalizing their own side), so a
    stray space, a URL or the wrong case means the advisory silently never matches. Names that still
    don't fit the ecosystem's naming rule are flagged, never guessed at.
    """
    if raw is None or not raw.strip():
        return None
    e = info(ghsa_ecosystem)
    s = _MD_LINK.sub(r"\1", raw).strip().strip("`'\"").strip()
    if e.name_style == "url":
        s = re.sub(r"^(?:git\+)?https?://", "", s).removesuffix("/").removesuffix(".git")
        if e.ghsa == "actions":
            s = s.removeprefix("github.com/")
    elif e.name_style == "pep503":
        if m := re.search(r"#egg=([\w.-]+)", s):
            s = m.group(1)
        s = re.sub(r"[-_.]+", "-", s).lower()
    elif e.name_style == "lower":
        s = s.lower()
    return PackageName(s, raw, re.fullmatch(e.name_rule, s) is not None)
