"""Ecosystem registry: GHSA ecosystem name -> OSV ecosystem, purl type, review support.

Adding an ecosystem means adding one entry here (and, for version evaluation, a comparator in
versions.py). Everything else looks ecosystems up through `info()`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EcosystemInfo:
    ghsa: str  # GHSA / GitHub Advisory Database ecosystem name
    osv: str | None  # OSV ecosystem name (None: OSV has no equivalent)
    purl_type: str | None
    reviewable: bool  # GitHub reviews advisories for this ecosystem (FINDINGS F-015, F-023)


_REGISTRY: dict[str, EcosystemInfo] = {
    e.ghsa: e
    for e in (
        EcosystemInfo("npm", "npm", "npm", True),
        EcosystemInfo("pip", "PyPI", "pypi", True),
        EcosystemInfo("go", "Go", "golang", True),
        EcosystemInfo("rust", "crates.io", "cargo", True),
        EcosystemInfo("maven", "Maven", "maven", True),
        EcosystemInfo("nuget", "NuGet", "nuget", True),
        EcosystemInfo("composer", "Packagist", "composer", True),
        EcosystemInfo("rubygems", "RubyGems", "gem", True),
        EcosystemInfo("erlang", "Hex", "hex", True),
        EcosystemInfo("actions", "GitHub Actions", "githubactions", True),
        EcosystemInfo("pub", "Pub", "pub", True),
        EcosystemInfo("swift", "SwiftURL", "swift", True),
    )
}


def info(ghsa_ecosystem: str | None) -> EcosystemInfo:
    """Registry entry; unknown, empty or free-text ecosystems are not reviewable."""
    key = (ghsa_ecosystem or "").strip().lower()
    return _REGISTRY.get(key) or EcosystemInfo(key or "other", None, None, False)


def reviewable(ghsa_ecosystem: str | None) -> bool:
    return info(ghsa_ecosystem).reviewable
