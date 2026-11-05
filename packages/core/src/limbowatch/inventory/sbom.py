"""Inventory from an SBOM: CycloneDX JSON or SPDX JSON, by each component's package URL."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from limbowatch.inventory import purl as purls
from limbowatch.models import Dependency, Inventory, Unchecked, UnresolvedDependency


def parse(text: str, source: str) -> Inventory:
    """Dependencies from a CycloneDX (`components`) or SPDX (`packages`) JSON document."""
    try:
        doc = json.loads(text)
    except ValueError as e:
        bad = UnresolvedDependency(reason=Unchecked.LOCKFILE_UNREADABLE, source=source, detail=str(e))
        return Inventory(unresolved=(bad,), sources=(source,), tool="sbom")
    if doc.get("bomFormat") == "CycloneDX":
        entries, tool = list(_cyclonedx(doc.get("components") or [])), "cyclonedx"
    elif "spdxVersion" in doc:
        entries, tool = list(_spdx(doc.get("packages") or [])), "spdx"
    else:
        bad = UnresolvedDependency(
            reason=Unchecked.LOCKFILE_UNREADABLE, source=source, detail="neither CycloneDX nor SPDX JSON"
        )
        return Inventory(unresolved=(bad,), sources=(source,), tool="sbom")
    lines = text.splitlines()
    deps: set[Dependency] = set()
    out: list[UnresolvedDependency] = []
    for name, ver, ref in entries:
        line = next((i for i, ln in enumerate(lines, 1) if ref and ref in ln), 1)
        p = purls.parse(ref) if ref else None
        if p is None:
            out.append(UnresolvedDependency(reason=Unchecked.NO_PURL, source=source, name=name, version=ver, line=line))
            continue
        pkg = purls.package(p)
        version = p.version or ver
        if pkg is None:
            out.append(UnresolvedDependency(reason=Unchecked.UNKNOWN_ECOSYSTEM, source=source, name=name or p.name,
                                            version=version, ecosystem=p.type, line=line))  # fmt: skip
            continue
        eco, pname = pkg
        if not version:
            out.append(UnresolvedDependency(reason=Unchecked.NO_VERSION, source=source, name=pname, ecosystem=eco,
                                            line=line))  # fmt: skip
            continue
        deps.add(Dependency(ecosystem=eco, name=pname, version=version, source=source, line=line, purl=ref))
    ordered = sorted(deps, key=lambda d: (d.line, d.ecosystem, d.name, d.version))
    return Inventory(dependencies=tuple(ordered), unresolved=tuple(out), sources=(source,), tool=tool)


def _cyclonedx(components: list[dict[str, Any]]) -> Iterator[tuple[str, str, str]]:
    for c in components:
        if c.get("type", "library") in ("library", "framework"):
            yield str(c.get("name", "")), str(c.get("version", "")), str(c.get("purl") or "")
        yield from _cyclonedx(c.get("components") or [])


def _spdx(packages: list[dict[str, Any]]) -> Iterator[tuple[str, str, str]]:
    for p in packages:
        ref = next(
            (r.get("referenceLocator", "") for r in p.get("externalRefs") or [] if r.get("referenceType") == "purl"),
            "",
        )
        yield str(p.get("name", "")), str(p.get("versionInfo", "")), str(ref)
