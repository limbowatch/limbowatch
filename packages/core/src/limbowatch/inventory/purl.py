"""Package URLs (https://github.com/package-url/purl-spec), just enough to name a package per ecosystem."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import unquote

from limbowatch.ecosystems import by_purl_type


@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str
    name: str
    version: str
    qualifiers: dict[str, str] = field(default_factory=dict)


def parse(purl: str) -> Purl | None:
    """`pkg:npm/%40scope/name@1.0.0?source=LOCAL` -> Purl, or None if it isn't a package URL."""
    if not purl.startswith("pkg:"):
        return None
    rest = purl[4:].lstrip("/").split("#", 1)[0]
    rest, _, query = rest.partition("?")
    quals = {}
    for kv in query.split("&") if query else []:
        k, _, v = kv.partition("=")
        quals[k.lower()] = unquote(v)
    typ, _, path = rest.partition("/")
    if not typ or not path:
        return None
    path, _, version = path.rpartition("@") if "@" in path.rsplit("/", 1)[-1] else (path, "", "")
    parts = [unquote(p) for p in path.split("/") if p]
    if not parts:
        return None
    return Purl(typ.lower(), "/".join(parts[:-1]), parts[-1], unquote(version), quals)


def package(p: Purl) -> tuple[str, str] | None:
    """(GHSA ecosystem key, package name as that ecosystem spells it), or None if the type isn't supported."""
    eco = by_purl_type(p.type)
    if eco is None:
        return None
    ns = p.namespace
    if eco.ghsa == "maven":
        return eco.ghsa, f"{ns}:{p.name}" if ns else p.name
    if eco.ghsa in ("npm", "go", "composer", "actions", "swift"):
        return eco.ghsa, f"{ns}/{p.name}" if ns else p.name
    return eco.ghsa, p.name
