"""Re-reading lockfiles for what OSV-Scanner's inventory gets wrong without saying so (FINDINGS F-078).

Pure functions over file text: each returns what one kind of file says about how a package was
installed, so the inventory can report a dependency as unchecked instead of matching a wrong version.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from typing import Any

PINNED, RANGE, VCS, PATH = "pinned", "range", "vcs", "path"


@dataclass(frozen=True)
class Requirement:
    name: str  # PEP 503 normalized; "" when a VCS or path line doesn't say
    kind: str  # PINNED, RANGE, VCS or PATH
    spec: str  # the line as written, for the report
    line: int


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirements(text: str) -> list[Requirement]:
    """Each requirement line of a pip requirements file, classified by how exactly it pins a version."""
    out: list[Requirement] = []
    joined: list[tuple[int, str]] = []
    buf, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start = n
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        joined.append((start, buf + raw))
        buf = ""
    if buf:
        joined.append((start, buf))
    for n, raw in joined:
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()  # a comment, but not "#egg=" inside a URL
        if not line:
            continue
        editable = re.match(r"(?:-e|--editable)[\s=]+(.+)", line)
        if editable:
            target = editable.group(1).strip()
            kind = VCS if "://" in target or target.startswith("git+") else PATH
            out.append(Requirement(_egg(target), kind, line, n))
            continue
        if line.startswith("-"):
            continue  # -r, -c, --index-url, --hash and other options
        if re.match(r"(?:[a-z][a-z0-9+.-]*\+)?[a-z]+://", line, re.I) or " @ " in line or line.startswith("git+"):
            name = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*@", line)
            target = line.split("@", 1)[-1] if name else line
            kind = PATH if target.strip().startswith("file:") else VCS
            out.append(Requirement(pep503(name.group(1)) if name else _egg(line), kind, line, n))
            continue
        if line.startswith((".", "/")) or re.search(r"\.(whl|tar\.gz|zip)$", line):
            out.append(Requirement(_egg(line), PATH, line, n))
            continue
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;]*)", line)
        if not m:
            continue
        spec = re.sub(r"\s*--[\w-]+(?:[=\s]+\S+)?", "", m.group(2)).strip()  # drop --hash and other options
        pinned = re.fullmatch(r"===?\s*[^,*\s]+", spec) is not None
        out.append(Requirement(pep503(m.group(1)), PINNED if pinned else RANGE, line, n))
    return out


def _egg(target: str) -> str:
    m = re.search(r"#egg=([A-Za-z0-9][A-Za-z0-9._-]*)", target)
    return pep503(m.group(1)) if m else ""


def cargo_sources(text: str) -> dict[tuple[str, str], str]:
    """(name, version) -> "registry", "vcs" or "path", from a Cargo.lock. Local crates have no `source`."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    out = {}
    for p in data.get("package", []):
        src = str(p.get("source") or "")
        kind = "registry" if src.startswith(("registry+", "sparse+")) else VCS if src.startswith("git+") else PATH
        out[(str(p.get("name", "")), str(p.get("version", "")))] = kind
    return out


def uv_sources(text: str) -> dict[str, str]:
    """name -> "registry", "vcs" or "path", from a uv.lock. The project itself is `editable` or `virtual`."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    out = {}
    for p in data.get("package", []):
        src = p.get("source") or {}
        kind = "registry" if "registry" in src else VCS if "git" in src or "url" in src else PATH
        out[str(p.get("name", ""))] = kind
    return out


def npm_registry_without_resolved(text: str) -> set[tuple[str, str]]:
    """(name, version) of package-lock entries that are registry packages despite having no `resolved`.

    npm leaves `resolved` out under `omit-lockfile-registry-resolved`; OSV-Scanner 2.7.0 then treats
    the package as local and doesn't check it (osv-scanner#3177, FINDINGS F-078). 2.7.1 checks it as a
    registry package itself (F-153); this stays for older binaries. A real local package is a link, a
    link's target (even one under another directory's `node_modules`), or resolves to a path.
    """
    packages = _npm_packages(text)
    targets = {str(e["resolved"]) for e in packages.values() if e.get("link") and isinstance(e.get("resolved"), str)}
    out = set()
    for key, entry in packages.items():
        if (not key.startswith("node_modules/") and "/node_modules/" not in key) or key in targets:
            continue
        if entry.get("link") or "resolved" in entry or "version" not in entry:
            continue
        name = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
        out.add((str(name), str(entry["version"])))
    return out


def npm_linked(text: str) -> set[tuple[str, str]]:
    """(name, version) of the local packages a package-lock links to: `file:` dependencies and workspaces.

    A `link` entry (`node_modules/o`, `"resolved": "../m/node_modules/n/o"`) names the package; its target
    holds the version. OSV-Scanner 2.7.1 reports a target under another directory's `node_modules` as a
    registry package (F-153), which would check local code against an unrelated npm package of that name.
    """
    packages = _npm_packages(text)
    out = set()
    for key, entry in packages.items():
        if not entry.get("link") or not isinstance(entry.get("resolved"), str):
            continue
        target = packages.get(entry["resolved"]) or {}
        version = str(target.get("version", ""))
        for name in {key.rsplit("node_modules/", 1)[-1], target.get("name")}:
            if name:
                out.add((str(name), version))
    return out


def _npm_packages(text: str) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return {}
    return {str(k): v for k, v in packages.items() if isinstance(v, dict)}


def locate(text: str, filename: str, name: str, version: str = "") -> int:
    """The 1-based line that declares `name` in a lockfile or manifest, or 1 if it can't be found.

    Code Quality and SARIF alerts need a line; OSV-Scanner doesn't report one (FINDINGS F-078, F-079).
    """
    lines = text.splitlines()
    patterns = []
    base = filename.rsplit("/", 1)[-1]
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        patterns.append(re.compile(rf'"(?:[^"]*/)?node_modules/{re.escape(name)}"'))
    if base == "Cargo.lock":
        patterns.append(re.compile(rf'^name = "{re.escape(name)}"$'))
    if base.endswith(".txt"):
        patterns.append(re.compile(rf"^\s*{_pep503_pattern(name)}\s*(?:[\[=<>!~;@ ]|$)", re.I))
    patterns.append(re.compile(rf"(?<![\w./-]){re.escape(name)}(?![\w-])"))
    if "/" in name:  # e.g. a Git URL: the lockfile names the package by its last path segment
        tail = re.sub(r"\.git$", "", name.rstrip("/").rsplit("/", 1)[-1])
        patterns.append(
            re.compile(rf'"(?:[^"]*/)?node_modules/{re.escape(tail)}"|(?<![\w.-]){re.escape(tail)}(?![\w-])')
        )
    for pat in patterns:
        hits = [i for i, ln in enumerate(lines, 1) if pat.search(ln)]
        if not hits:
            continue
        if version and len(hits) > 1:
            near = [i for i in hits if any(version in ln for ln in lines[i - 1 : i + 3])]
            hits = near or hits
        return hits[0]
    return 1


def _pep503_pattern(name: str) -> str:
    return "[-_.]+".join(re.escape(part) for part in re.split(r"[-_.]+", name))
