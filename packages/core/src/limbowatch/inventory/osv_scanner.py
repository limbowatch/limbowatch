"""Inventory from OSV-Scanner (`scan source --all-packages`), run offline as a pure inventory step.

OSV-Scanner reads about 25 lockfile formats (FINDINGS F-032). It runs with `--offline` against a
directory of empty databases, so it sends nothing over the network and matches nothing: Limbowatch
does the matching. Its output is then checked against the lockfiles, because it drops or misreports
some dependencies without saying so (FINDINGS F-078).
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from limbowatch.ecosystems import OSV_ECOSYSTEMS, by_osv
from limbowatch.inventory import checks
from limbowatch.models import Dependency, Inventory, Unchecked, UnresolvedDependency

TESTED_VERSION = "2.7.0"  # behaviour verified in F-074 and F-078

# Exit codes (F-078): 0 no findings, 1 findings, 127 an error (e.g. an unreadable lockfile), 128 no lockfiles.
# One unreadable file of a kind: "Error during extraction: (extracting as java/pomxml) PATH: ERROR". Several of
# the same kind: that line ends after the kind, and each file follows on its own tab-indented line (F-131).
_EXTRACT_ERROR = re.compile(r"^Error during extraction: \(extracting as [^)]+\) ?(.*)$")
_PATH_ERROR = re.compile(r"^(.+?): (.+)$")


def extraction_errors(stderr: str) -> list[tuple[str, str]]:
    """(path, error) for every file OSV-Scanner couldn't read, as printed (paths may lack their leading "/")."""
    out: list[tuple[str, str]] = []
    listing = False
    for line in stderr.splitlines():
        if m := _EXTRACT_ERROR.match(line):
            rest = m.group(1).strip()
            listing = not rest
            if rest and (pe := _PATH_ERROR.match(rest)):
                out.append((pe.group(1), pe.group(2)))
        elif listing and line.startswith("\t") and (pe := _PATH_ERROR.match(line.strip())):
            out.append((pe.group(1), pe.group(2)))
        else:
            listing = False
    return out


class InventoryError(RuntimeError):
    pass


def version(binary: str = "osv-scanner") -> str | None:
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30, check=False).stdout
    except OSError:
        return None
    m = re.search(r"osv-scanner version: (\S+)", out)
    return m.group(1) if m else None


def command(binary: str, project: Path, db: Path, include_ignored: bool = False) -> list[str]:
    """OSV-Scanner skips files a .gitignore excludes, an enclosing repo's included (F-085); `include_ignored`
    passes --no-ignore."""
    return [
        binary, "scan", "source", "--offline", "--offline-vulnerabilities", "--local-db-path", str(db),
        "--no-call-analysis=all", "--all-packages", "--format", "json",
        *(["--no-ignore"] if include_ignored else []), "-r", str(project),
    ]  # fmt: skip


def empty_db(root: Path) -> Path:
    """`<root>/osv-scalibr/<Ecosystem>/all.zip`, empty, for every OSV ecosystem (F-074)."""
    for eco in OSV_ECOSYSTEMS:
        d = root / "osv-scalibr" / eco
        d.mkdir(parents=True, exist_ok=True)
        zipfile.ZipFile(d / "all.zip", "w").close()
    return root


def run(project: Path, binary: str = "osv-scanner", timeout: int = 900, include_ignored: bool = False) -> Inventory:
    project = project.resolve()
    with tempfile.TemporaryDirectory(prefix="limbowatch-db-") as tmp:
        cmd = command(binary, project, empty_db(Path(tmp)), include_ignored)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    data = json.loads(proc.stdout) if proc.stdout.strip().startswith("{") else {}
    tool = f"osv-scanner {version(binary) or 'unknown version'}"
    return parse(data, proc.stderr, proc.returncode, project, _reader, tool)


def _reader(path: Path) -> str | None:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None


def parse(
    data: dict[str, Any],
    stderr: str,
    code: int,
    root: Path,
    read: Callable[[Path], str | None],
    tool: str = "osv-scanner",
) -> Inventory:
    """OSV-Scanner's JSON, stderr and exit code -> an inventory with every unchecked dependency named."""
    deps: list[Dependency] = []
    unresolved: list[UnresolvedDependency] = []
    sources: list[str] = []
    failed = {_rel(path, root): err for path, err in extraction_errors(stderr)}
    for path, err in sorted(failed.items()):
        unresolved.append(UnresolvedDependency(reason=Unchecked.LOCKFILE_UNREADABLE, source=path, detail=err))
    if code == 128:
        hint = "files a .gitignore excludes (also an enclosing repo's) are skipped; --scan-ignored includes them"
        unresolved.append(UnresolvedDependency(reason=Unchecked.NO_LOCKFILES, source=".", detail=hint))
    elif code not in (0, 1) and not (code == 127 and failed):
        tail = " ".join(stderr.strip().splitlines()[-3:])
        raise InventoryError(f"osv-scanner exited with {code}: {tail}")
    skipped: list[str] = []
    for result in data.get("results") or []:
        src = Path(result["source"]["path"])
        rel = _rel(str(src), root)
        text = read(src if src.is_absolute() else root / src) or ""
        if own_report(text):  # a CycloneDX report from an earlier scan would count every finding twice
            skipped.append(rel)
            continue
        sources.append(rel)
        d, u = _from_source(rel, text, result.get("packages") or [])
        deps += d
        unresolved += u
    deps = sorted(set(deps), key=lambda d: (d.source, d.line, d.ecosystem, d.name, d.version))
    return Inventory(dependencies=tuple(deps), unresolved=tuple(unresolved), sources=tuple(sorted(sources)), tool=tool,
                     skipped=tuple(sorted(skipped)))  # fmt: skip


def own_report(text: str) -> bool:
    """A CycloneDX document whose tool is Limbowatch: `limbowatch scan -o cyclonedx=…` output, not an SBOM."""
    if '"limbowatch"' not in text or '"CycloneDX"' not in text:
        return False
    try:
        doc = json.loads(text)
    except ValueError:
        return False
    tools = (doc.get("metadata") or {}).get("tools") or {}
    comps = tools.get("components", []) if isinstance(tools, dict) else tools
    return doc.get("bomFormat") == "CycloneDX" and any(
        c.get("name") == "limbowatch" for c in comps if isinstance(c, dict)
    )


def _rel(path: str, root: Path) -> str:
    p = Path(path if path.startswith("/") else "/" + path)  # stderr paths drop the leading "/" (F-078)
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        try:
            return Path(path).relative_to(root).as_posix()
        except ValueError:
            return path


@dataclass(frozen=True)
class _Lockfile:
    """What the lockfile itself says, for the checks OSV-Scanner's output can't answer (F-078)."""

    rel: str
    text: str
    reqs: dict[str, checks.Requirement]
    cargo: dict[tuple[str, str], str]
    uv: dict[str, str]
    npm_registry: set[tuple[str, str]]


def _from_source(
    rel: str, text: str, packages: list[dict[str, Any]]
) -> tuple[list[Dependency], list[UnresolvedDependency]]:
    base = rel.rsplit("/", 1)[-1]
    is_req = base.endswith(".txt")
    reqs = checks.requirements(text) if is_req else []
    lock = _Lockfile(
        rel,
        text,
        {r.name: r for r in reqs if r.name},
        checks.cargo_sources(text) if base == "Cargo.lock" else {},
        checks.uv_sources(text) if base == "uv.lock" else {},
        checks.npm_registry_without_resolved(text) if base in ("package-lock.json", "npm-shrinkwrap.json") else set(),
    )
    deps: list[Dependency] = []
    out: list[UnresolvedDependency] = []
    for entry in packages:
        got = _one(entry.get("package") or {}, lock)
        if isinstance(got, Dependency):
            deps.append(got)
        else:
            out.append(got)
    listed = {checks.pep503(str((e.get("package") or {}).get("name", ""))) for e in packages}
    for r in reqs:
        if r.kind in (checks.VCS, checks.PATH) and r.name not in listed:  # OSV-Scanner leaves these out (F-078)
            reason = Unchecked.VCS if r.kind == checks.VCS else Unchecked.PATH
            out.append(UnresolvedDependency(reason=reason, source=rel, name=r.name, ecosystem="pip", detail=r.spec,
                                            line=r.line))  # fmt: skip
    return deps, out


def _one(p: dict[str, Any], lock: _Lockfile) -> Dependency | UnresolvedDependency:
    name, ver, osv_eco = str(p.get("name", "")), str(p.get("version", "")), str(p.get("ecosystem", ""))
    purl = str(p["purl"]) if p.get("purl") else None
    line = checks.locate(lock.text, lock.rel, name, ver)
    eco = by_osv(osv_eco)

    def unchecked(reason: Unchecked, detail: str = "") -> UnresolvedDependency:
        shown = "" if reason is Unchecked.RANGE_ONLY else ver  # OSV-Scanner reads ">=2" as version "2" (F-078)
        return UnresolvedDependency(reason=reason, source=lock.rel, name=name, version=shown,
                                    ecosystem=eco.ghsa if eco else osv_eco, detail=detail, line=line)  # fmt: skip

    if osv_eco == "GIT":
        return unchecked(Unchecked.VCS, f"commit {p.get('commit') or 'unknown'}")
    if eco is None:
        return unchecked(Unchecked.UNKNOWN_ECOSYSTEM)
    if name.startswith((".", "/")):
        return unchecked(Unchecked.PATH)
    note = None
    if purl and "source=LOCAL" in purl:
        if (name, ver) not in lock.npm_registry:
            return unchecked(Unchecked.LOCAL)
        note = "no `resolved` field in the lockfile; checked as a registry package (osv-scanner#3177)"
    kind = lock.cargo.get((name, ver)) or lock.uv.get(name)
    if kind == checks.VCS:
        return unchecked(Unchecked.VCS)
    if kind == checks.PATH:
        return unchecked(Unchecked.LOCAL)
    if not ver:
        return unchecked(Unchecked.NO_VERSION)
    req = lock.reqs.get(checks.pep503(name))
    if req is not None and req.kind == checks.RANGE:
        return unchecked(Unchecked.RANGE_ONLY, req.spec)
    return Dependency(ecosystem=eco.ghsa, name=name, version=ver, source=lock.rel, line=line, purl=purl, note=note)
