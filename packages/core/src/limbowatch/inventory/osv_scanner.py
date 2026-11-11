"""Inventory from OSV-Scanner (`scan source --all-packages`), as a pure inventory step.

OSV-Scanner reads about 25 lockfile formats (FINDINGS F-032). It runs with `--offline` against a
directory of empty databases, so it sends nothing over the network and matches nothing: Limbowatch
does the matching. Its output is then checked against the lockfiles, because it drops or misreports
some dependencies without saying so (FINDINGS F-078).

Maven has no lockfile: offline, a pom.xml gives only its direct dependencies, and only those with a literal
version. When the tree has pom.xml files, a second run with only the pom.xml extractor and its resolver
resolves them the way Maven does, through deps.dev and Maven Central and nothing else (FINDINGS F-132).
Every pom.xml left unresolved, and every Gradle build without a lockfile, is reported.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from limbowatch.ecosystems import OFFLINE_ECOSYSTEMS, by_osv
from limbowatch.inventory import checks
from limbowatch.models import Dependency, Inventory, Unchecked, UnresolvedDependency

TESTED_VERSION = "2.7.0"  # behaviour verified in F-074 and F-078

# Exit codes (F-078): 0 no findings, 1 findings, 127 an error (e.g. an unreadable lockfile), 128 no lockfiles.
# One unreadable file of a kind: "Error during extraction: (extracting as java/pomxml) PATH: ERROR". Several of
# the same kind: that line ends after the kind, and each file follows on its own tab-indented line (F-131).
_EXTRACT_ERROR = re.compile(r"^Error during extraction: \(extracting as [^)]+\) ?(.*)$")
_PATH_ERROR = re.compile(r"^(.+?): (.+)$")
# The resolver's errors, one per pom.xml, each on its own line, the first also after "Error during extraction" (F-132).
_FAILED_RESOLUTION = re.compile(r"failed resolution for (.+?): (.+)$")
MAVEN_PLUGINS = "java/pomxml,transitivedependency/pomxml"
GRADLE_BUILDS = ("build.gradle", "build.gradle.kts")
_NOT_WALKED = {".git", ".gradle", "node_modules", "build", "target", ".idea"}


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


def maven_command(binary: str, project: Path, db: Path, include_ignored: bool = False) -> list[str]:
    """Only the pom.xml extractor and its resolver, so nothing else goes online (requirements.txt would be
    resolved too, guessing versions for ranges); vulnerabilities still offline, against the empty databases."""
    return [
        binary, "scan", "source", "--x-no-default-plugins", "--x-plugins", MAVEN_PLUGINS,
        "--offline-vulnerabilities", "--local-db-path", str(db), "--no-call-analysis=all", "--all-packages",
        "--format", "json", *(["--no-ignore"] if include_ignored else []), "-r", str(project),
    ]  # fmt: skip


@dataclass(frozen=True)
class Resolution:
    """The resolving run's output (F-132); `error` when the run itself failed."""

    data: dict[str, Any]
    stderr: str
    error: str = ""


def empty_db(root: Path) -> Path:
    """`<root>/osv-scalibr/<Ecosystem>/all.zip`, empty, for every OSV ecosystem (F-074)."""
    for eco in OFFLINE_ECOSYSTEMS:
        d = root / "osv-scalibr" / eco
        d.mkdir(parents=True, exist_ok=True)
        zipfile.ZipFile(d / "all.zip", "w").close()
    return root


def run(
    project: Path,
    binary: str = "osv-scanner",
    timeout: int = 900,
    include_ignored: bool = False,
    resolve_maven: bool = True,
) -> Inventory:
    """With `resolve_maven`, pom.xml dependencies go to deps.dev and Maven Central to be resolved (F-132)."""
    project = project.resolve()
    maven: Resolution | None = None
    with tempfile.TemporaryDirectory(prefix="limbowatch-db-") as tmp:
        db = empty_db(Path(tmp))
        proc = subprocess.run(command(binary, project, db, include_ignored), capture_output=True, text=True,
                              timeout=timeout, check=False)  # fmt: skip
        data = _json(proc.stdout)
        if resolve_maven and _has_pom(data, proc.stderr):
            maven = _resolve(maven_command(binary, project, db, include_ignored), timeout)
    tool = f"osv-scanner {version(binary) or 'unknown version'}"
    return parse(data, proc.stderr, proc.returncode, project, _reader, tool, maven=maven,
                 gradle_builds=gradle_builds(project), resolve_maven=resolve_maven)  # fmt: skip


def _json(out: str) -> dict[str, Any]:
    return json.loads(out) if out.strip().startswith("{") else {}


def _has_pom(data: dict[str, Any], stderr: str) -> bool:
    paths = [str(r["source"]["path"]) for r in data.get("results") or []] + [p for p, _ in extraction_errors(stderr)]
    return any(_is_pom(p) for p in paths)


def _is_pom(path: str) -> bool:
    """OSV-Scanner's pom.xml extractor also reads `*.pom` files (F-132)."""
    name = path.rsplit("/", 1)[-1]
    return name == "pom.xml" or name.endswith(".pom")


def _resolve(cmd: list[str], timeout: int) -> Resolution:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return Resolution({}, "", f"resolving timed out after {timeout} s")
    data = _json(proc.stdout)
    if not data and proc.returncode not in (0, 1):
        return Resolution({}, proc.stderr, " ".join(proc.stderr.strip().splitlines()[-1:])[:300] or "resolving failed")
    return Resolution(data, proc.stderr)


def gradle_builds(project: Path) -> list[str]:
    """Gradle build files under `project`, relative, skipping VCS, build output and dependency directories."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(project):
        dirnames[:] = sorted(d for d in dirnames if d not in _NOT_WALKED)
        out += [(Path(dirpath) / f).relative_to(project).as_posix() for f in filenames if f in GRADLE_BUILDS]
    return sorted(out)


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
    *,
    maven: Resolution | None = None,
    gradle_builds: Sequence[str] = (),
    resolve_maven: bool = True,
) -> Inventory:
    """OSV-Scanner's JSON, stderr and exit code -> an inventory with every unchecked dependency named.

    `maven` is the resolving run's output (None: not run); `gradle_builds` the tree's Gradle build files."""
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
    poms = sorted({s for s in sources if _is_pom(s)})
    if poms:
        deps, unresolved = _transitive(poms, maven, resolve_maven, root, read, deps, unresolved)
    unresolved += _unlocked_gradle(gradle_builds, set(sources) | set(failed))
    deps = sorted(set(deps), key=lambda d: (d.source, d.line, d.ecosystem, d.name, d.version))
    return Inventory(dependencies=tuple(deps), unresolved=tuple(unresolved), sources=tuple(sorted(sources)), tool=tool,
                     skipped=tuple(sorted(skipped)))  # fmt: skip


def _transitive(
    poms: list[str],
    maven: Resolution | None,
    resolve_maven: bool,
    root: Path,
    read: Callable[[Path], str | None],
    deps: list[Dependency],
    unresolved: list[UnresolvedDependency],
) -> tuple[list[Dependency], list[UnresolvedDependency]]:
    """Add each pom.xml's resolved dependencies; report every pom.xml not resolved, with the reason (F-132).

    The resolving run lists a pom.xml's direct dependencies again (as offline), and, when resolution works, a
    second group for the same file with the whole resolved tree, direct dependencies included. A pom.xml whose
    dependencies have none of their own gets no second group; one that fails is named on stderr."""
    groups: dict[str, list[dict[str, Any]]] = {}
    failed: dict[str, str] = {}
    if maven is not None:
        for result in maven.data.get("results") or []:
            rel = _rel(str(result["source"]["path"]), root)
            if (result["source"].get("type") or "lockfile") != "lockfile":
                groups.setdefault(rel, []).extend(result.get("packages") or [])
        for line in maven.stderr.splitlines():
            if m := _FAILED_RESOLUTION.search(line):
                failed.setdefault(_rel(m.group(1), root), m.group(2).strip()[:300])
    for pom in poms:
        if not resolve_maven or maven is None or maven.error or pom in failed:
            if not resolve_maven:
                why = "only direct dependencies with a literal version are checked (--no-resolve-maven)"
            elif maven is None or maven.error:
                why = f"resolving failed: {maven.error if maven else 'not run'}"
            else:
                why = failed[pom]
            unresolved.append(UnresolvedDependency(reason=Unchecked.TRANSITIVE, source=pom, ecosystem="maven",
                                                   detail=why))  # fmt: skip
            continue
        text = read(root / pom) or ""
        got, _ = _from_source(pom, text, [e for e in groups.get(pom, []) if (e.get("package") or {}).get("version")])
        names = {d.name for d in got}
        unresolved = [u for u in unresolved
                      if not (u.source == pom and u.reason is Unchecked.NO_VERSION and u.name in names)]  # fmt: skip
        have = {o.name for o in deps if o.source == pom}
        deps += [d for d in got if d.name not in have]
    return deps, unresolved


def _unlocked_gradle(builds: Sequence[str], read_files: set[str]) -> list[UnresolvedDependency]:
    """A Gradle build resolves versions at build time; only a lockfile next to it (or the root's dependency
    verification metadata, which lists every artifact) says what it uses (F-132)."""
    if "gradle/verification-metadata.xml" in read_files:
        return []
    out = []
    for b in builds:
        folder = b.rsplit("/", 1)[0] + "/" if "/" in b else ""
        if f"{folder}gradle.lockfile" not in read_files:
            hint = "commit a lockfile (Gradle dependency locking) or pass an SBOM with --sbom"
            out.append(UnresolvedDependency(reason=Unchecked.NO_GRADLE_LOCKFILE, source=b, ecosystem="maven",
                                            detail=hint))  # fmt: skip
    return out


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
