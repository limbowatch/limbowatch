"""Upstream sources against advisories in limbo (PHASE0_PLAN §13.18 steps 2-3; FINDINGS F-136, F-138).

An upstream source (a submodule, a CMake fetch, a Bazel module, a vcpkg port, ...) is a repo at a commit, tag or
version. Its repo's advisories that name no package OSV knows (C/C++, `other`: 60% of the feed, F-135) are about
that repo's code, so they're matched by repository; advisories that name a registry package (an npm or PyPI
package built from the same repo) are left to that package's users, as `match` does.

Affected or not:
1. **By commit, from the repo's history** (a commits-only clone, `gitgraph`): the fix versions are looked up among
   the repo's tags. A pinned commit that contains a fix tag is fixed. One that's older than a fix tag, on the same
   history, is affected (unless the range's lower bound says it's too old). One on a branch that contains neither is
   only possibly affected.
2. **By version**, where the commit can't be placed: the version (a tag's, a registry's, or the nearest tag's) against
   the advisory's range and fixed version, the way `match` reads ranges, with lenient upstream versions
   (`UpstreamVersion`).
3. **OSV by commit:** OSV evaluates its own GIT ranges for a commit (F-136). When it lists the commit under a CVE the
   advisory cites, the commit is affected.

Anything that can't be evaluated exactly is a *possible* finding, never a silent pass.
"""

from __future__ import annotations

import hashlib
import re
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from limbowatch.ecosystems import info, package_name
from limbowatch.http import HttpClient
from limbowatch.models import (
    AdvisoryPackage,
    Dependency,
    Finding,
    MatchKind,
    Unchecked,
    UnresolvedDependency,
    Upstream,
)
from limbowatch.sources import osv
from limbowatch.versions import (
    UPSTREAM,
    UpstreamVersion,
    affected,
    already_fixed,
    alternatives,
    dotdot_readings,
    fixed_versions,
    tag_for,
    version_of_tag,
)
from limbowatch.watch.candidates import Candidate, Index


class Graph(Protocol):
    tags: dict[str, str]

    def commit(self, ref: str) -> str | None: ...
    def contains(self, ancestor: str, descendant: str) -> bool | None: ...
    def describe(self, commit: str) -> str | None: ...
    def tags_containing(self, commit: str) -> list[str]: ...


@dataclass(frozen=True)
class Pin:
    """What's known of the version an upstream source builds from."""

    commit: str | None  # full hash, when the repo's history placed it
    version: str | None  # a release version: declared, from its tag, or the nearest tag's
    shown: str  # as reported: the tag, the version or a short commit


def _uv(s: str | None) -> UpstreamVersion | None:
    try:
        return UpstreamVersion(s) if s else None
    except ValueError:
        return None


def _same(a: str | None, b: str | None) -> bool:
    va, vb = _uv(a), _uv(b)
    return va is not None and vb is not None and va == vb


def _tag_version(tag: str, g: Graph | None) -> str | None:
    """The version a tag names, when it's certain: with the repo's tags at hand, the version must lead back to the
    same commit (`pcre2-10.44` → 10.44 → pcre2-10.44), so a misread tag never stands for a release (F-141)."""
    v = version_of_tag(tag)
    if v is None or g is None or tag not in g.tags:
        return v
    back = tag_for(v, g.tags)
    return v if back is not None and g.tags[back] == g.tags[tag] else None


def pin(u: Upstream, g: Graph | None) -> Pin:
    version = u.version if u.version and not u.version.startswith(">=") else None
    commit = None
    if g is not None:
        if u.ref:
            commit = g.commit(u.ref)
        if commit is None and version and (t := tag_for(version, g.tags)):
            commit = g.tags[t]
    if version is None and u.ref and not u.ref_is_commit:
        version = _tag_version(u.ref, g)
    if version is None and commit and g is not None and (near := g.describe(commit)):
        version = _tag_version(near, g)
    shown = (u.ref[:12] if u.ref_is_commit else u.ref) if u.ref else (u.version or "")
    return Pin(commit, version, shown)


def _fix_versions(p: AdvisoryPackage) -> list[str]:
    """The fix releases an advisory package names: its fixed versions; only when it names none, the upper bounds of
    its `< X` ranges. (A range's bounds aren't fixes when fixes are named: `3.1.*` reads as `< 3.2.0`, and 3.2.0 was
    affected; F-139.)"""
    fixes = fixed_versions(p.patched_versions) or []
    if not fixes:
        for alt in alternatives(UPSTREAM, p.vulnerable_version_range) or []:
            fixes += [v for op, v in alt if op == "<"]
    return list(dict.fromkeys(fixes))


def exact_only(rng: str | None) -> list[str] | None:
    """The versions of a range that lists only exact versions ("3.26.0"), else None. Maintainers often type the last
    affected version this way, meaning "up to 3.26.0" (FINDINGS F-139), so it's never read as "only 3.26.0"."""
    alts = alternatives(UPSTREAM, rng)
    if not alts or not all(len(a) == 1 and a[0][0] == "=" for a in alts):
        return None
    return [a[0][1] for a in alts]


def by_version(version: str | None, p: AdvisoryPackage) -> tuple[bool | None, str]:
    """`match._version` for upstream versions."""
    rng, patched = p.vulnerable_version_range, p.patched_versions
    if not rng and not patched:
        return None, "the advisory gives no affected or fixed version"
    if not version:
        return None, "which release this commit belongs to isn't known"
    if rng and (listed := exact_only(rng)) is not None and not any(_same(version, x) for x in listed):
        if already_fixed(UPSTREAM, version, patched):
            return False, ""
        fixed = f" and {patched} as fixed" if patched else ""
        return None, f"the advisory lists only {rng} as affected{fixed}; earlier versions may be affected too"
    if rng:
        hit = affected(UPSTREAM, version, rng)
        if hit is None and (readings := dotdot_readings(rng)):
            verdicts = {affected(UPSTREAM, version, r) for r in readings}
            hit = verdicts.pop() if len(verdicts) == 1 and None not in verdicts else None
        if hit is False:
            return False, ""
        if hit is None:
            return None, f"the advisory's range “{rng}” can't be evaluated exactly"
        if already_fixed(UPSTREAM, version, patched):
            return None, f"{version} is in the range “{rng}”, but at or after the fixed version “{patched}”"
        return True, f"{version} is in the range “{rng}”"
    is_fixed = already_fixed(UPSTREAM, version, patched)
    if is_fixed is None:
        return None, f"the fixed version “{patched}” can't be compared with {version}"
    return (False, "") if is_fixed else (True, f"{version} is before the fixed version “{patched}”")


def _major(v: str | None) -> int | None:
    m = re.match(r"v?(\d+)", (v or "").strip())
    return int(m.group(1)) if m else None


def _open_after(p: AdvisoryPackage, fixes: list[str]) -> bool:
    """Does a range alternative start at or after these fixes and have no upper bound (`< 1.2.5 || >= 2.0.0`: the 2.x
    line has no fix)? Unreadable ranges don't say so."""
    top = max((v for f in fixes if (v := _uv(f)) is not None), default=None)
    if top is None:
        return False
    for alt in alternatives(UPSTREAM, p.vulnerable_version_range) or []:
        lows = [_uv(v) for op, v in alt if op in (">=", ">")]
        if not any(op in ("<", "<=", "=") for op, _ in alt) and any(lo is not None and lo >= top for lo in lows):
            return True
    return False


def _affected_release(pn: Pin, p: AdvisoryPackage, g: Graph) -> str | None:
    """A release whose history includes the pinned commit and that's itself in the affected range: then the pin, older
    than it, can't have the fix either. None when there's none (a commit after the last affected release)."""
    hits = []
    for tag in g.tags_containing(pn.commit or ""):
        v = _tag_version(tag, g)
        if v is not None and by_version(v, p)[0] is True and (uv := _uv(v)) is not None:
            hits.append((uv, tag))
    return min(hits)[1] if hits else None


def verdict(pn: Pin, p: AdvisoryPackage, g: Graph | None) -> tuple[bool | None, str]:
    """Is the pinned source affected per this advisory package? (verdict, evidence)."""
    if pn.commit and g is not None:
        fixes = {v: (t, g.tags[t]) for v in _fix_versions(p) if (t := tag_for(v, g.tags))}
        contained = [v for v, (_, c) in fixes.items() if g.contains(c, pn.commit)]
        if contained:
            # A fix release in its history clears it, unless that fix is for an older line than the pin's own
            # release: `< 1.2.5 || >= 2.0.0, < 2.0.3` at 2.0.1 contains 1.2.5, not 2.0.3 (F-141).
            if len(contained) == len(fixes) and not _open_after(p, contained):
                return False, ""  # every fix release the advisory names is in its history
            pv = _uv(pn.version)
            if pv is None:
                if len(fixes) == 1:
                    return False, ""
                return None, (f"{pn.shown} contains the fix release {fixes[contained[0]][0]}, but which release line "
                              "it's on isn't known")  # fmt: skip
            if any((fv := _uv(v)) is None or fv >= pv for v in contained):
                return False, ""
            hit, why = by_version(pn.version, p)
            if hit is False:
                return False, ""
            # Fixed when its own line's fixes are all in its history (3.10.0 has 3.0.0-beta3, the 3.x fix; 2.11.0 is on
            # a 2.x branch), or the one fix is ("> 1.0", fixed in 2.0.0, at 3.10.0), and no range runs past them (F-141)
            line = [v for v in fixes if _major(v) == _major(pn.version)]
            closed = (
                (bool(line) and all(v in contained for v in line))
                or len(fixes) == 1
                or bool(already_fixed(UPSTREAM, pn.version or "", p.patched_versions))
            )
            if hit is None and closed and not _open_after(p, contained):
                return False, ""
            older_fix = ", ".join(fixes[v][0] for v in contained)
            return hit, f"{pn.shown} contains {older_fix}, the fix of an older line; {why}"
        older = [(v, t) for v, (t, c) in fixes.items() if g.contains(pn.commit, c)]
        if older:
            v, t = older[0]
            rng = p.vulnerable_version_range
            if (listed := exact_only(rng)) is not None and not any(_same(pn.version, x) for x in listed):
                return None, (f"{pn.shown} is older than the fix release, and the advisory lists only {rng} as "
                              "affected; earlier versions may be affected too")  # fmt: skip
            if rng:
                lower = affected(UPSTREAM, pn.version, rng) if pn.version else None
                if lower is False:
                    return False, ""  # older than the fix, and older than the affected range too
                if lower is None:  # where the range starts can't be told: possibly too old to be affected
                    return (
                        None,
                        f"{pn.shown} is older than {t}, the fix release, but the range “{rng}” can't be evaluated",
                    )
            if rel := _affected_release(pn, p, g):
                where = "is" if g.tags.get(rel) == pn.commit else f"is in the history of {rel}, which is"
                return True, f"{pn.shown} {where} in the affected range, and older than {t}, the fix release ({v})"
            return None, (f"{pn.shown} is newer than the last affected release and older than {t}, the fix release: "
                          "the fix may already be in it")  # fmt: skip
        if fixes:
            hit, why = by_version(pn.version, p)
            if hit is False:
                return False, ""
            tags = ", ".join(t for t, _ in fixes.values())
            return None, f"{pn.shown} is on a branch without the fix release ({tags}); {why}"
    return by_version(pn.version, p)


def _usable(p: AdvisoryPackage) -> bool:
    """A package a registry's users match by name: a valid name in an ecosystem OSV knows (`other`, `c` aren't)."""
    n = package_name(p.ecosystem, p.name)
    return n is not None and n.valid and info(p.ecosystem).osv is not None


def candidates(u: Upstream, index: Index, aliases: dict[str, str] | None = None) -> list[Candidate]:
    """The repo's advisories in limbo about its own code: those with an entry that names no registry package (an
    advisory naming `pip:protobuf` and `other:protobuf C++` is about the C++ code too; F-141). `aliases` maps a repo's
    old name (GitHub redirects renamed repos) to the one advisories are filed under."""
    if u.host != "github.com" or not u.repo:
        return []
    repo = (aliases or {}).get(u.repo, u.repo)
    return [c for c in index.by_repo.get(repo, [])
            if not c.adv.packages or any(not _usable(p) for p in c.adv.packages)]  # fmt: skip


def dependency(u: Upstream, pn: Pin) -> Dependency:
    name = f"{u.host}/{u.repo}"
    purl = f"pkg:github/{u.repo}@{pn.shown}" if u.host == "github.com" and pn.shown else None
    return Dependency(ecosystem=UPSTREAM, name=name, version=pn.shown, source=u.source, line=u.line, purl=purl,
                      note=f"{u.kind.value} {u.name}")  # fmt: skip


def findings(u: Upstream, pn: Pin, cands: list[Candidate], g: Graph | None,
             osv_ids: set[str] | None = None) -> list[Finding]:  # fmt: skip
    dep = dependency(u, pn)
    out = []
    for c in cands:
        own = [p for p in c.adv.packages if not _usable(p)]  # its registry packages are their users' to match
        entries: Sequence[AdvisoryPackage | None] = own or [None]
        verdicts = [verdict(pn, p, g) if p else (None, "the advisory gives no affected or fixed version")
                    for p in entries]  # fmt: skip
        hits = [(h, why, p) for (h, why), p in zip(verdicts, entries, strict=True) if h is not False]
        cited = sorted(set(c.cves) & (osv_ids or set()))
        if cited:
            hits = [(True, f"OSV lists {pn.shown} as affected by {', '.join(cited)}, which the advisory cites",
                     next((p for _, _, p in hits), entries[0]))]  # fmt: skip
        if not hits:
            continue
        hit, why, p = next(((h, w, x) for h, w, x in hits if h is True), hits[0])
        key = hashlib.sha256(f"{UPSTREAM}:{dep.name}:{c.adv.ghsa_id}".encode()).hexdigest()[:16]
        out.append(Finding(
            key=key, dependency=dep, ghsa_id=c.adv.ghsa_id, url=c.adv.html_url, repo=c.adv.repo,
            severity=c.adv.severity, cve=c.cve, cves=c.cves, published_at=c.adv.published_at, affected=hit,
            match=MatchKind.UPSTREAM, advisory_package=(p.name or "") if p else "",
            vulnerable_range=p.vulnerable_version_range if p else None, fixed=p.patched_versions if p else None,
            evidence=f"from {u.repo}, which this {u.kind.value} builds from. {why}", source=c.source,
        ))  # fmt: skip
    return sorted(out, key=lambda f: f.ghsa_id)


@dataclass
class Checked:
    """One upstream source's outcome: its findings, or why it wasn't (fully) checked."""

    findings: list[Finding] = field(default_factory=list)
    unchecked: UnresolvedDependency | None = None


def unchecked(u: Upstream, reason: Unchecked, detail: str) -> UnresolvedDependency:
    return UnresolvedDependency(reason=reason, source=u.source, name=u.name, version=u.ref or u.version or "",
                                ecosystem=u.kind.value, detail=detail, line=u.line)  # fmt: skip


def _where(u: Upstream) -> str:
    return f"{u.host}/{u.repo}" if u.repo else ""


async def check(
    http: HttpClient,
    ups: Sequence[Upstream],
    index: Index,
    *,
    not_polled: set[str],
    git_cache: Path | None = None,
    osv_commits: bool = True,
    aliases: dict[str, str] | None = None,
) -> dict[Upstream, Checked]:
    """Every resolved upstream source against the index (the feed plus repos polled just now)."""
    out: dict[Upstream, Checked] = {}
    todo: list[tuple[Upstream, list[Candidate]]] = []
    for u in dict.fromkeys(ups):
        if u.repo is None:
            out[u] = Checked(
                unchecked=unchecked(u, Unchecked.UPSTREAM_UNKNOWN, u.detail + (f" ({u.via})" if u.via else ""))
            )
        elif u.host != "github.com":
            out[u] = Checked(unchecked=unchecked(u, Unchecked.UPSTREAM_OFF_GITHUB, _where(u)))
        elif u.repo in not_polled:
            out[u] = Checked(unchecked=unchecked(u, Unchecked.REPO_NOT_POLLED, _where(u)))
        elif not (cands := candidates(u, index, aliases)):
            out[u] = Checked()  # checked: nothing in limbo about its code
        elif not u.ref and not u.version:
            n = len(cands)
            detail = f"{_where(u)} has {n} advisor{'y' if n == 1 else 'ies'} in limbo; " + (
                u.detail or "no tag or commit"
            )
            out[u] = Checked(unchecked=unchecked(u, Unchecked.UPSTREAM_NO_REF, detail))
        else:
            todo.append((u, cands))
    if not todo:
        return out
    with tempfile.TemporaryDirectory(prefix="limbowatch-git-") as tmp:
        root = git_cache / "git" if git_cache is not None else Path(tmp)
        from limbowatch.watch.gitgraph import graphs

        urls = {u.repo: f"https://github.com/{u.repo}.git" for u, _ in todo if u.repo}
        gs = await graphs(urls, root)
        pins = {u: pin(u, gs.get(u.repo or "")) for u, _ in todo}
        hits: dict[str, set[str]] = {}
        commits = sorted({p.commit for (u, cands), p in zip(todo, pins.values(), strict=True)
                          if p.commit and any(c.cves for c in cands)})  # fmt: skip
        if osv_commits and commits:
            hits = await osv.by_commit(http, commits) or {}
        for u, cands in todo:
            pn, g = pins[u], gs.get(u.repo or "")
            if pn.commit is None and pn.version is None:
                why = "its history couldn't be read" if g is None else f"{u.ref} isn't in {_where(u)}'s history"
                n = len(cands)
                out[u] = Checked(unchecked=unchecked(u, Unchecked.UPSTREAM_NO_REF,
                                                     f"{_where(u)} has {n} advisor{'y' if n == 1 else 'ies'} in limbo, "
                                                     f"but which release {u.ref} is can't be told: {why}"))  # fmt: skip
                continue
            out[u] = Checked(findings=findings(u, pn, cands, g, hits.get(pn.commit or "")))
    return out
