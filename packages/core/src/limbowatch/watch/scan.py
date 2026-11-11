"""`scan()`: an inventory against the limbo feed and, for repos the tracker doesn't cover, their own advisories.

Nothing about the project is sent to limbo.watch: the feed and watchlist are downloaded whole
(PHASE0_PLAN §13.9). Package names go to deps.dev for mapping, and source repo names to GitHub.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from limbowatch.http import HttpClient
from limbowatch.models import (
    Dependency,
    Finding,
    Inventory,
    Unchecked,
    UnresolvedDependency,
    Upstream,
    UpstreamKind,
)
from limbowatch.watch import mapping, upstream
from limbowatch.watch import upstream_check as upcheck
from limbowatch.watch.candidates import Index, from_feed_zip
from limbowatch.watch.match import match
from limbowatch.watch.registries import Registries

FEED_URL = "https://limbo.watch/feed/all.zip"
WATCHLIST_URL = "https://limbo.watch/feed/watchlist.json"
# A tracker check older than this and the watcher checks the repo itself. The tracker re-checks quiet repos only
# every 30 days (and after releases, F-104), so a project's own dependencies get fresher checks here (F-071).
STALE = timedelta(days=10)


@dataclass
class ScanResult:
    inventory: Inventory
    findings: list[Finding] = field(default_factory=list)
    unresolved: list[UnresolvedDependency] = field(default_factory=list)  # the inventory's, plus partly checked
    upstreams: list[Upstream] = field(default_factory=list)  # with registry names resolved to repos and tags
    upstreams_checked: set[str] = field(default_factory=set)  # host/repo of upstream sources checked in full
    stats: dict[str, int] = field(default_factory=dict)


async def fetch(http: HttpClient, url: str, cache: Path | None) -> bytes:
    """Download `url`, reusing a cached copy while its ETag still matches."""
    body = etag = None
    if cache is not None:
        f, t = cache / Path(url).name, cache / (Path(url).name + ".etag")
        if f.exists() and t.exists():
            body, etag = f.read_bytes(), t.read_text().strip() or None
    r = await http.get(url, etag=etag, raw=True)
    if r.status == 304 and body is not None:
        return body
    if not r.ok or not isinstance(r.body, bytes):
        if body is not None:
            return body  # stale but usable; the result says when the feed was generated
        raise RuntimeError(f"couldn't download {url}: HTTP {r.status}")
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        (cache / Path(url).name).write_bytes(r.body)
        (cache / (Path(url).name + ".etag")).write_text(r.etag or "")
    return r.body


@dataclass
class Shared:
    """What every project in a run shares: the feed plus repos polled just now, and each dependency's source
    repo. Org-wide mode builds it once over all projects, so each upstream repo is mapped and polled once."""

    index: Index
    mapped: dict[tuple[str, str, str], mapping.Mapped] = field(default_factory=dict)
    on_watchlist: set[str] = field(default_factory=set)
    polled: set[str] = field(default_factory=set)
    not_polled: set[str] = field(default_factory=set)
    upstream_check: bool = True
    # each upstream source (submodule, CMake, Bazel, vcpkg, ...) → itself resolved, then what it pulls in
    upstreams: dict[Upstream, list[Upstream]] = field(default_factory=dict)
    checked: dict[Upstream, upcheck.Checked] = field(default_factory=dict)  # each resolved one's outcome


async def prepare(
    deps: list[Dependency],
    http: HttpClient,
    *,
    feed_zip: bytes,
    watchlist: dict[str, str],
    now: datetime,
    upstream_check: bool = True,
    upstreams: Sequence[Upstream] = (),
    git_cache: Path | None = None,
    osv_commits: bool = True,
) -> Shared:
    index = Index()
    for c in from_feed_zip(feed_zip):
        index.add(c)
    sh = Shared(index, upstream_check=upstream_check)
    if upstream_check:
        sh.upstreams = await Registries(http).resolve(upstreams)
        sh.mapped = await mapping.map_all(http, deps)
        sources = [r for rs in sh.upstreams.values() for r in rs]
        repos = {m.repo for m in sh.mapped.values() if m.repo}
        repos |= {u.repo for u in sources if u.host == "github.com" and u.repo}
        due = {r for r in repos if not _fresh(watchlist.get(r), now)}
        polled = await upstream.poll(http, due)
        for c in polled.candidates:
            index.add(c)
        sh.on_watchlist, sh.polled, sh.not_polled = repos - due, polled.polled, polled.not_polled
        sh.checked = await upcheck.check(http, sources, index, not_polled=sh.not_polled, git_cache=git_cache,
                                         osv_commits=osv_commits, aliases=polled.aliases)  # fmt: skip
    return sh


def assess(inv: Inventory, sh: Shared) -> ScanResult:
    """One project's findings against the shared feed, polls and mappings. No I/O."""
    res = ScanResult(inventory=inv, unresolved=list(inv.unresolved))
    deps = list(inv.dependencies)
    keys = {(d.ecosystem, d.name, d.version) for d in deps}
    mapped = {k: m for k, m in sh.mapped.items() if k in keys}
    if sh.upstream_check:
        repos = {m.repo for m in mapped.values() if m.repo}
        res.stats |= {
            "repos": len(repos),
            "repos_on_watchlist": len(repos & sh.on_watchlist),
            "repos_polled": len(repos & sh.polled),
        }
        for d in deps:
            m = mapped[(d.ecosystem, d.name, d.version)]
            if m.repo is None:
                res.unresolved.append(_partial(d, Unchecked.NO_REPO, m.method))
            elif m.repo in sh.not_polled:
                res.unresolved.append(_partial(d, Unchecked.REPO_NOT_POLLED, m.repo))
    index = sh.index
    go = [c for cs in index.by_repo.values() for c in cs if any(p.ecosystem == "go" for p in c.adv.packages)]
    per_repo: dict[str, set[tuple[str, str]]] = {}
    for (eco, name, _), m in mapped.items():
        if m.repo:
            per_repo.setdefault(m.repo, set()).add((eco, name))
    for d in deps:
        found = mapped.get((d.ecosystem, d.name, d.version))
        repo = found.repo if found else None
        n_pkgs = len(per_repo.get(repo, ())) if repo else 1
        res.findings += match(d, index, repo, go if d.ecosystem == "go" else None, n_pkgs)
    res.findings.sort(key=lambda f: (f.dependency.source, f.dependency.line, f.dependency.name, f.ghsa_id))
    seen: set[tuple[object, ...]] = set()
    for u in inv.upstreams:
        for r in sh.upstreams.get(u, [u]):
            # whole declarations, so two sources with one name in two files are both kept (F-141); a vcpkg port
            # pulled in by several ports is one dependency of the manifest (F-142)
            transitive = r.kind is UpstreamKind.VCPKG and "a dependency of" in r.via
            k = (r.kind.value, r.name, r.host, r.repo, r.ref, r.version, r.url, r.source,
                 None if transitive else r.line)  # fmt: skip
            if k not in seen:
                seen.add(k)
                res.upstreams.append(r)
                if not sh.upstream_check:
                    res.unresolved.append(upstream_unchecked(r, checking=False))
                    continue
                done = sh.checked.get(r) or upcheck.Checked(unchecked=upstream_unchecked(r))
                res.findings += done.findings
                if done.unchecked is not None:
                    res.unresolved.append(done.unchecked)
                elif r.repo:
                    res.upstreams_checked.add(f"{r.host}/{r.repo}")
    res.findings.sort(key=lambda f: (f.dependency.source, f.dependency.line, f.dependency.name, f.ghsa_id))
    res.stats |= {"dependencies": len(deps), "feed_advisories": len(index.ids), "findings": len(res.findings),
                  "upstreams": len(res.upstreams)}  # fmt: skip
    return res


def upstream_unchecked(u: Upstream, checking: bool = True) -> UnresolvedDependency:
    """An upstream source not checked: with `--no-upstream` (`checking` False), or because its repo or its version is
    unknown. Says how far it got."""
    where = f"{u.host}/{u.repo}" if u.repo else ""
    pin = u.ref or (f"version {u.version}" if u.version else "")
    known = f"{where} at {pin}" if where and pin else where
    if not checking:
        reason, detail = Unchecked.UPSTREAM_NO_CHECK, known or pin or u.detail
    elif u.repo is None:
        reason, detail = Unchecked.UPSTREAM_UNKNOWN, u.detail
    elif not u.ref:
        reason, detail = Unchecked.UPSTREAM_NO_REF, "; ".join(x for x in (known, u.detail) if x)
    else:
        reason, detail = Unchecked.UPSTREAM_NO_CHECK, known
    if u.via:
        detail = f"{detail} ({u.via})" if detail else u.via
    return UnresolvedDependency(reason=reason, source=u.source, name=u.name, version=u.ref or u.version or "",
                                ecosystem=u.kind.value, detail=detail, line=u.line)  # fmt: skip


async def scan(
    inv: Inventory,
    http: HttpClient,
    *,
    feed_zip: bytes,
    watchlist: dict[str, str],
    now: datetime,
    upstream_check: bool = True,
    git_cache: Path | None = None,
    osv_commits: bool = True,
) -> ScanResult:
    sh = await prepare(list(inv.dependencies), http, feed_zip=feed_zip, watchlist=watchlist, now=now,
                       upstream_check=upstream_check, upstreams=inv.upstreams, git_cache=git_cache,
                       osv_commits=osv_commits)  # fmt: skip
    return assess(inv, sh)


def _fresh(last: str | None, now: datetime) -> bool:
    if not last:
        return False
    return now - datetime.fromisoformat(last.replace("Z", "+00:00")) < STALE


def _partial(d: Dependency, reason: Unchecked, detail: str) -> UnresolvedDependency:
    return UnresolvedDependency(reason=reason, source=d.source, name=d.name, version=d.version, ecosystem=d.ecosystem,
                                detail=detail, line=d.line)  # fmt: skip


def watchlist_repos(data: bytes) -> dict[str, str]:
    return dict(json.loads(data).get("repos") or {})
