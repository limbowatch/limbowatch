"""`scan()`: an inventory against the limbo feed and, for repos the tracker doesn't cover, their own advisories.

Nothing about the project is sent to limbo.watch: the feed and watchlist are downloaded whole
(PHASE0_PLAN §13.9). Package names go to deps.dev for mapping, and source repo names to GitHub.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from limbowatch.http import HttpClient
from limbowatch.models import Dependency, Finding, Inventory, Unchecked, UnresolvedDependency
from limbowatch.watch import mapping, upstream
from limbowatch.watch.candidates import Index, from_feed_zip
from limbowatch.watch.match import match

FEED_URL = "https://limbo.watch/feed/all.zip"
WATCHLIST_URL = "https://limbo.watch/feed/watchlist.json"
STALE = timedelta(days=10)  # the tracker checks quiet repos weekly, a little later when its budget is tight (F-071)


@dataclass
class ScanResult:
    inventory: Inventory
    findings: list[Finding] = field(default_factory=list)
    unresolved: list[UnresolvedDependency] = field(default_factory=list)  # the inventory's, plus partly checked
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


async def scan(
    inv: Inventory,
    http: HttpClient,
    *,
    feed_zip: bytes,
    watchlist: dict[str, str],
    now: datetime,
    upstream_check: bool = True,
) -> ScanResult:
    index = Index()
    for c in from_feed_zip(feed_zip):
        index.add(c)
    res = ScanResult(inventory=inv, unresolved=list(inv.unresolved))
    deps = list(inv.dependencies)
    mapped: dict[tuple[str, str, str], mapping.Mapped] = {}
    if upstream_check:
        mapped = await mapping.map_all(http, deps)
        repos = {m.repo for m in mapped.values() if m.repo}
        due = {r for r in repos if not _fresh(watchlist.get(r), now)}
        polled = await upstream.poll(http, due)
        for c in polled.candidates:
            index.add(c)
        res.stats |= {
            "repos": len(repos),
            "repos_on_watchlist": len(repos) - len(due),
            "repos_polled": len(polled.polled),
        }
        for d in deps:
            m = mapped[(d.ecosystem, d.name, d.version)]
            if m.repo is None:
                res.unresolved.append(_partial(d, Unchecked.NO_REPO, m.method))
            elif m.repo in polled.not_polled:
                res.unresolved.append(_partial(d, Unchecked.REPO_NOT_POLLED, m.repo))
    go = [c for cs in index.by_repo.values() for c in cs if any(p.ecosystem == "go" for p in c.adv.packages)]
    for d in deps:
        found = mapped.get((d.ecosystem, d.name, d.version))
        res.findings += match(d, index, found.repo if found else None, go if d.ecosystem == "go" else None)
    res.findings.sort(key=lambda f: (f.dependency.source, f.dependency.line, f.dependency.name, f.ghsa_id))
    res.stats |= {"dependencies": len(deps), "feed_advisories": len(index.ids), "findings": len(res.findings)}
    return res


def _fresh(last: str | None, now: datetime) -> bool:
    if not last:
        return False
    return now - datetime.fromisoformat(last.replace("Z", "+00:00")) < STALE


def _partial(d: Dependency, reason: Unchecked, detail: str) -> UnresolvedDependency:
    return UnresolvedDependency(reason=reason, source=d.source, name=d.name, version=d.version, ecosystem=d.ecosystem,
                                detail=detail, line=d.line)  # fmt: skip


def watchlist_repos(data: bytes) -> dict[str, str]:
    return dict(json.loads(data).get("repos") or {})
