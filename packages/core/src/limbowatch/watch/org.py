"""Org-wide mode (`limbowatch watch`): every project of some GitLab groups, Gitea orgs, GitHub orgs or git URLs,
in one run.

1. List the sources' projects (hosts.gitlab, hosts.gitea, hosts.github; plain git URLs as given).
2. Clone each shallowly into a temporary directory and take its inventory, a few at a time; the clone is
   removed as soon as the inventory is read.
3. Map and poll the upstream repos of all projects' dependencies together (`scan.prepare`), so each upstream
   repo costs one poll per run however many projects use it (PHASE0_PLAN §7).
4. Match each project on its own (`scan.assess`).

Nothing is dropped: a project that can't be cloned or inventoried comes back with the error, and one that
isn't checked (archived, empty, excluded) with the reason. An empty repository is found when it's cloned (no
commit checked out): GitHub has no reliable flag for it (F-147), and a plain git URL has none at all.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from limbowatch.hosts import Listing, Project, Skip, excluded
from limbowatch.hosts import git as git_host
from limbowatch.http import HttpClient
from limbowatch.models import Dependency, Inventory
from limbowatch.watch.scan import ScanResult, Shared, assess, prepare

InventoryFn = Callable[[Path], Inventory]
CloneFn = Callable[[Project, Path, str | None], str]


@dataclass
class Checked:
    project: Project
    commit: str | None = None
    result: ScanResult | None = None
    error: str | None = None  # couldn't be cloned or inventoried: nothing about it was judged
    empty: bool = False  # cloned, but the repository has no commits: reported as not checked


@dataclass
class Watch:
    listings: list[Listing]
    checked: list[Checked] = field(default_factory=list)
    skipped: list[tuple[Project, Skip]] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    @property
    def errors(self) -> list[str]:
        """Sources that couldn't be listed (completely)."""
        return [ls.error for ls in self.listings if ls.error]


def select(listings: list[Listing], exclude: list[str]) -> tuple[list[Project], list[tuple[Project, Skip]]]:
    """The projects to check, once each (a project in two listed groups is checked once), and the rest."""
    seen: set[str] = set()
    todo: list[Project] = []
    skipped: list[tuple[Project, Skip]] = []
    for ls in listings:
        for p, why in ls.skipped:
            if p.name not in seen:
                seen.add(p.name)
                skipped.append((p, why))
        for p in ls.projects:
            if p.name in seen:
                continue
            seen.add(p.name)
            if excluded(p, exclude):
                skipped.append((p, Skip.EXCLUDED))
            else:
                todo.append(p)
    return sorted(todo, key=lambda p: p.name), sorted(skipped, key=lambda s: s[0].name)


async def take_inventories(
    projects: list[Project],
    token: str | None,
    inventory: InventoryFn,
    *,
    jobs: int = 4,
    clone: CloneFn = git_host.clone,
) -> list[tuple[Checked, Inventory | None]]:
    sem = asyncio.Semaphore(max(1, jobs))

    def one(p: Project) -> tuple[Checked, Inventory | None]:
        tmp = Path(tempfile.mkdtemp(prefix="limbowatch-clone-"))
        try:
            dest = tmp / "repo"
            try:
                commit = clone(p, dest, token)
            except git_host.CloneError as e:
                return Checked(p, error=f"clone failed: {e}"), None
            if not commit:
                return Checked(p, empty=True), None
            try:
                return Checked(p, commit=commit), inventory(dest)
            except Exception as e:
                return Checked(p, commit=commit, error=f"inventory failed: {e}"), None
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    async def guarded(p: Project) -> tuple[Checked, Inventory | None]:
        async with sem:
            return await asyncio.to_thread(one, p)

    return list(await asyncio.gather(*(guarded(p) for p in projects)))


async def run(
    listings: list[Listing],
    http: HttpClient,
    *,
    feed_zip: bytes,
    watchlist: dict[str, str],
    now: datetime,
    inventory: InventoryFn,
    token: str | None,
    exclude: list[str] | None = None,
    upstream_check: bool = True,
    jobs: int = 4,
    clone: CloneFn = git_host.clone,
    git_cache: Path | None = None,
    osv_commits: bool = True,
) -> Watch:
    out = Watch(listings)
    for ls in listings:
        if not (ls.error or ls.projects or ls.skipped):
            # Gitea answers a private org it won't show with 200 and no repos (F-129): never read that as "nothing
            # to check"
            ls.error = f"{ls.source} lists no projects: it's empty, or private (LIMBOWATCH_SOURCE_TOKEN reads it)"
    todo, out.skipped = select(listings, exclude or [])
    taken: list[tuple[Checked, Inventory | None]] = []
    for checked, inv in await take_inventories(todo, token, inventory, jobs=jobs, clone=clone):
        if checked.empty:
            out.skipped.append((checked.project, Skip.EMPTY))
        else:
            taken.append((checked, inv))
    out.skipped.sort(key=lambda s: s[0].name)
    deps: dict[tuple[str, str, str], Dependency] = {}
    for _, inv in taken:
        for d in inv.dependencies if inv else ():
            deps.setdefault((d.ecosystem, d.name, d.version), d)
    ups = list(dict.fromkeys(u for _, inv in taken if inv for u in inv.upstreams))
    sh: Shared = await prepare(list(deps.values()), http, feed_zip=feed_zip, watchlist=watchlist, now=now,
                               upstream_check=upstream_check, upstreams=ups, git_cache=git_cache,
                               osv_commits=osv_commits)  # fmt: skip
    for checked, inv in taken:
        if inv is not None:
            checked.result = assess(inv, sh)
        out.checked.append(checked)
    repos = {m.repo for m in sh.mapped.values() if m.repo}
    out.stats = {
        "projects": len(taken),  # selected and cloned; empty ones are counted as not checked
        "projects_checked": sum(1 for c in out.checked if c.result is not None),
        "projects_failed": sum(1 for c in out.checked if c.error),
        "projects_skipped": len(out.skipped),
        "dependencies": sum(len(inv.dependencies) for _, inv in taken if inv),
        "unique_dependencies": len(deps),
        "repos": len(repos),
        "repos_on_watchlist": len(sh.on_watchlist),
        "repos_polled": len(sh.polled),
        "repos_not_polled": len(sh.not_polled),
        "feed_advisories": len(sh.index.ids),
    }
    return out
