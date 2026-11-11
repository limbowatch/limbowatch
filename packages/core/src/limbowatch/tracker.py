"""The live tracker: one run = sync, poll within a budget, assess, record changes.

Watchlist (PHASE0_PLAN §7a): repos where reviewed advisories originated, seed files
(dependency upstreams of popular projects), repos named by new GitHub-CNA CVEs, and any repo
found publishing an advisory. Coverage is reported honestly: every number is a floor.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select

from limbowatch import schedule
from limbowatch.classify import facts_hash, transitions
from limbowatch.ecosystems import info as eco_info
from limbowatch.ecosystems import package_name
from limbowatch.http import BudgetExhausted, DeadlineReached, HttpClient
from limbowatch.models import GITHUB_CNA, CveInfo, Facts, RepoAdvisory
from limbowatch.normalize import LINK_RULE, ts
from limbowatch.sources import cve as cve_src
from limbowatch.sources import github, gitrefs, goproxy, nvd, osv, releases
from limbowatch.store import (
    Advisory,
    Cve,
    Event,
    FactSnapshot,
    GitTag,
    GoModule,
    Nvd,
    PackageMeta,
    Repo,
    Reviewed,
    Run,
    Store,
    now_iso,
)
from limbowatch.versions import tag_for

log = logging.getLogger(__name__)

REVIEW_OVERLAP = timedelta(days=2)  # re-read recent reviews: late edits, ties on the cursor
DELTA_BOOTSTRAP = timedelta(days=2)  # first run: only this much of the CVE delta log
RESERVED_RECHECK = timedelta(hours=20)
NVD_RECHECK = timedelta(days=7)
POLL_WORKERS = 8
# Go module lookups (F-113): a path's module rarely changes, so each is re-checked twice a year. The first pass over
# the stored advisories takes about 2,500 proxy requests; later runs only look up new paths.
GO_MODULE_RECHECK = timedelta(days=180)
GO_MODULE_MAX_REQUESTS = 4000
GO_MODULE_WORKERS = 8
# Tags of repos whose advisories in limbo name no package, listed again every run (F-138, F-141): at most
# GIT_TAG_MAX_REPOS repos a run, GIT_TAG_WORKERS at a time.
GIT_TAG_MAX_REPOS = 3000
GIT_TAG_WORKERS = 16


@dataclass
class TrackerConfig:
    seeds: list[Path] = field(default_factory=list)  # files with one owner/repo per line
    nvd: bool = True
    max_nvd: int = 150  # NVD lookups per run (6.5 s each without an API key)
    checkpoint: Callable[[], None] | None = None  # persist state; called after each step and every 500 polls
    checkpoint_every: int = 500
    # First-time polls per run. Never-checked repos outrank anything merely due, so a large seed list would
    # otherwise use the whole budget for days and starve the daily re-checks of repos with advisories in limbo.
    max_new: int | None = None
    # Release-triggered checks (docs/RELEASE_CHECKS.md): collect releases since the last run and check a repo after
    # its package releases. Packages not yet watched join the watchlist when this many repositories depend on them.
    releases: bool = False
    release_min_dependents: int | None = 100
    # Watched Maven packages (`group:artifact` -> owner/repo), polled on Maven Central once a day (F-108)
    maven_packages: dict[str, str] = field(default_factory=dict)


@dataclass
class RunReport:
    started_at: str
    finished_at: str = ""
    stopped_early: str | None = None  # "budget" / "deadline" when polling didn't finish
    reviewed_synced: int = 0
    cve_records_seen: int = 0
    watchlist: int = 0
    polled: int = 0
    not_modified: int = 0
    new_advisories: int = 0
    assessed: int = 0
    changed: int = 0
    # CVE records read again because they were stored under an older normalize.LINK_RULE (F-120)
    cves_relinked: int = 0
    # Polls per schedule tier ("new" for first checks) by outcome: "304", "200", "404", "other", and "no_etag" for
    # polls sent without a usable ETag (never polled with this token), which can't come back 304. Shows where the
    # budget goes (FINDINGS F-100).
    by_tier: dict[str, dict[str, int]] = field(default_factory=dict)
    # Per release feed: releases collected, how many hit a watched repo, repos added, and whether the feed reached
    # the previous run (docs/RELEASE_CHECKS.md).
    releases: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Go advisory paths and their modules (F-113): paths named, due, resolved this run, "in_module" (a package inside
    # a shorter module), "no_module" (no prefix is a module), failed, and proxy requests
    go_modules: dict[str, int] = field(default_factory=dict)
    git_tags: dict[str, int] = field(default_factory=dict)
    events: list[str] = field(default_factory=list)
    http: dict[str, Any] = field(default_factory=dict)


def _iso(d: datetime | None) -> str | None:
    return d.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z") if d else None


def _parse(s: str | None) -> datetime | None:
    return ts(s)


def _cna_repos(records: list[dict[str, Any]]) -> set[str]:
    """Repos named by CVE records; github.com/advisories/GHSA-... links parse as owner "advisories"."""
    return {r for rec in records for r in rec.get("repo_refs", []) if not r.startswith("advisories/")}


class Tracker:
    def __init__(self, store: Store, http: HttpClient, cfg: TrackerConfig) -> None:
        self.store, self.http, self.cfg = store, http, cfg
        self._tier: dict[str, str] = {}  # schedule tier per repo, set by poll_order, for RunReport.by_tier

    # ------------------------------------------------------------------ watchlist
    def add_repos(self, repos: set[str], source: str) -> int:
        added = 0
        with self.store.session() as s:
            existing = {r.full_name: r for r in s.execute(select(Repo).where(Repo.full_name.in_(repos))).scalars()}
            for name in sorted(repos):
                r = existing.get(name)
                if r is None:
                    s.add(Repo(full_name=name, sources=[source], first_seen=now_iso()))
                    added += 1
                elif source not in r.sources:
                    r.sources = sorted({*r.sources, source})
        return added

    def load_seeds(self) -> None:
        for path in self.cfg.seeds:
            names = {
                ln.strip().lower()
                for ln in path.read_text().splitlines()
                if ln.strip() and not ln.startswith("#") and ln.count("/") == 1
            }
            n = self.add_repos(names, f"seed:{path.stem}")
            log.info("seed loaded", extra={"seed": path.name, "repos": len(names), "new": n})

    def watch_cna_repos(self) -> int:
        """Watch every repo named by a stored GitHub-CNA CVE. The CVE delta sync adds these as CVEs arrive;
        this also covers CVEs stored by the bulk import, which adds none (F-066). Idempotent."""
        with self.store.session() as s:
            refs = [c.data for c in s.execute(select(Cve)).scalars() if c.data.get("cna") == GITHUB_CNA]
        n = self.add_repos(_cna_repos(refs), "github-cna-cve")
        log.info("github-cna repos", extra={"new": n})
        return n

    # ------------------------------------------------------------------ 1. reviewed list
    async def sync_reviewed(self, report: RunReport) -> None:
        cursor = _parse(self.store.cursor("reviewed_at"))
        since = cursor - REVIEW_OVERLAP if cursor else None
        newest = cursor
        origins: set[str] = set()
        batch: list[Reviewed] = []
        async for e in github.reviewed_since(self.http, since):
            batch.append(
                Reviewed(ghsa_id=e.ghsa_id, cve_id=e.cve_id, reviewed_at=_iso(e.reviewed_at), origin_repo=e.origin_repo)
            )
            if e.origin_repo:
                origins.add(e.origin_repo)
            if e.reviewed_at and (newest is None or e.reviewed_at > newest):
                newest = e.reviewed_at
            if len(batch) >= 500:
                self._merge(batch)
                batch = []
        self._merge(batch)
        report.reviewed_synced += len(batch)
        if newest:
            self.store.set_cursor("reviewed_at", _iso(newest) or "")
        self.add_repos(origins, "reviewed-origin")

    def _merge(self, rows: list[Any]) -> None:
        if rows:
            with self.store.session() as s:
                for r in rows:
                    s.merge(r)

    # ------------------------------------------------------------------ 2. CVE delta log
    async def sync_cve_delta(self, report: RunReport) -> None:
        cursor = self.store.cursor("cve_delta")
        if cursor is None:
            cursor = _iso(datetime.now(UTC) - DELTA_BOOTSTRAP)
        entries = await cve_src.delta_since(self.http, cursor)
        latest: dict[str, cve_src.DeltaEntry] = {e.cve_id: e for e in entries}  # last change per CVE
        sem = asyncio.Semaphore(8)

        async def fetch(e: cve_src.DeltaEntry) -> CveInfo | None:
            async with sem:
                return await cve_src.record(self.http, e.record_url)

        infos = await asyncio.gather(*(fetch(e) for e in latest.values()))
        keep = [i for i in infos if i is not None and i.ghsa_refs]
        report.cve_records_seen = len(latest)
        self._merge([Cve(cve_id=i.cve_id, data=i.model_dump(mode="json"), fetched_at=now_iso()) for i in keep])
        self.add_repos(_cna_repos([i.model_dump() for i in keep if i.cna == GITHUB_CNA]), "github-cna-cve")
        if entries:
            self.store.set_cursor("cve_delta", entries[-1].fetch_time)

    # ------------------------------------------------------------------ 3. polling
    def poll_order(self) -> list[Repo]:
        """Repos due for a check, most overdue first (limbowatch.schedule)."""
        now = datetime.now(UTC)
        with self.store.session() as s:
            repos = list(s.execute(select(Repo)).scalars())
            reviewed = set(s.execute(select(Reviewed.ghsa_id)).scalars())
            # repos with an advisory currently in limbo are re-polled first: that's where changes matter
            limbo_repos = {
                a.repo
                for a in s.execute(select(Advisory).where(Advisory.gone_since.is_(None))).scalars()
                if a.data.get("state") == "published" and a.ghsa_id not in reviewed
            }

        by_name = {r.full_name: r for r in repos}
        self._tier = {
            r.full_name: "new"
            if r.last_polled_at is None
            else "release"
            if schedule.release_due(_parse(r.last_polled_at), _parse(r.released_at), now)
            else schedule.tier(r.full_name in limbo_repos, r.advisory_count, r.poll_status).name.lower()
            for r in repos
        }
        scores = [
            (
                r.full_name,
                schedule.overdue(
                    schedule.tier(r.full_name in limbo_repos, r.advisory_count, r.poll_status),
                    _parse(r.last_polled_at),
                    _parse(r.first_seen),
                    now,
                    _parse(r.released_at),
                ),
            )
            for r in repos
        ]
        order = [by_name[n] for n in schedule.due_order(scores)]
        if self.cfg.max_new is None:
            return order
        new = [r for r in order if r.last_polled_at is None][: self.cfg.max_new]
        keep = {r.full_name for r in new}
        return [r for r in order if r.last_polled_at is not None or r.full_name in keep]

    async def poll(self, report: RunReport) -> None:
        queue: asyncio.Queue[Repo] = asyncio.Queue()
        for r in self.poll_order():
            queue.put_nowait(r)
        stop: list[str] = []

        async def worker() -> None:
            while not stop and not queue.empty():
                repo = queue.get_nowait()
                etag = repo.etag if repo.etag_token == self.http.token_fingerprint else None
                tally = report.by_tier.setdefault(self._tier.get(repo.full_name, "unknown"), {})
                if etag is None:
                    tally["no_etag"] = tally.get("no_etag", 0) + 1
                try:
                    res = await github.repo_advisories(self.http, repo.full_name, etag)
                except BudgetExhausted:
                    stop.append("budget")
                    return
                except DeadlineReached:
                    stop.append("deadline")
                    return
                outcome = str(res.status) if res.status in (200, 304, 404) else "other"
                tally[outcome] = tally.get(outcome, 0) + 1
                before = report.new_advisories
                self._record_poll(repo.full_name, res, report)  # synchronous: no other worker runs in between
                if report.new_advisories > before:  # what each tier finds: release-triggered vs routine checks
                    tally["new_advisories"] = tally.get("new_advisories", 0) + report.new_advisories - before

        await asyncio.gather(*(worker() for _ in range(POLL_WORKERS)))
        report.stopped_early = stop[0] if stop else None

    def _record_poll(self, name: str, res: github.RepoPoll, report: RunReport) -> None:
        now = now_iso()
        report.polled += 1
        if self.cfg.checkpoint and report.polled % self.cfg.checkpoint_every == 0:
            self.cfg.checkpoint()
        with self.store.session() as s:
            repo = s.get(Repo, name)
            if repo is None:
                return
            repo.last_polled_at, repo.poll_status = now, res.status
            if res.status == 304:
                report.not_modified += 1
                return
            if res.advisories is None:
                return
            repo.etag, repo.etag_token = res.etag, self.http.token_fingerprint
            repo.advisory_count = len(res.advisories)
            seen = {a.ghsa_id for a in res.advisories}
            # The repo may have been renamed: advisories carry their canonical repo, and the same
            # advisory can arrive via an old name and the new one (F-060). Key on the GHSA ID.
            owners = {name} | {a.repo for a in res.advisories}
            rows = s.execute(select(Advisory).where(Advisory.repo.in_(owners) | Advisory.ghsa_id.in_(seen))).scalars()
            known = {a.ghsa_id: a for a in rows}
            for adv in res.advisories:
                row = known.get(adv.ghsa_id)
                data = adv.model_dump(mode="json")
                if row is None:
                    row = Advisory(ghsa_id=adv.ghsa_id, repo=adv.repo, data=data, first_seen=now, last_seen=now)
                    s.add(row)
                    known[adv.ghsa_id] = row
                    report.new_advisories += 1
                else:
                    row.repo, row.data, row.last_seen, row.gone_since = adv.repo, data, now, None
            for ghsa, row in known.items():
                if ghsa not in seen and row.repo in owners and row.gone_since is None:
                    row.gone_since = now

    # ------------------------------------------------------------------ 4. assess
    async def assess(self, report: RunReport) -> None:
        with self.store.session() as s:
            advisories = [
                (RepoAdvisory.model_validate(a.data), a.gone_since is not None)
                for a in s.execute(select(Advisory)).scalars()
            ]
            reviewed = {r.ghsa_id: r for r in s.execute(select(Reviewed)).scalars()}
            by_cve: dict[str, list[str]] = {}
            for r in reviewed.values():
                if r.cve_id:
                    by_cve.setdefault(r.cve_id, []).append(r.ghsa_id)
            cves = {c.cve_id: c for c in s.execute(select(Cve)).scalars()}
            nvds = {n.cve_id: n for n in s.execute(select(Nvd)).scalars()}
        previous = self.store.latest_facts()
        # Assess what isn't reviewed, plus anything we've been tracking (to record its transition).
        todo = [(a, gone) for a, gone in advisories if a.ghsa_id not in reviewed or a.ghsa_id in previous]
        open_ = [a for a, gone in todo if a.ghsa_id not in reviewed and a.state == "published" and not gone]

        # OSV presence and cited CVEs, for unreviewed published advisories only
        sem = asyncio.Semaphore(16)

        async def in_osv(g: str) -> bool | None:
            async with sem:
                return await osv.present(self.http, g)

        osv_state = dict(
            zip([a.ghsa_id for a in open_], await asyncio.gather(*(in_osv(a.ghsa_id) for a in open_)), strict=True)
        )
        now = datetime.now(UTC)
        stale = sorted({a.cve_id for a in open_ if a.cve_id and self._cve_stale(cves.get(a.cve_id), now)})
        # A record stored under an older LINK_RULE may link an advisory it only mentions (F-120). Where that link
        # would count, as an uncited CVE or a duplicate, read the record again.
        cited = {a.ghsa_id.upper(): a.cve_id for a, _ in todo}
        relink = sorted(
            c.cve_id
            for c in cves.values()
            if c.data.get("link_rule", 0) < LINK_RULE
            and c.cve_id not in stale
            and any(g in cited and cited[g] != c.cve_id for g in c.data.get("ghsa_refs", []))
        )
        cve_sem = asyncio.Semaphore(8)

        async def lookup(c: str) -> CveInfo:
            async with cve_sem:
                return await cve_src.lookup(self.http, c)

        fresh = list(await asyncio.gather(*(lookup(c) for c in stale)))
        # only a full record replaces a stored one: a failed lookup mustn't erase its links
        relinked = [i for i in await asyncio.gather(*(lookup(c) for c in relink)) if i.link_rule == LINK_RULE]
        report.cves_relinked = len(relinked)
        fresh += relinked
        self._merge([Cve(cve_id=i.cve_id, data=i.model_dump(mode="json"), fetched_at=now_iso()) for i in fresh])
        cves.update(
            {i.cve_id: Cve(cve_id=i.cve_id, data=i.model_dump(mode="json"), fetched_at=now_iso()) for i in fresh}
        )
        refs: dict[str, list[str]] = {}
        for c in cves.values():
            if c.data.get("state") == "PUBLISHED":
                for g in c.data.get("ghsa_refs", []):
                    refs.setdefault(g, []).append(c.cve_id)

        if self.cfg.nvd:
            await self._refresh_nvd(open_, cves, nvds, now)

        changed = 0
        for adv, gone in todo:
            info = cves.get(adv.cve_id or "")
            uncited = sorted(c for c in refs.get(adv.ghsa_id.upper(), []) if c != adv.cve_id)
            linked = [c for c in [adv.cve_id, *uncited] if c]
            dup = sorted({g for c in linked for g in by_cve.get(c, []) if g != adv.ghsa_id})
            n = nvds.get(adv.cve_id or "")
            rv = reviewed.get(adv.ghsa_id)
            f = Facts(
                ghsa_id=adv.ghsa_id,
                repo=adv.repo,
                repo_state="gone" if gone else adv.state,
                reviewed=rv is not None,
                reviewed_at=_parse(rv.reviewed_at) if rv else None,
                in_osv=osv_state.get(adv.ghsa_id),
                cited_cve=adv.cve_id,
                cited_cve_state=info.data.get("state") if info else None,
                cited_cve_cna=info.data.get("cna") if info else None,
                uncited_cves=tuple(uncited),
                duplicate_of=tuple(dup),
                nvd_status=n.status if n else None,
                nvd_enriched=n.enriched if n else None,
            )
            old = previous.get(adv.ghsa_id)
            h = facts_hash(f)
            if old is not None and facts_hash(Facts.model_validate(old)) == h:
                continue
            cnas = {c: cves[c].data.get("cna") if c in cves else None for c in uncited}
            evs = transitions(Facts.model_validate(old) if old else None, f, cnas)
            with self.store.session() as s:
                s.add(
                    FactSnapshot(
                        ghsa_id=adv.ghsa_id, observed_at=now_iso(), facts=f.model_dump(mode="json"), facts_hash=h
                    )
                )
                s.add_all(Event(ghsa_id=adv.ghsa_id, at=now_iso(), event=e) for e in evs)
            changed += 1
            report.events += [f"{adv.ghsa_id}: {e}" for e in evs if e != "first seen"]
        report.assessed, report.changed = len(todo), changed

    @staticmethod
    def _cve_stale(row: Cve | None, now: datetime) -> bool:
        if row is None:
            return True
        state = row.data.get("state")
        fetched = _parse(row.fetched_at) or now
        return state in ("RESERVED", "unknown") and now - fetched > RESERVED_RECHECK

    async def _refresh_nvd(
        self, open_: list[RepoAdvisory], cves: dict[str, Cve], nvds: dict[str, Nvd], now: datetime
    ) -> None:
        want = [
            a.cve_id
            for a in open_
            if a.cve_id
            and cves.get(a.cve_id)
            and cves[a.cve_id].data.get("state") == "PUBLISHED"
            and (a.cve_id not in nvds or now - (_parse(nvds[a.cve_id].fetched_at) or now) > NVD_RECHECK)
        ]
        for c in sorted(set(want))[: self.cfg.max_nvd]:
            try:
                st = await nvd.status(self.http, c)
            except DeadlineReached:
                return
            if st is not None:
                row = Nvd(cve_id=c, status=st.status, enriched=st.enriched, fetched_at=now_iso())
                self._merge([row])
                nvds[c] = row

    # ------------------------------------------------------------------ releases
    async def collect_releases(self, report: RunReport) -> None:
        """Releases since the last run, from every feed: mark watched repos as released, and add the repos of
        packages enough projects depend on. Feeds run in parallel; one failing doesn't stop the others."""
        now = datetime.now(UTC)
        first = now - timedelta(days=1)

        def since(name: str) -> datetime:
            return _parse(self.store.cursor(f"releases:{name}")) or first

        maven_last = _parse(self.store.cursor("releases:maven-central"))
        maven_due = bool(self.cfg.maven_packages) and (
            maven_last is None or now - maven_last >= releases.MAVEN_INTERVAL
        )
        with self.store.session() as s:
            meta = {
                m.key.removeprefix("maven:"): (m.etag, m.updated)
                for m in s.execute(select(PackageMeta).where(PackageMeta.key.startswith("maven:"))).scalars()
            } if maven_due else {}  # fmt: skip

        async def maven() -> releases.Feed:
            poll = await releases.maven_central(self.http, self.cfg.maven_packages, meta, maven_last or first)
            with self.store.session() as s:
                for package, (etag, updated) in poll.meta.items():
                    if (etag, updated) != meta.get(package):
                        s.merge(PackageMeta(key=f"maven:{package}", etag=etag, updated=updated))
            report.releases["maven-central:polled"] = {
                "packages": len(self.cfg.maven_packages), "not_found": poll.not_found, "failed": poll.failed,
            }  # fmt: skip
            return poll.feed

        feeds = await asyncio.gather(
            *(
                releases.ecosystems(self.http, reg, since(reg), releases.ECOSYSTEMS_OVERLAP)
                for reg in releases.ECOSYSTEMS_REGISTRIES
            ),
            releases.go_index(self.http, since("proxy.golang.org")),
            releases.packagist(self.http, since("packagist.org")),
            *([maven()] if maven_due else []),
            return_exceptions=True,
        )
        with self.store.session() as s:
            watched = {r.full_name: r for r in s.execute(select(Repo)).scalars()}
        for feed in feeds:
            if isinstance(feed, BaseException):
                if isinstance(feed, BudgetExhausted | DeadlineReached):
                    raise feed
                report.releases[type(feed).__name__] = {"error": str(feed)[:200]}
                continue
            hit: dict[str, datetime] = {}
            new: set[str] = set()
            for rel in feed.releases:
                # Packagist names packages, not repos: a watched repo with the same owner/name is the match
                repo = rel.repo or (rel.package.lower() if feed.source == "packagist.org" else None)
                if not repo:
                    continue
                if repo in watched or repo in new:
                    hit[repo] = max(hit.get(repo, rel.published_at), rel.published_at)
                elif (
                    self.cfg.release_min_dependents is not None
                    and rel.repo
                    and (rel.dependents or 0) >= self.cfg.release_min_dependents
                ):
                    new.add(repo)
                    hit[repo] = max(hit.get(repo, rel.published_at), rel.published_at)
            if new:
                self.add_repos(new, f"release:{feed.source}")
            with self.store.session() as s:
                for row in s.execute(select(Repo).where(Repo.full_name.in_(hit))).scalars():
                    stamp = _iso(hit[row.full_name])
                    if stamp and (row.released_at is None or stamp > row.released_at):
                        row.released_at = stamp
            report.releases[feed.source] = {
                "releases": len(feed.releases), "watched": len(hit) - len(new), "added": len(new),
                "complete": feed.complete, "newest": _iso(feed.newest),  # a stale "newest" means the feed lags
            }  # fmt: skip
            # A complete feed moves on to its own position (now for Packagist); a partial one keeps its place
            if feed.complete:
                self.store.set_cursor(f"releases:{feed.source}", feed.cursor or _iso(now) or "")
        log.info("releases collected", extra={"feeds": report.releases})

    # ------------------------------------------------------------------ Go modules
    async def resolve_go_modules(self, report: RunReport) -> None:
        """Which module contains each Go package path the stored advisories name, per the Go module proxy (F-113).
        New paths first, then paths last checked more than GO_MODULE_RECHECK ago; at most GO_MODULE_MAX_REQUESTS."""
        now = datetime.now(UTC)
        with self.store.session() as s:
            checked = {g.path: g.checked_at for g in s.execute(select(GoModule)).scalars()}
            paths: set[str] = set()
            for a in s.execute(select(Advisory)).scalars():
                for p in a.data.get("packages") or []:
                    if p.get("ecosystem") == "go" and (n := package_name("go", p.get("name"))) is not None and n.valid:
                        paths.add(n.name)
        due = sorted(p for p in paths if p not in checked or (_parse(checked[p]) or now) <= now - GO_MODULE_RECHECK)
        due.sort(key=lambda p: p in checked)  # never-checked paths first
        resolver = goproxy.Resolver(self.http)
        results: dict[str, str | None] = {}
        failed = 0
        queue = list(reversed(due))

        async def worker() -> None:
            nonlocal failed
            while queue and resolver.requests < GO_MODULE_MAX_REQUESTS:
                path = queue.pop()
                module, complete = await resolver.module_of(path)
                if complete:
                    results[path] = module
                else:
                    failed += 1

        await asyncio.gather(*(worker() for _ in range(GO_MODULE_WORKERS)))
        stamp = now_iso()
        with self.store.session() as s:
            for path, module in results.items():
                s.merge(GoModule(path=path, module=module, checked_at=stamp))
        report.go_modules = {
            "paths": len(paths),
            "due": len(due),
            "resolved": len(results),
            "in_module": sum(1 for p, m in results.items() if m and m != p),
            "no_module": sum(1 for m in results.values() if m is None),
            "failed": failed,
            "requests": resolver.requests,
        }

    # ------------------------------------------------------------------ tags of unpackaged advisories
    async def resolve_git_tags(self, report: RunReport) -> None:
        """For advisories in limbo that name no package OSV knows (C/C++ and the like), the commit of each version
        their ranges give, by `git ls-remote` on the repo (no API quota; F-136). The feed turns them into OSV GIT
        ranges (F-138). Every repo is listed again each run, never-listed ones first (F-141)."""
        from limbowatch.classify import assess as assess_one
        from limbowatch.models import Status
        from limbowatch.publish.feed import git_versions

        latest = self.store.latest_facts()
        needed: dict[str, set[str]] = {}
        with self.store.session() as s:
            stored = {g.repo: (g.versions or {}, g.checked_at) for g in s.execute(select(GitTag)).scalars()}
            for a in s.execute(select(Advisory)).scalars():
                if a.gone_since or a.ghsa_id not in latest:
                    continue
                adv = RepoAdvisory.model_validate(a.data)
                unpackaged = [p for p in adv.packages if package_name(p.ecosystem, p.name) is None
                              or eco_info(p.ecosystem).osv is None]  # fmt: skip
                if (
                    not unpackaged
                    or assess_one(adv, Facts.model_validate(latest[a.ghsa_id])).status is not Status.LIMBO
                ):
                    continue
                for p in unpackaged:
                    needed.setdefault(adv.repo, set()).update(git_versions(p))

        # Every repo is listed again each run (1,900 repos took 47 s, F-138): tags move, and a better tag reading
        # (F-141) must replace an old one. Never-listed repos first, then the longest unchecked (the queue pops from
        # its end); at most GIT_TAG_MAX_REPOS.
        def order(repo: str) -> str:
            return stored[repo][1] or "" if repo in stored else ""

        queue = sorted((r for r in needed if needed[r]), key=order, reverse=True)[-GIT_TAG_MAX_REPOS:]
        results: dict[str, dict[str, Any]] = {}
        failed = 0

        stopped = False

        async def worker() -> None:
            nonlocal failed, stopped
            while queue:
                if self.http.deadline is not None and time.monotonic() > self.http.deadline:
                    stopped = True  # keep what's listed so far; the next run goes on (F-142)
                    return
                repo = queue.pop()
                listed = await gitrefs.tags(f"https://github.com/{repo}.git")
                if listed is None:
                    failed += 1
                    continue
                have: dict[str, Any] = {}  # this listing's reading replaces the stored one
                for v in needed[repo]:
                    tag = tag_for(v, listed)
                    have[v] = [tag, listed[tag]] if tag else None
                results[repo] = have

        await asyncio.gather(*(worker() for _ in range(GIT_TAG_WORKERS)))
        stamp = now_iso()
        with self.store.session() as s:
            for repo, versions in results.items():
                s.merge(GitTag(repo=repo, versions=versions, checked_at=stamp))
        report.git_tags = {
            "repos": len(needed),
            "listed": len(results),
            "failed": failed,
            "versions": sum(len(v) for v in needed.values()),
            "tagged": sum(1 for r in results.values() for x in r.values() if x),
        }
        if stopped:
            raise DeadlineReached

    # ------------------------------------------------------------------ run
    def _checkpoint(self) -> None:
        if self.cfg.checkpoint:
            self.cfg.checkpoint()

    async def run(self) -> RunReport:
        report = RunReport(started_at=now_iso())
        t0 = time.monotonic()
        self.load_seeds()
        self.watch_cna_repos()
        steps = [self.sync_reviewed, self.sync_cve_delta] + ([self.collect_releases] if self.cfg.releases else [])
        for step in steps:
            try:
                await step(report)
            except (BudgetExhausted, DeadlineReached) as e:
                report.stopped_early = type(e).__name__
            self._checkpoint()
        if report.stopped_early is None:
            await self.poll(report)
            self._checkpoint()
        try:
            await self.assess(report)
        except (BudgetExhausted, DeadlineReached) as e:
            report.stopped_early = report.stopped_early or type(e).__name__
        try:
            await self.resolve_go_modules(report)
        except DeadlineReached:
            report.stopped_early = report.stopped_early or "DeadlineReached"
        try:
            await self.resolve_git_tags(report)
        except DeadlineReached:
            report.stopped_early = report.stopped_early or "DeadlineReached"
        self._checkpoint()
        with self.store.session() as s:
            report.watchlist = len(list(s.execute(select(Repo.full_name)).scalars()))
        report.finished_at = now_iso()
        report.http = {
            "requests": self.http.stats.requests,
            "github_counted": self.http.stats.github_counted,
            "github_not_modified": self.http.stats.github_not_modified,
            "failures": self.http.stats.failures,
            "seconds": round(time.monotonic() - t0),
        }
        with self.store.session() as s:
            s.add(
                Run(
                    started_at=report.started_at,
                    finished_at=report.finished_at,
                    stats={k: v for k, v in report.__dict__.items() if k != "events"} | {"events": len(report.events)},
                )
            )
        return report


def import_cve_list(store: Store, release_zip: Path, workdir: Path) -> int:
    """Bootstrap: every CVE in a bulk CVE List release that references a GHSA. Finds uncited CVEs that
    other CNAs (mostly VulnCheck) assigned before the tracker started (F-050)."""
    n = 0
    batch: list[Cve] = []
    for info in cve_src.bulk_records(release_zip, workdir):
        batch.append(Cve(cve_id=info.cve_id, data=info.model_dump(mode="json"), fetched_at=now_iso()))
        if len(batch) >= 1000:
            with store.session() as s:
                for row in batch:
                    s.merge(row)
            n, batch = n + len(batch), []
    with store.session() as s:
        for row in batch:
            s.merge(row)
    store.set_cursor("cve_bulk", release_zip.name)
    return n + len(batch)
