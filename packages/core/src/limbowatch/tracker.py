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

from limbowatch.classify import facts_hash, transitions
from limbowatch.http import BudgetExhausted, DeadlineReached, HttpClient
from limbowatch.models import CveInfo, Facts, RepoAdvisory
from limbowatch.normalize import ts
from limbowatch.sources import cve as cve_src
from limbowatch.sources import github, nvd, osv
from limbowatch.store import Advisory, Cve, Event, FactSnapshot, Nvd, Repo, Reviewed, Run, Store, now_iso

log = logging.getLogger(__name__)

REVIEW_OVERLAP = timedelta(days=2)  # re-read recent reviews: late edits, ties on the cursor
DELTA_BOOTSTRAP = timedelta(days=2)  # first run: only this much of the CVE delta log
RESERVED_RECHECK = timedelta(hours=20)
NVD_RECHECK = timedelta(days=7)
POLL_404_BACKOFF = timedelta(days=7)
POLL_WORKERS = 8


@dataclass
class TrackerConfig:
    seeds: list[Path] = field(default_factory=list)  # files with one owner/repo per line
    nvd: bool = True
    max_nvd: int = 150  # NVD lookups per run (6.5 s each without an API key)
    checkpoint: Callable[[], None] | None = None  # persist state; called after each step and every 500 polls
    checkpoint_every: int = 500


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
    events: list[str] = field(default_factory=list)
    http: dict[str, Any] = field(default_factory=dict)


def _iso(d: datetime | None) -> str | None:
    return d.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z") if d else None


def _parse(s: str | None) -> datetime | None:
    return ts(s)


class Tracker:
    def __init__(self, store: Store, http: HttpClient, cfg: TrackerConfig) -> None:
        self.store, self.http, self.cfg = store, http, cfg

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
        cna_repos = {r for i in keep if i.cna == "GitHub_M" for r in i.repo_refs}
        self.add_repos(cna_repos, "github-cna-cve")
        if entries:
            self.store.set_cursor("cve_delta", entries[-1].fetch_time)

    # ------------------------------------------------------------------ 3. polling
    def poll_order(self) -> list[Repo]:
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

        def key(r: Repo) -> tuple[int, str]:
            last = _parse(r.last_polled_at)
            if last is None:
                return (0, "")  # never polled
            if r.poll_status == 404 and now - last < POLL_404_BACKOFF:
                return (9, r.last_polled_at or "")
            if r.full_name in limbo_repos:
                return (1, r.last_polled_at or "")
            return (2, r.last_polled_at or "")  # oldest first

        return [r for r in sorted(repos, key=key) if key(r)[0] < 9]

    async def poll(self, report: RunReport) -> None:
        queue: asyncio.Queue[Repo] = asyncio.Queue()
        for r in self.poll_order():
            queue.put_nowait(r)
        stop: list[str] = []

        async def worker() -> None:
            while not stop and not queue.empty():
                repo = queue.get_nowait()
                etag = repo.etag if repo.etag_token == self.http.token_fingerprint else None
                try:
                    res = await github.repo_advisories(self.http, repo.full_name, etag)
                except BudgetExhausted:
                    stop.append("budget")
                    return
                except DeadlineReached:
                    stop.append("deadline")
                    return
                self._record_poll(repo.full_name, res, report)

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
        stale = [a.cve_id for a in open_ if a.cve_id and self._cve_stale(cves.get(a.cve_id), now)]
        fresh = await asyncio.gather(*(cve_src.lookup(self.http, c) for c in sorted(set(stale))))
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
            evs = transitions(Facts.model_validate(old) if old else None, f)
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

    # ------------------------------------------------------------------ run
    def _checkpoint(self) -> None:
        if self.cfg.checkpoint:
            self.cfg.checkpoint()

    async def run(self) -> RunReport:
        report = RunReport(started_at=now_iso())
        t0 = time.monotonic()
        self.load_seeds()
        for step in (self.sync_reviewed, self.sync_cve_delta):
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
