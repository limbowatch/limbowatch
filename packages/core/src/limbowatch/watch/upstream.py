"""Polling a dependency's source repo directly, for repos the tracker doesn't watch or hasn't checked lately.

The same facts as the tracker's, from the same sources: the repo's published advisories, OSV for
"reviewed" (an advisory in OSV is one scanners already see, F-055), and CVE Services for the state of
a cited CVE. Uncited CVEs and duplicates need the CVE List, so they aren't detected here; the feed
carries them for watched repos.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from limbowatch.classify import assess
from limbowatch.http import BudgetExhausted, HttpClient
from limbowatch.models import Facts, Status
from limbowatch.sources import cve, github, osv
from limbowatch.watch.candidates import Candidate


@dataclass
class Polled:
    candidates: list[Candidate] = field(default_factory=list)
    polled: set[str] = field(default_factory=set)
    not_polled: set[str] = field(default_factory=set)  # stopped by the GitHub rate limit or budget


async def poll(http: HttpClient, repos: set[str]) -> Polled:
    out = Polled()
    stop = asyncio.Event()

    async def one(repo: str) -> None:
        if stop.is_set():
            out.not_polled.add(repo)
            return
        try:
            res = await github.repo_advisories(http, repo)
        except BudgetExhausted:
            stop.set()
            out.not_polled.add(repo)
            return
        out.polled.add(repo)
        for adv in res.advisories or []:
            if adv.state != "published" or adv.withdrawn_at:
                continue
            in_osv = await osv.present(http, adv.ghsa_id)
            if in_osv:
                continue  # scanners already see it
            state = (await cve.lookup(http, adv.cve_id)).state if adv.cve_id else None
            f = Facts(ghsa_id=adv.ghsa_id, repo=adv.repo, repo_state="published", reviewed=False,
                      in_osv=in_osv, cited_cve=adv.cve_id, cited_cve_state=state)  # fmt: skip
            a = assess(adv, f)
            if a.status is Status.LIMBO:
                cves = (adv.cve_id,) if adv.cve_id else ()
                out.candidates.append(Candidate(adv, a.cve_label, cves, "github"))

    await asyncio.gather(*(one(r) for r in sorted(repos)))
    return out
