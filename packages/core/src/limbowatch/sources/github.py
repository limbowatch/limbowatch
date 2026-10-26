"""GitHub: repository advisories (per repo) and the global reviewed list."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime

from limbowatch.http import HttpClient
from limbowatch.models import RepoAdvisory, ReviewedEntry
from limbowatch.normalize import repo_advisory, reviewed_entry

API = "https://api.github.com"
_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


@dataclass
class RepoPoll:
    status: int  # 200, 304 (unchanged), 404, ...
    advisories: list[RepoAdvisory] | None  # None when unchanged or unavailable
    etag: str | None


async def repo_advisories(http: HttpClient, repo: str, etag: str | None = None) -> RepoPoll:
    """All published advisories of one repository. With `etag`, an unchanged repo costs nothing."""
    url = f"{API}/repos/{repo}/security-advisories?state=published&per_page=100"
    r = await http.get(url, etag=etag)
    if r.status == 304:
        return RepoPoll(304, None, etag)
    if not r.ok or not isinstance(r.body, list):
        return RepoPoll(r.status, None, None)
    first_etag, raw = r.etag, list(r.body)
    link = r.link
    while link and (m := _NEXT.search(link)):  # >100 advisories: follow pages (no etag on later pages)
        nxt = await http.get(m.group(1))
        if not nxt.ok or not isinstance(nxt.body, list):
            break
        raw += nxt.body
        link = nxt.link
    return RepoPoll(200, [repo_advisory(a, repo) for a in raw], first_etag)


async def reviewed_since(http: HttpClient, since: datetime | None) -> AsyncIterator[ReviewedEntry]:
    """Reviewed global advisories, newest review first, stopping at `since`.

    The global `published_at` equals the review time (FINDINGS F-009), so `sort=published` orders
    by review. With `since=None` this walks the whole reviewed list (~370 pages, F-057).
    """
    url: str | None = f"{API}/advisories?type=reviewed&sort=published&direction=desc&per_page=100"
    while url:
        r = await http.get(url)
        if not r.ok or not isinstance(r.body, list):
            return
        for raw in r.body:
            e = reviewed_entry(raw)
            if since is not None and e.reviewed_at is not None and e.reviewed_at < since:
                return
            yield e
        m = _NEXT.search(r.link or "")
        url = m.group(1) if m else None
