"""GitHub: repository advisories (per repo) and the global reviewed list."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime

from limbowatch.http import HttpClient
from limbowatch.mdsafe import GHSA_ID
from limbowatch.models import RepoAdvisory, ReviewedEntry
from limbowatch.normalize import repo_advisory, reviewed_entry

API = "https://api.github.com"
_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')
log = logging.getLogger(__name__)


def _on_api(url: str) -> bool:
    """A next-page link the token may follow: on GitHub's API, over https. Anything else ends the listing, logged."""
    if url.startswith(f"{API}/"):
        return True
    log.warning("next page link isn't on %s; stopped there", API)
    return False


@dataclass
class RepoPoll:
    status: int  # 200, 304 (unchanged), 404, ...; -1: no answer, or a later page couldn't be read
    advisories: list[RepoAdvisory] | None  # None when unchanged or unavailable, or only partly listed
    etag: str | None


async def repo_advisories(http: HttpClient, repo: str, etag: str | None = None) -> RepoPoll:
    """All published advisories of one repository. With `etag`, an unchanged repo costs nothing.

    All or nothing: if a later page can't be read, the result has no advisories (like a failed first page), never
    the pages read so far, which callers would take for the whole list (and for the others being withdrawn)."""
    url = f"{API}/repos/{repo}/security-advisories?state=published&per_page=100"
    r = await http.get(url, etag=etag)
    if r.status == 304:
        return RepoPoll(304, None, etag)
    if not r.ok or not isinstance(r.body, list):
        return RepoPoll(r.status, None, None)
    first_etag, raw = r.etag, list(r.body)
    link = r.link
    while link and (m := _NEXT.search(link)):  # >100 advisories: follow pages (no etag on later pages)
        # -1 whatever the page said: a later page's 404 isn't "no such repo", nor a 200 that isn't a list a success
        if not _on_api(m.group(1)):
            return RepoPoll(-1, None, None)
        nxt = await http.get(m.group(1))
        if not nxt.ok or not isinstance(nxt.body, list):
            log.warning("%s: page %d of its advisories couldn't be read (%s)", repo, len(raw) // 100 + 1, nxt.status)
            return RepoPoll(-1, None, None)
        raw += nxt.body
        link = nxt.link
    # the ID names the advisory's page and feed record files: one that isn't a GHSA ID is logged and left out
    ok = [a for a in raw if isinstance(a, dict) and GHSA_ID.fullmatch(str(a.get("ghsa_id") or ""))]
    if len(ok) < len(raw):
        log.warning("%s: %d advisories without a GHSA ID left out", repo, len(raw) - len(ok))
    return RepoPoll(200, [repo_advisory(a, repo) for a in ok], first_etag)


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
        url = m.group(1) if m and _on_api(m.group(1)) else None
