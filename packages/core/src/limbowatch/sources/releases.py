"""Release feeds: which packages released since a given time (docs/RELEASE_CHECKS.md, FINDINGS F-101).

Most advisories appear within days of a release of their package, usually right after the fix (F-100), so the
tracker checks a repo after its package releases. Sources:

- npm, PyPI, NuGet, crates.io, Maven, RubyGems: ecosyste.ms packages sorted by `latest_release_published_at`
  (CC BY-SA 4.0 data, used at run time for scheduling only);
- Go: the official module index (index.golang.org), without pseudo-versions;
- Packagist: its metadata change feed, `update` actions without `~dev` branches. It names no repository;
- Maven Central, for the watched Maven packages: each package's `maven-metadata.xml`, polled with its ETag. Maven
  Central has no current feed (its index is rebuilt about every two weeks, search.maven.org stopped in June 2026)
  and ecosyste.ms's Maven data lags by weeks (F-108).

Each feed returns what it got and whether it reached `since`; a partial feed is reported, never silent.

ecosyste.ms lists a release only once it has crawled it, sometimes hours or days late (Maven, F-105). Its cursor is
the newest release it returned, never the time of the run, and the tracker re-reads `ECOSYSTEMS_OVERLAP` before it,
so late arrivals within that window are still seen; later ones fall back to the routine schedule.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from limbowatch.http import HttpClient
from limbowatch.watch.mapping import github_repo, go_repo

ECOSYSTEMS_API = "https://packages.ecosyste.ms/api/v1/registries"
GO_INDEX = "https://index.golang.org/index"
PACKAGIST_CHANGES = "https://packagist.org/metadata/changes.json"
MAVEN_CENTRAL = "https://repo1.maven.org/maven2"
MAVEN_INTERVAL = timedelta(hours=20)  # one pass a day: Maven Central asks tools to keep their traffic low
_LAST_UPDATED = re.compile(rb"<lastUpdated>(\d{14})</lastUpdated>")
# ecosyste.ms registries whose latest-release sort is current (F-101); Go and Packagist use their own feeds
ECOSYSTEMS_REGISTRIES = ("npmjs.org", "pypi.org", "nuget.org", "crates.io", "repo1.maven.org", "rubygems.org")
ECOSYSTEMS_OVERLAP = timedelta(hours=6)  # about 6 extra npm pages a run (5 MB gzipped each, F-105)
_PSEUDO = re.compile(r"\d{14}-[0-9a-f]{12}")  # Go pseudo-version: a commit, not a release


@dataclass(frozen=True)
class Release:
    source: str  # registry or feed
    package: str
    repo: str | None  # owner/name on GitHub, lower case; None when the feed doesn't say
    published_at: datetime
    dependents: int | None = None  # dependent repositories (ecosyste.ms), when known


@dataclass
class Feed:
    source: str
    releases: list[Release]
    complete: bool  # reached `since`; False if a page failed or the page cap was hit
    cursor: str | None = None  # where the next run starts (the feed's own position when it has one)

    @property
    def newest(self) -> datetime | None:
        return max((r.published_at for r in self.releases), default=None)


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


async def ecosystems(
    http: HttpClient, registry: str, since: datetime, overlap: timedelta = timedelta(0), max_pages: int = 60
) -> Feed:
    """Packages of one registry with a release after `since - overlap`, newest first. The cursor is the newest
    release seen, never earlier than `since`, so a feed that lags behind isn't skipped past."""
    out: list[Release] = []
    floor = since - overlap

    def done(complete: bool) -> Feed:
        newest = max((r.published_at for r in out), default=since)
        return Feed(registry, out, complete, max(newest, since).isoformat().replace("+00:00", "Z"))

    for page in range(1, max_pages + 1):
        url = (f"{ECOSYSTEMS_API}/{quote(registry)}/packages?sort=latest_release_published_at&order=desc"
               f"&per_page=1000&page={page}")  # fmt: skip
        r = await http.get(url)
        if not r.ok or not isinstance(r.body, list):
            return done(False)
        for p in r.body:
            when = _ts(p.get("latest_release_published_at"))
            if when is None:
                continue
            if when <= floor:
                return done(True)
            out.append(Release(registry, str(p.get("name") or ""), github_repo(p.get("repository_url")), when,
                               p.get("dependent_repos_count")))  # fmt: skip
        if len(r.body) < 1000:
            return done(True)
    return done(False)


async def go_index(http: HttpClient, since: datetime, max_pages: int = 100) -> Feed:
    """Go module versions published after `since`, without pseudo-versions."""
    out: list[Release] = []
    cursor = since
    for _ in range(max_pages):
        stamp = cursor.isoformat().replace("+00:00", "Z")
        r = await http.get(f"{GO_INDEX}?since={quote(stamp)}&limit=2000")
        if r.status != 200 or not isinstance(r.body, str | dict):
            return Feed("proxy.golang.org", out, False, stamp)
        # newline-delimited JSON; a one-line page parses as a single object
        lines = [r.body] if isinstance(r.body, dict) else [json.loads(x) for x in r.body.splitlines() if x.strip()]
        for m in lines:
            when = _ts(m.get("Timestamp"))
            if when is None or when <= since:
                continue
            cursor = max(cursor, when)
            if _PSEUDO.search(str(m.get("Version", ""))):
                continue
            path = str(m.get("Path", ""))
            out.append(Release("proxy.golang.org", path, go_repo(path), when))
        if len(lines) < 2000:
            return Feed("proxy.golang.org", out, True, cursor.isoformat().replace("+00:00", "Z"))
    return Feed("proxy.golang.org", out, False, cursor.isoformat().replace("+00:00", "Z"))


async def packagist(http: HttpClient, since: datetime) -> Feed:
    """Packagist packages updated after `since` (tagged releases; `~dev` branches skipped). The feed names
    packages, not repositories: the tracker matches them to watched repos by name."""
    r = await http.get(f"{PACKAGIST_CHANGES}?since={int(since.timestamp() * 10_000)}")
    if r.status != 200 or not isinstance(r.body, dict) or "actions" not in r.body:
        return Feed("packagist.org", [], False)  # e.g. {"error": ..., "timestamp": ...} when `since` is too old
    out = []
    for a in r.body.get("actions") or []:
        name = str(a.get("package", ""))
        if a.get("type") != "update" or name.endswith("~dev") or "/" not in name:
            continue
        out.append(Release("packagist.org", name, None, datetime.fromtimestamp(int(a.get("time", 0)), UTC)))
    return Feed("packagist.org", out, True)


@dataclass
class MavenPoll:
    feed: Feed
    meta: dict[str, tuple[str | None, str | None]]  # package -> (ETag, lastUpdated), for the next pass
    not_found: int = 0
    failed: int = 0


async def maven_central(
    http: HttpClient, packages: dict[str, str], meta: dict[str, tuple[str | None, str | None]], since: datetime
) -> MavenPoll:
    """Watched Maven packages (`group:artifact` -> owner/repo) whose maven-metadata.xml says they were deployed after
    `since`. One conditional GET each: an unchanged file is a 304 with no body. Packages that fail are reported and
    the feed is marked partial, so the next run polls again."""
    out: list[Release] = []
    new_meta = dict(meta)
    poll = MavenPoll(Feed("maven-central", out, True, since.isoformat().replace("+00:00", "Z")), new_meta)

    async def one(package: str, repo: str) -> None:
        group, _, artifact = package.partition(":")
        if not group or not artifact:
            return
        etag, updated = meta.get(package, (None, None))
        try:
            r = await http.get(f"{MAVEN_CENTRAL}/{group.replace('.', '/')}/{artifact}/maven-metadata.xml",
                               etag=etag, raw=True)  # fmt: skip
        except (OSError, RuntimeError):
            poll.failed += 1
            return
        if r.status == 304:
            return
        if r.status == 404:
            poll.not_found += 1
            return
        if not r.ok or not isinstance(r.body, bytes):
            poll.failed += 1
            return
        m = _LAST_UPDATED.search(r.body)
        stamp = datetime.strptime(m.group(1).decode(), "%Y%m%d%H%M%S").replace(tzinfo=UTC) if m else None
        new_meta[package] = (r.etag, stamp.isoformat().replace("+00:00", "Z") if stamp else updated)
        if stamp and stamp > since:
            out.append(Release("maven-central", package, repo.lower(), stamp))

    started = datetime.now(UTC)
    await asyncio.gather(*(one(p, r) for p, r in sorted(packages.items())))
    poll.feed.complete = poll.failed == 0
    poll.feed.cursor = started.isoformat().replace("+00:00", "Z")
    return poll


def read_maven_packages(text: str) -> dict[str, str]:
    """`group:artifact owner/repo` per line (tracker/seeds/maven-packages.txt); # comments."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) == 2 and ":" in parts[0] and "/" in parts[1]:
            out[parts[0]] = parts[1].lower()
    return out
