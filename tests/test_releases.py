"""Release-triggered checks (docs/RELEASE_CHECKS.md): the feeds, the schedule and the tracker step. No network."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import respx
from limbowatch import schedule
from limbowatch.http import HttpClient
from limbowatch.sources import releases
from limbowatch.store import Repo, Store
from limbowatch.tracker import RunReport, Tracker, TrackerConfig

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


def iso(d: datetime) -> str:
    return d.isoformat().replace("+00:00", "Z")


def test_release_checks_come_a_day_and_three_days_after() -> None:
    rel = NOW - timedelta(days=2)
    polled_before = rel - timedelta(hours=1)
    assert schedule.release_due(polled_before, rel, NOW)  # the 20-hour check is due
    assert not schedule.release_due(rel + timedelta(hours=21), rel, NOW)  # done; the 3-day one isn't due yet
    assert schedule.release_due(rel + timedelta(hours=21), rel, rel + timedelta(days=3))
    assert not schedule.release_due(polled_before, None, NOW)
    quiet = schedule.overdue(schedule.Tier.QUIET, NOW - timedelta(days=2), None, NOW, rel)
    assert quiet == schedule.RELEASE_SCORE  # a quiet repo checked 2 days ago jumps ahead of routine checks
    seed = schedule.overdue(schedule.Tier.QUIET, None, NOW - timedelta(days=1), NOW)
    fresh = schedule.overdue(schedule.Tier.QUIET, None, NOW, NOW, NOW - timedelta(hours=1))
    assert fresh > seed  # a just-released new repo goes before a seed list's backlog


async def test_ecosystems_feed_stops_at_since(no_sleep: Any) -> None:
    since = NOW - timedelta(hours=1)
    page = [
        {"name": "fresh", "latest_release_published_at": iso(NOW - timedelta(minutes=5)),
         "repository_url": "https://github.com/Org/Fresh", "dependent_repos_count": 500},
        {"name": "norepo", "latest_release_published_at": iso(NOW - timedelta(minutes=9)), "repository_url": None},
        {"name": "old", "latest_release_published_at": iso(NOW - timedelta(hours=2)),
         "repository_url": "https://github.com/org/old"},
    ]  # fmt: skip
    with respx.mock(assert_all_called=True) as router:
        router.get(url__startswith=releases.ECOSYSTEMS_API).mock(return_value=httpx.Response(200, json=page))
        async with HttpClient(sleep=no_sleep) as http:
            feed = await releases.ecosystems(http, "npmjs.org", since)
    assert feed.complete and [r.package for r in feed.releases] == ["fresh", "norepo"]
    assert feed.releases[0].repo == "org/fresh" and feed.releases[0].dependents == 500
    assert feed.cursor == iso(NOW - timedelta(minutes=5))  # the newest release seen, not the time of the run


async def test_a_lagging_ecosystems_feed_is_not_skipped_past(no_sleep: Any) -> None:
    """ecosyste.ms lists some releases late (F-105): the cursor stays at the feed's newest release, never moves
    back, and the next run re-reads an overlap before it."""
    since = NOW - timedelta(hours=1)
    late = [{"name": "late", "latest_release_published_at": iso(since - timedelta(hours=2)), "repository_url": None}]
    with respx.mock(assert_all_called=True) as router:
        router.get(url__startswith=releases.ECOSYSTEMS_API).mock(return_value=httpx.Response(200, json=late))
        async with HttpClient(sleep=no_sleep) as http:
            plain = await releases.ecosystems(http, "repo1.maven.org", since)
            overlapped = await releases.ecosystems(http, "repo1.maven.org", since, timedelta(hours=6))
    assert plain.releases == [] and plain.cursor == iso(since)  # nothing new: the cursor doesn't move back
    assert [r.package for r in overlapped.releases] == ["late"] and overlapped.cursor == iso(since)


async def test_go_index_skips_pseudo_versions_and_packagist_skips_branches(no_sleep: Any) -> None:
    since = NOW - timedelta(hours=1)
    lines = [
        {"Path": "github.com/a/b", "Version": "v1.2.3", "Timestamp": iso(NOW - timedelta(minutes=30))},
        {"Path": "github.com/a/c", "Version": "v0.0.0-20261107174219-27142332909b", "Timestamp": iso(NOW)},
    ]
    changes = {"actions": [{"type": "update", "package": "vendor/pkg", "time": int(NOW.timestamp())},
                           {"type": "update", "package": "vendor/pkg~dev", "time": int(NOW.timestamp())},
                           {"type": "delete", "package": "vendor/gone", "time": int(NOW.timestamp())}],
               "timestamp": 1}  # fmt: skip
    with respx.mock(assert_all_called=True) as router:
        router.get(url__startswith=releases.GO_INDEX).mock(
            return_value=httpx.Response(200, text="\n".join(json.dumps(x) for x in lines)))  # fmt: skip
        router.get(url__startswith=releases.PACKAGIST_CHANGES).mock(return_value=httpx.Response(200, json=changes))
        async with HttpClient(sleep=no_sleep) as http:
            go = await releases.go_index(http, since)
            pk = await releases.packagist(http, since)
    assert go.complete and [(r.repo, r.package) for r in go.releases] == [("a/b", "github.com/a/b")]
    assert go.cursor == iso(NOW)  # the next run starts after the newest entry, pseudo-versions included
    assert [r.package for r in pk.releases] == ["vendor/pkg"] and pk.releases[0].repo is None


async def test_tracker_marks_released_repos_and_adds_popular_ones(no_sleep: Any) -> None:
    store = Store()
    with store.session() as s:
        s.add(Repo(full_name="org/watched", sources=["seed"], first_seen=iso(NOW), last_polled_at=iso(NOW)))
        s.add(Repo(full_name="vendor/pkg", sources=["seed"], first_seen=iso(NOW), last_polled_at=iso(NOW)))
    rel = datetime.now(UTC) - timedelta(minutes=10)
    page = [
        {"name": "w", "latest_release_published_at": iso(rel), "repository_url": "https://github.com/org/watched"},
        {"name": "popular", "latest_release_published_at": iso(rel), "repository_url": "https://github.com/big/lib",
         "dependent_repos_count": 5000},
        {"name": "tiny", "latest_release_published_at": iso(rel), "repository_url": "https://github.com/me/toy",
         "dependent_repos_count": 3},
    ]  # fmt: skip
    changes = {"actions": [{"type": "update", "package": "Vendor/Pkg", "time": int(rel.timestamp())}]}
    with respx.mock() as router:
        router.get(url__startswith=releases.ECOSYSTEMS_API + "/npmjs.org").mock(
            return_value=httpx.Response(200, json=page)
        )
        router.get(url__startswith=releases.ECOSYSTEMS_API).mock(return_value=httpx.Response(200, json=[]))
        router.get(url__startswith=releases.GO_INDEX).mock(return_value=httpx.Response(500))
        router.get(url__startswith=releases.PACKAGIST_CHANGES).mock(return_value=httpx.Response(200, json=changes))
        async with HttpClient(sleep=no_sleep) as http:
            report = RunReport(started_at=iso(NOW))
            await Tracker(store, http, TrackerConfig(releases=True, release_min_dependents=100)).collect_releases(
                report
            )
    with store.session() as s:
        rows = {r.full_name: r for r in s.query(Repo).all()}
    assert rows["org/watched"].released_at and rows["vendor/pkg"].released_at  # Packagist matched by name
    assert "big/lib" in rows and rows["big/lib"].sources == ["release:npmjs.org"]  # 5,000 dependents: watched now
    assert "me/toy" not in rows  # 3 dependents: not added
    assert report.releases["npmjs.org"] == {
        "releases": 3, "watched": 1, "added": 1, "complete": True, "newest": iso(rel.replace(microsecond=0)),
    }  # fmt: skip
    assert report.releases["proxy.golang.org"]["complete"] is False  # a failing feed is reported, not silent
    assert store.cursor("releases:npmjs.org") and store.cursor("releases:proxy.golang.org") is None


def maven_xml(updated: datetime) -> bytes:
    return (f"<metadata><groupId>g</groupId><versioning><release>1.0</release>"
            f"<lastUpdated>{updated:%Y%m%d%H%M%S}</lastUpdated></versioning></metadata>").encode()  # fmt: skip


async def test_maven_central_feed_uses_etags_and_reports_failures(no_sleep: Any) -> None:
    """Maven Central has no current release feed: each watched package's maven-metadata.xml, sent with its ETag
    (an unchanged file is a 304 with no body), says when it was last deployed (F-108)."""
    since = NOW - timedelta(days=1)
    base = releases.MAVEN_CENTRAL
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{base}/org/same/lib/maven-metadata.xml", headers={"If-None-Match": '"e1"'}).mock(
            return_value=httpx.Response(304)
        )
        router.get(f"{base}/org/fresh/lib/maven-metadata.xml").mock(
            return_value=httpx.Response(200, content=maven_xml(NOW - timedelta(hours=3)), headers={"ETag": '"e2"'})
        )
        router.get(f"{base}/org/old/lib/maven-metadata.xml").mock(
            return_value=httpx.Response(200, content=maven_xml(NOW - timedelta(days=9)), headers={"ETag": '"e3"'})
        )
        router.get(f"{base}/org/gone/lib/maven-metadata.xml").mock(return_value=httpx.Response(404))
        router.get(f"{base}/org/broken/lib/maven-metadata.xml").mock(return_value=httpx.Response(500))
        packages = {f"org.{n}:lib": f"o/{n}" for n in ("same", "fresh", "old", "gone", "broken")}
        async with HttpClient(sleep=no_sleep) as http:
            known = {"org.same:lib": ('"e1"', "2026-10-01T00:00:00Z")}
            poll = await releases.maven_central(http, packages, known, since)
    assert [(r.package, r.repo) for r in poll.feed.releases] == [("org.fresh:lib", "o/fresh")]
    assert poll.meta["org.fresh:lib"] == ('"e2"', iso(NOW - timedelta(hours=3)))
    assert poll.meta["org.old:lib"][0] == '"e3"' and poll.meta["org.same:lib"] == ('"e1"', "2026-10-01T00:00:00Z")
    assert (poll.not_found, poll.failed, poll.feed.complete) == (1, 1, False)  # the next run polls again


def test_maven_packages_file() -> None:
    text = "# group:artifact owner/repo\ncom.google.guava:guava google/Guava\nnot a line\norg.x:y a/b # note\n"
    assert releases.read_maven_packages(text) == {"com.google.guava:guava": "google/guava", "org.x:y": "a/b"}


async def test_tracker_polls_maven_central_once_a_day_and_keeps_etags(no_sleep: Any) -> None:
    store = Store()
    with store.session() as s:
        s.add(Repo(full_name="google/guava", sources=["seed"], first_seen=iso(NOW), last_polled_at=iso(NOW)))
    url = f"{releases.MAVEN_CENTRAL}/com/google/guava/guava/maven-metadata.xml"
    fresh = datetime.now(UTC) - timedelta(hours=1)
    cfg = TrackerConfig(releases=True, maven_packages={"com.google.guava:guava": "google/guava"})

    async def run() -> RunReport:
        with respx.mock(assert_all_called=False) as router:
            router.get(url).mock(return_value=httpx.Response(200, content=maven_xml(fresh), headers={"ETag": '"g1"'}))
            router.get(url__regex=r"^(?!https://repo1\.maven\.org).*").mock(return_value=httpx.Response(200, json=[]))
            async with HttpClient(sleep=no_sleep) as http:
                report = RunReport(started_at=iso(NOW))
                await Tracker(store, http, cfg).collect_releases(report)
                return report

    first = await run()
    assert first.releases["maven-central"]["watched"] == 1 and first.releases["maven-central"]["complete"]
    with store.session() as s:
        assert s.get(Repo, "google/guava").released_at  # type: ignore[union-attr]
        from limbowatch.store import PackageMeta

        assert s.get(PackageMeta, "maven:com.google.guava:guava").etag == '"g1"'  # type: ignore[union-attr]
    second = await run()  # minutes later: not due again for 20 hours
    assert "maven-central" not in second.releases
