"""End to end on recorded, real-shaped responses. No network: respx intercepts everything."""

from __future__ import annotations

import csv
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import httpx
import pytest
import respx
from conftest import load
from limbowatch.http import HttpClient
from limbowatch.models import CveLabel, Status
from limbowatch.publish import all_events, feed, items, metrics, site
from limbowatch.store import Event, Repo, Store
from limbowatch.tracker import Tracker, TrackerConfig

GH = "https://api.github.com"
ETAG_REGEXP2 = '"etag-regexp2"'


PAGES = (
    "index.html",
    "tracker/index.html",
    "tracker/data.json",
    "check/index.html",
    "check/index.json",
    "assets/check.js",
    "feed/index.html",
    "scan/index.html",
    "why/index.html",
    "compliance/index.html",
    "methodology/index.html",
    "press/index.html",
    "press/queue.svg",
    "press/limbo.csv",
    "feed/limbo.atom",
    "feed/critical.atom",
    "sitemap.xml",
    "robots.txt",
)


def delta_log() -> list[dict[str, Any]]:
    return [
        {
            "fetchTime": "2099-01-01T00:00:00.000Z",
            "numberOfChanges": 1,
            "new": [
                {"cveId": "CVE-2026-110858", "githubLink": "https://raw.githubusercontent.com/cve/CVE-2026-110858.json"}
            ],
            "updated": [],
            "error": [],
        }
    ]


def mock_world(router: respx.MockRouter, *, regexp2_reviewed: bool = False) -> None:
    reviewed = load("reviewed_page.json")
    if regexp2_reviewed:
        reviewed = [
            *reviewed,
            {
                "ghsa_id": "GHSA-wq9v-j77v-qr26",
                "cve_id": "CVE-2026-77299",
                "type": "reviewed",
                "github_reviewed_at": "2099-01-01T00:00:00Z",
                "published_at": "2099-01-01T00:00:00Z",
                "repository_advisory_url": f"{GH}/repos/dlclark/regexp2/security-advisories/GHSA-wq9v-j77v-qr26",
            },
        ]
    router.get(url__startswith=f"{GH}/advisories?type=reviewed").mock(return_value=httpx.Response(200, json=reviewed))

    def regexp2(request: httpx.Request) -> httpx.Response:
        if request.headers.get("if-none-match") == ETAG_REGEXP2:
            return httpx.Response(304)
        return httpx.Response(200, json=load("repo_advisories_regexp2.json"), headers={"etag": ETAG_REGEXP2})

    router.get(url__startswith=f"{GH}/repos/dlclark/regexp2/security-advisories").mock(side_effect=regexp2)
    router.get(url__startswith=f"{GH}/repos/gitpython-developers/gitpython/security-advisories").mock(
        return_value=httpx.Response(200, json=load("repo_advisories_gitpython.json"), headers={"etag": '"g"'})
    )
    router.get(url__startswith=f"{GH}/repos/").mock(return_value=httpx.Response(404, json={"message": "Not Found"}))
    router.get("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json").mock(
        return_value=httpx.Response(200, json=delta_log())
    )
    router.get("https://raw.githubusercontent.com/cve/CVE-2026-110858.json").mock(
        return_value=httpx.Response(200, json=load("cve_CVE-2026-110858.json"))
    )
    router.get("https://cveawg.mitre.org/api/cve/CVE-2026-77299").mock(
        return_value=httpx.Response(404, json=load("cve_not_found.json"))
    )
    router.get("https://cveawg.mitre.org/api/cve-id/CVE-2026-77299").mock(
        return_value=httpx.Response(200, json=load("cve_id_CVE-2026-77299.json"))
    )
    router.get(url__startswith="https://api.osv.dev/v1/vulns/").mock(return_value=httpx.Response(404, json={"code": 5}))
    router.get("https://proxy.golang.org/github.com/dlclark/regexp2/@v/list").mock(
        return_value=httpx.Response(200, text="v1.11.4\nv1.11.5\n")
    )


async def run_once(store: Store, seed: Path, no_sleep: Any) -> Any:
    async with HttpClient("test-token", github_budget=100, sleep=no_sleep) as http:
        return await Tracker(store, http, TrackerConfig(seeds=[seed], nvd=False)).run()


async def test_tracker_end_to_end(tmp_path: Path, no_sleep: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    seed = tmp_path / "seed.txt"
    seed.write_text("dlclark/regexp2\ngitpython-developers/gitpython\n# comment\nnot-a-repo\n")
    store = Store()

    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        mock_world(router)
        r1 = await run_once(store, seed, no_sleep)
    assert r1.stopped_early is None
    assert r1.new_advisories == 3
    # regexp2's Go path is a module of its own, per the module proxy (F-113)
    assert r1.go_modules == {"paths": 1, "due": 1, "resolved": 1, "in_module": 0, "no_module": 0, "failed": 0,
                             "requests": 1}  # fmt: skip

    by_id = {i.adv.ghsa_id: i for i in items(store)}
    regexp2 = by_id["GHSA-wq9v-j77v-qr26"]
    assert regexp2.assessment.status is Status.LIMBO
    assert regexp2.adv.packages[0].module == "github.com/dlclark/regexp2"
    assert feed.record(regexp2, "2026-11-08T00:00:00Z")["affected"][0]["database_specific"]["go_module"] == (
        "github.com/dlclark/regexp2"
    )
    assert regexp2.assessment.cve_label is CveLabel.RESERVED
    gitpython = by_id["GHSA-f9j4-qggq-h239"]
    assert gitpython.assessment.status is Status.LIMBO
    assert gitpython.facts.uncited_cves == ("CVE-2026-110858",)  # VulnCheck CVE found via the delta log
    assert gitpython.assessment.cve_label is CveLabel.PUBLISHED_UNCITED
    assert "GHSA-83vg-56qc-22m7" not in by_id  # already reviewed when first seen: never tracked

    # right away, nothing is due (limbowatch.schedule), and the Go path isn't looked up again
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        mock_world(router)
        again = await run_once(store, seed, no_sleep)
        assert again.polled == 0 and again.go_modules["requests"] == 0
    with store.session() as s:  # four days pass: due in every tier but the 30-day one
        for repo in s.query(Repo):
            repo.last_polled_at = (datetime.now(UTC) - timedelta(days=4)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # second run: regexp2 gets reviewed; its repo answers 304 (ETag stored for this token)
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        mock_world(router, regexp2_reviewed=True)
        r2 = await run_once(store, seed, no_sleep)
    assert r2.not_modified >= 1
    # every poll is tallied per tier, and the 304s add up (F-100)
    assert sum(t.get("304", 0) for t in r2.by_tier.values()) == r2.not_modified
    assert (
        sum(sum(v for k, v in t.items() if k not in ("no_etag", "new_advisories")) for t in r2.by_tier.values())
        == r2.polled
    )
    assert any(e == "GHSA-wq9v-j77v-qr26: in limbo -> reviewed" for e in r2.events)
    with store.session() as s:
        assert s.get(Repo, "dlclark/regexp2").etag_token != "anonymous"  # type: ignore[union-attr]
        assert s.query(Event).count() >= 3

    m = metrics(store, datetime(2099, 1, 2, tzinfo=UTC))
    assert m["in_limbo"]["count"] == 1
    assert m["left_limbo"]["reviewed"] == 1
    assert sum(m["coverage"]["by_source"].values()) >= m["coverage"]["watchlist_repos"] > 0  # every repo has a reason

    # the feed: OSV-schema records for what's in limbo, factual fields only
    records, zipped = feed.build(items(store), m["generated_at"])
    assert [r["id"] for r in records] == ["GHSA-f9j4-qggq-h239"]
    rec = records[0]
    assert rec["aliases"] == ["CVE-2026-110858"]
    # PEP 503 form, which OSV requires and OSV-Scanner compares against (F-069); the original is kept
    assert rec["affected"][0]["package"] == {"ecosystem": "PyPI", "name": "gitpython"}
    assert rec["affected"][0]["database_specific"]["name_as_entered"] == "GitPython"
    assert rec["database_specific"]["limbowatch"]["quality"] == {"names": "cleaned", "ranges": "converted"}
    assert "summary" not in rec and "details" not in rec
    assert "REDACTED" not in json.dumps(rec)
    with zipfile.ZipFile(io.BytesIO(zipped)) as z:
        assert z.namelist() == ["GHSA-f9j4-qggq-h239.json"]

    # the home page's examples: shown only while their advisory is in limbo, not reviewed and not in OSV
    ex = {"ecosystem": "PyPI", "package": "pkg", "version": "1.0", "fixed": "1.1", "fix_released": "2026-01-01"}
    monkeypatch.setattr(site, "EXAMPLES", [{**ex, "ghsa": "GHSA-f9j4-qggq-h239"}, {**ex, "ghsa": "GHSA-wq9v-j77v-qr26"},
                                           {**ex, "ghsa": "GHSA-0000-0000-0000"}])  # fmt: skip
    pages = site.build(items(store), m, datetime.now(UTC), events=all_events(store), sample=rec)
    assert set(PAGES) <= set(pages)
    home = pages["index.html"]
    assert home.count('class="exc"') == 1 and 'href="/advisory/GHSA-f9j4-qggq-h239/"><div class="top2">' in home
    assert "Fixed upstream." in home and "already name a fixed version" in home and site.POC_URL in home
    assert '<details class="learn"><summary>Learn</summary>' in home and 'href="/compliance/"' in home
    comp = pages["compliance/index.html"]
    assert "Compliant, and exposed." in comp and site.BOD_2604 in comp and site.PCI_FAQ in comp
    assert (
        '<details class="learn on">' in comp
        and "<loc>https://limbo.watch/compliance/</loc>" in pages["sitemap-pages.xml"]
    )
    assert site.POC_URL in pages["scan/index.html"]
    scan_page = pages["scan/index.html"]  # what the scan sends where, and the switch that turns each off
    assert 'id="data"' in scan_page and "--no-resolve-maven" in scan_page and "#security-and-data" in scan_page
    monkeypatch.setattr(site, "EXAMPLES", [])
    assert 'id="examples"' not in site.build(items(store), m, datetime.now(UTC))["index.html"]  # none left: no section
    adv = pages["advisory/GHSA-f9j4-qggq-h239/index.html"]
    assert "CVE-2026-110858" in adv and "published by another CNA" in adv
    left_page = pages["advisory/GHSA-wq9v-j77v-qr26/index.html"]  # reviewed: left limbo, but its link still works
    assert "Left limbo: reviewed by GitHub after" in left_page and "/feed/GHSA-wq9v-j77v-qr26.json" not in left_page
    assert '<div class="fixbar"><p><strong>Fixed in' in adv and 'class="fixbar"' not in left_page  # the fix, up top
    assert (
        "can report it" in left_page
        and "<loc>https://limbo.watch/advisory/GHSA-wq9v-j77v-qr26/</loc>" in pages["sitemap-advisories-1.xml"]
    )
    left = json.loads(pages["tracker/data.json"])["left"]
    assert [r["id"] for r in left] == ["GHSA-wq9v-j77v-qr26"] and left[0]["to"] == "Reviewed by GitHub"
    pend = json.loads(pages["tracker/data.json"])["pending"]  # the "fix released" filter's flag
    assert [(r["id"], r["fx"]) for r in pend] == [("GHSA-f9j4-qggq-h239", 1)]
    assert '<select id="fix">' in pages["tracker/index.html"] and 'href="/tracker/?fix=yes"' in home
    assert all("REDACTED" not in text for text in pages.values())
    checker = json.loads(pages["check/index.json"])  # the package checker's data: facts only, no advisory text
    assert checker["advisories"] >= 1 and "/assets/check.js?v=" in pages["check/index.html"]
    for path in ("feed/limbo.atom", "feed/critical.atom", "sitemap.xml", "sitemap-pages.xml", "press/queue.svg"):
        ElementTree.fromstring(pages[path])  # well-formed XML
    # sitemap.xml is an index of the files below (F-168); an advisory's lastmod is when its facts last changed
    index = ElementTree.fromstring(pages["sitemap.xml"])
    listed = [e.text for e in index.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]
    assert listed == ["https://limbo.watch/sitemap-pages.xml", "https://limbo.watch/sitemap-advisories-1.xml"]
    advs = pages["sitemap-advisories-1.xml"]
    ElementTree.fromstring(advs)
    assert "<loc>https://limbo.watch/advisory/GHSA-f9j4-qggq-h239/</loc>" in advs
    newest = max(e["at"] for e in all_events(store) if e["ghsa_id"] == "GHSA-f9j4-qggq-h239")[:10]
    assert f"<loc>https://limbo.watch/advisory/GHSA-f9j4-qggq-h239/</loc><lastmod>{newest}</lastmod>" in advs
    # advisory pages: facts in the title and description, breadcrumbs (F-168)
    assert (
        "<title>gitpython (PyPI): critical vulnerability CVE-2026-110858, GHSA-f9j4-qggq-h239 · limbo.watch</title>"
        in adv
    )
    assert '"@type":"BreadcrumbList"' in adv and "Dependabot, npm audit and OSV-Scanner don’t report it yet" in adv
    assert '"@type":"WebSite"' in home and '"@type":"Dataset"' in home
    assert "https://limbo.watch/advisory/GHSA-f9j4-qggq-h239/" in pages["feed/limbo.atom"]
    table = pages["press/limbo.csv"]
    assert table.startswith("\ufeff")  # BOM, so Excel reads UTF-8
    rows = list(csv.DictReader(io.StringIO(table.removeprefix("\ufeff"))))
    assert [r["ghsa_id"] for r in rows] == ["GHSA-f9j4-qggq-h239"] and rows[0]["status"] == "pending review"
    assert rows[0]["affected_versions"] and rows[0]["published"].count("-") == 2
    assert all("mailto:" not in v for k, v in pages.items() if k.endswith(".html"))  # the contact is an image
    assert '<link rel="canonical" href="https://limbo.watch/press/">' in pages["press/index.html"]
    assert '"@type":"Dataset"' in pages["index.html"]
    flow = metrics(store, datetime.now(UTC))["flow_7d"]  # regexp2 was reviewed just now
    assert flow["reviewed"] == 1 and flow["left"] == 1
    assert "analytics.js" not in pages["index.html"] and "assets/analytics.js" not in pages  # off unless configured
    tagged = site.build(items(store), m, datetime.now(UTC), analytics_id="G-ABC123XYZ")
    assert all('data-id="G-ABC123XYZ"' in v for k, v in tagged.items() if k.endswith(".html"))
    assert "analytics_storage:choice==='granted'?'granted':'denied'" in tagged["assets/analytics.js"]
    with pytest.raises(ValueError):
        site.build(items(store), m, datetime.now(UTC), analytics_id='G-1"><script>')

    # state round-trips through JSONL
    store.export_jsonl(tmp_path / "state")
    again = Store()
    again.import_jsonl(tmp_path / "state")
    assert {i.adv.ghsa_id for i in items(again)} == set(by_id)


async def test_budget_stops_polling_but_keeps_progress(tmp_path: Path, no_sleep: Any) -> None:
    seed = tmp_path / "seed.txt"
    seed.write_text("\n".join(f"o/r{i}" for i in range(20)) + "\ndlclark/regexp2\n")
    store = Store()
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        mock_world(router)
        async with HttpClient("t", github_budget=5, sleep=no_sleep) as http:
            report = await Tracker(store, http, TrackerConfig(seeds=[seed], nvd=False)).run()
    assert report.stopped_early == "budget"
    assert 0 < report.polled < 21


async def test_renamed_repo_does_not_duplicate_advisories(tmp_path: Path, no_sleep: Any) -> None:
    """A repo polled under its old and new names returns the same advisory twice (F-060)."""
    seed = tmp_path / "seed.txt"
    seed.write_text("dlclark/regexp2\nold-owner/regexp2\n")
    store = Store()
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        router.get(url__startswith=f"{GH}/repos/old-owner/regexp2/security-advisories").mock(
            return_value=httpx.Response(200, json=load("repo_advisories_regexp2.json"))
        )
        mock_world(router)
        report = await run_once(store, seed, no_sleep)
    assert report.stopped_early is None
    regexp2 = [i for i in items(store) if i.adv.ghsa_id == "GHSA-wq9v-j77v-qr26"]
    assert len(regexp2) == 1
    assert regexp2[0].adv.repo == "dlclark/regexp2"  # canonical name from the advisory's URL


async def test_tracker_rereads_cve_records_stored_under_an_older_link_rule(tmp_path: Path, no_sleep: Any) -> None:
    """Records stored before F-120 took GHSA IDs from descriptions too. Where such a link would count, the record
    is read again; a lookup that finds no record keeps the stored one."""
    from limbowatch.store import Cve

    seed = tmp_path / "seed.txt"
    seed.write_text("gitpython-developers/gitpython\n")
    store = Store()
    old = {"state": "PUBLISHED", "cna": "VulnCheck", "ghsa_refs": ["GHSA-F9J4-QGGQ-H239"], "repo_refs": []}
    with store.session() as s:
        for cid in ("CVE-2026-900001", "CVE-2026-900002"):
            s.add(Cve(cve_id=cid, data={**old, "cve_id": cid}, fetched_at="2026-10-30T00:00:00Z"))
    mention = {
        "cveMetadata": {"cveId": "CVE-2026-900001", "state": "PUBLISHED", "assignerShortName": "VulnCheck"},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Distinct from GHSA-f9j4-qggq-h239."}],
                               "references": [{"url": "https://example.com/advisory"}]}},
    }  # fmt: skip
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        mock_world(router)
        router.get("https://cveawg.mitre.org/api/cve/CVE-2026-900001").mock(
            return_value=httpx.Response(200, json=mention)
        )
        router.get("https://cveawg.mitre.org/api/cve/CVE-2026-900002").mock(
            return_value=httpx.Response(404, json=load("cve_not_found.json"))
        )
        router.get("https://cveawg.mitre.org/api/cve-id/CVE-2026-900002").mock(
            return_value=httpx.Response(404, json=load("cve_not_found.json"))
        )
        r = await run_once(store, seed, no_sleep)
    assert r.cves_relinked == 1
    gitpython = next(i for i in items(store) if i.adv.ghsa_id == "GHSA-f9j4-qggq-h239")
    assert gitpython.facts.uncited_cves == ("CVE-2026-110858", "CVE-2026-900002")


def test_cve_list_bootstrap_finds_uncited_cves(tmp_path: Path) -> None:
    """A bulk CVE List release is nested zips; only records that reference a GHSA are kept (F-050)."""
    from limbowatch.tracker import import_cve_list

    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("cves/2026/110xxx/CVE-2026-110858.json", json.dumps(load("cve_CVE-2026-110858.json")))
        z.writestr("cves/2026/110xxx/CVE-2026-110001.json", json.dumps({"cveMetadata": {"cveId": "CVE-2026-110001"}}))
        z.writestr("cves/deltaLog.json", "[]")
    release = tmp_path / "2026-10-25_all_CVEs_at_midnight.zip.zip"
    with zipfile.ZipFile(release, "w") as z:
        z.writestr("cves.zip", inner.getvalue())
    store = Store()
    work = tmp_path / "work"
    work.mkdir()
    assert import_cve_list(store, release, work) == 1
    assert store.cursor("cve_bulk") == release.name


async def test_daily_report_tracks_changes(tmp_path: Path, no_sleep: Any) -> None:
    from limbowatch.publish import report

    seed = tmp_path / "seed.txt"
    seed.write_text("dlclark/regexp2\ngitpython-developers/gitpython\n")
    store = Store()
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        mock_world(router)
        await run_once(store, seed, no_sleep)
    first = report.build(store, datetime.now(UTC))
    assert "first report" in first.markdown
    assert "**2 advisories in limbo**" in first.markdown
    assert "REDACTED" not in first.markdown
    report.commit(store, first)

    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        mock_world(router, regexp2_reviewed=True)
        await run_once(store, seed, no_sleep)
    second = report.build(store, datetime.now(UTC))
    assert (
        "**1 advisories in limbo** (−1 since the last report: 0 newly published, "
        "0 older ones found for the first time, 1 left limbo)" in second.markdown
    )
    assert "1 reviewed by GitHub" in second.markdown
    # GitHub's reviews overall, including the one seen leaving limbo whatever its review date (F-167)
    assert "GitHub reviewed 1 advisory in all in this period, from any repository." in second.markdown
    assert second.summary["pending_ids"] == ["GHSA-f9j4-qggq-h239"] and second.summary["permanent_ids"] == []
    assert "**0 more are likely permanent** (+0 since the last report: 0 newly published," in second.markdown
    assert "## Longest waiting, published in the last 90 days" in second.markdown
    assert "0 advisories in limbo have waited more than a year." in second.markdown


async def test_watch_cna_repos_backfills_bulk_imported_cves(tmp_path: Path, no_sleep: Any) -> None:
    """The bulk CVE import stores GitHub-CNA CVEs without watching their repos (F-066); each run catches up."""
    from limbowatch.store import Cve

    store = Store()
    with store.session() as s:
        for cid, cna, refs in [
            ("CVE-1", "GitHub_M", ["acme/widget", "advisories/ghsa-xxxx-xxxx-xxxx"]),
            ("CVE-2", "VulnCheck", ["other/repo"]),
        ]:
            s.add(
                Cve(cve_id=cid, data={"cve_id": cid, "cna": cna, "repo_refs": refs}, fetched_at="2026-10-30T00:00:00Z")
            )
    async with HttpClient("t", github_budget=1, sleep=no_sleep) as http:
        tracker = Tracker(store, http, TrackerConfig())
        assert tracker.watch_cna_repos() == 1
        assert tracker.watch_cna_repos() == 0
    with store.session() as s:
        assert [r.full_name for r in s.query(Repo)] == ["acme/widget"]


async def test_daily_report_names_moves_and_review_stalls(tmp_path: Path, no_sleep: Any) -> None:
    """Advisories that move between in limbo and likely permanent are named, not "other changes", and a period in
    which GitHub reviewed nothing says so (F-167)."""
    from limbowatch.publish import report

    seed = tmp_path / "seed.txt"
    seed.write_text("dlclark/regexp2\ngitpython-developers/gitpython\n")
    store = Store()
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        mock_world(router)
        await run_once(store, seed, no_sleep)
    first = report.build(store, datetime.now(UTC))
    ids = first.summary["pending_ids"]
    assert len(ids) == 2
    # as if both had been likely permanent at the last report, and their packages had changed ecosystem since
    report.commit(store, report.Report(first.date, "", {**first.summary, "limbo": 0, "permanent": 2,
                                                        "pending_ids": [], "permanent_ids": ids}))  # fmt: skip
    again = report.build(store, datetime.now(UTC))
    assert (
        "**2 advisories in limbo** (+2 since the last report: 0 newly published, 0 older ones found for the first "
        "time, 0 left limbo, 2 moved in from likely permanent)" in again.markdown
    )
    assert "(−2 since the last report: 0 newly published, 0 older ones found for the first time, 0 left limbo, " \
        "2 moved to the in-limbo count)" in again.markdown  # fmt: skip
    assert "other changes" not in again.markdown
    assert "**GitHub reviewed no advisories at all in this period.**" in again.markdown


def test_report_comment_fits_an_issue_comment() -> None:
    from limbowatch.publish import report

    short = "# Report\n\nall of it\n"
    assert report.comment(short, "https://x/full.md") == short
    long = "# Report\n" + "".join(f"| row {i} | é |\n" for i in range(10_000))
    out = report.comment(long, "https://x/full.md", limit=5_000)
    assert len(out.encode()) <= 5_000
    assert out.endswith("_The report is longer than an issue comment allows; [read all of it](https://x/full.md)._\n")
    body = out.split("\n\n_The report")[0]
    assert body.endswith("|") and long.startswith(body)  # cut at a line break, never inside a character or a row


def test_report_cve_changes_are_plain_or_code_and_ordered() -> None:
    from limbowatch.publish import report

    assert report._event("CVE-2026-1 RESERVED -> PUBLISHED") == "CVE-2026-1 RESERVED -> PUBLISHED"
    assert report._event("new CVE from GitHub's CNA, not cited: CVE-2026-2") == (
        "new CVE from GitHub's CNA, not cited: CVE-2026-2"
    )
    assert report._event("cites CVE-1 [x](https://e) | y (was none)") == "`cites CVE-1 [x](https://e) \\| y (was none)`"
    kinds = ["new CVE from another CNA: CVE-3", "cites CVE-2 (was none)", "CVE-1 RESERVED -> PUBLISHED", "duplicate"]
    item = next(iter(_items_for_rank()))
    ranked = sorted([(item, k) for k in kinds], key=report._cve_rank)
    assert [k for _, k in ranked] == [kinds[2], kinds[1], kinds[0], kinds[3]]


def _items_for_rank() -> list[Any]:
    """A stand-in item: _cve_rank reads only the advisory's severity and ID."""
    from types import SimpleNamespace

    return [SimpleNamespace(adv=SimpleNamespace(severity="high", ghsa_id="GHSA-aaaa-bbbb-cccc"))]
