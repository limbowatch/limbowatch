"""End to end on recorded, real-shaped responses. No network: respx intercepts everything."""

from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import respx
from conftest import load
from limbowatch.http import HttpClient
from limbowatch.models import CveLabel, Status
from limbowatch.publish import feed, items, metrics, site
from limbowatch.store import Event, Repo, Store
from limbowatch.tracker import Tracker, TrackerConfig

GH = "https://api.github.com"
ETAG_REGEXP2 = '"etag-regexp2"'


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


async def run_once(store: Store, seed: Path, no_sleep: Any) -> Any:
    async with HttpClient("test-token", github_budget=100, sleep=no_sleep) as http:
        return await Tracker(store, http, TrackerConfig(seeds=[seed], nvd=False)).run()


async def test_tracker_end_to_end(tmp_path: Path, no_sleep: Any) -> None:
    seed = tmp_path / "seed.txt"
    seed.write_text("dlclark/regexp2\ngitpython-developers/gitpython\n# comment\nnot-a-repo\n")
    store = Store()

    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        mock_world(router)
        r1 = await run_once(store, seed, no_sleep)
    assert r1.stopped_early is None
    assert r1.new_advisories == 3

    by_id = {i.adv.ghsa_id: i for i in items(store)}
    regexp2 = by_id["GHSA-wq9v-j77v-qr26"]
    assert regexp2.assessment.status is Status.LIMBO
    assert regexp2.assessment.cve_label is CveLabel.RESERVED
    gitpython = by_id["GHSA-f9j4-qggq-h239"]
    assert gitpython.assessment.status is Status.LIMBO
    assert gitpython.facts.uncited_cves == ("CVE-2026-110858",)  # VulnCheck CVE found via the delta log
    assert gitpython.assessment.cve_label is CveLabel.PUBLISHED_UNCITED
    assert "GHSA-83vg-56qc-22m7" not in by_id  # already reviewed when first seen: never tracked

    # second run: regexp2 gets reviewed; its repo answers 304 (ETag stored for this token)
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        mock_world(router, regexp2_reviewed=True)
        r2 = await run_once(store, seed, no_sleep)
    assert r2.not_modified >= 1
    assert any(e == "GHSA-wq9v-j77v-qr26: in limbo -> reviewed" for e in r2.events)
    with store.session() as s:
        assert s.get(Repo, "dlclark/regexp2").etag_token != "anonymous"  # type: ignore[union-attr]
        assert s.query(Event).count() >= 3

    m = metrics(store, datetime(2099, 1, 2, tzinfo=UTC))
    assert m["in_limbo"]["count"] == 1
    assert m["left_limbo"]["reviewed"] == 1

    # the feed: OSV-schema records for what's in limbo, factual fields only
    records, zipped = feed.build(items(store), m["generated_at"])
    assert [r["id"] for r in records] == ["GHSA-f9j4-qggq-h239"]
    rec = records[0]
    assert rec["aliases"] == ["CVE-2026-110858"]
    assert rec["affected"][0]["package"] == {"ecosystem": "PyPI", "name": "GitPython"}  # as the advisory names it
    assert "summary" not in rec and "details" not in rec
    assert "REDACTED" not in json.dumps(rec)
    with zipfile.ZipFile(io.BytesIO(zipped)) as z:
        assert z.namelist() == ["GHSA-f9j4-qggq-h239.json"]

    page = site.build(items(store), m, datetime(2099, 1, 2, tzinfo=UTC))
    assert "GHSA-f9j4-qggq-h239" in page and "REDACTED" not in page

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
    assert "**1 advisories in limbo** (−1 since the last report)" in second.markdown
    assert "1 reviewed by GitHub" in second.markdown
