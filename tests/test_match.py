"""Matching dependencies to advisories in limbo, from the feed and from polled repos (PHASE0_PLAN §5)."""

import io
import json
import zipfile
from datetime import UTC, datetime
from typing import Any

import httpx
import respx
from conftest import load
from limbowatch.http import HttpClient
from limbowatch.models import CveLabel, Dependency, Inventory, MatchKind, Unchecked
from limbowatch.watch.candidates import Index, from_feed_record, from_feed_zip
from limbowatch.watch.match import key, match
from limbowatch.watch.scan import fetch, scan

GH = "https://api.github.com"
NOW = datetime(2026, 11, 5, tzinfo=UTC)


def rec(ghsa: str, repo: str, *pkgs: tuple[str, str, str | None, str | None], valid: bool = True,
        entered: str | None = None, cve: str = CveLabel.NONE.value) -> dict[str, Any]:  # fmt: skip
    """A feed record: pkgs are (OSV ecosystem, name, vulnerable range, patched)."""
    return {
        "id": ghsa,
        "published": "2026-10-01T00:00:00Z",
        "aliases": [],
        "references": [{"type": "ADVISORY", "url": f"https://github.com/{repo}/security/advisories/{ghsa}"}],
        "affected": [
            {
                "package": {"ecosystem": eco, "name": name},
                "database_specific": {"vulnerable_version_range": rng, "patched_versions": fix, "name_valid": valid}
                | ({"name_as_entered": entered} if entered else {}),
            }
            for eco, name, rng, fix in pkgs
        ],
        "database_specific": {"limbowatch": {"repository": repo, "severity": "high", "cve": cve}},
    }


def dep(eco: str, name: str, version: str) -> Dependency:
    return Dependency(ecosystem=eco, name=name, version=version, source="lock", line=3)


def index(*records: dict[str, Any]) -> Index:
    ix = Index()
    for r in records:
        ix.add(from_feed_record(r))
    return ix


def test_package_match_and_version() -> None:
    ix = index(rec("GHSA-1", "lodash/lodash", ("npm", "lodash", "< 4.17.21", "4.17.21"), cve=CveLabel.RESERVED.value))
    [f] = match(dep("npm", "lodash", "4.17.20"), ix, None)
    assert f.affected is True and f.match is MatchKind.PACKAGE and f.cve is CveLabel.RESERVED
    assert f.severity == "high" and f.fixed == "4.17.21" and "in the range" in f.evidence
    assert match(dep("npm", "lodash", "4.17.21"), ix, None) == []
    assert f.key == key(dep("npm", "lodash", "4.0.0"), "GHSA-1")  # same issue across versions


def test_names_compare_as_scanners_do() -> None:
    ix = index(rec("GHSA-2", "yaml/pyyaml", ("PyPI", "py-yaml", "< 6.0", None), entered="Py_Yaml"))
    assert [f.ghsa_id for f in match(dep("pip", "PY.yaml", "5.4"), ix, None)] == ["GHSA-2"]


def test_unclear_ranges_are_possible_findings_never_passes() -> None:
    ix = index(
        rec("GHSA-3", "o/a", ("npm", "a", "tbd", None)),
        rec("GHSA-4", "o/b", ("npm", "b", "< 2.0.0", "1.5.0")),  # the range contradicts its own fix (F-051)
    )
    [a] = match(dep("npm", "a", "1.0.0"), ix, None)
    assert a.affected is None and "can't be evaluated" in a.evidence
    [b] = match(dep("npm", "b", "1.6.0"), ix, None)
    assert b.affected is None and "fixed version" in b.evidence


def test_go_packages_inside_a_module_and_major_versions() -> None:
    ix = index(
        rec("GHSA-5", "x/y", ("Go", "github.com/x/y/pkg/sub", "< 1.2.0", "1.2.0")),
        rec("GHSA-6", "x/y", ("Go", "github.com/x/y/v2", "< 2.1.0", "2.1.0")),
        rec("GHSA-12", "x/y", ("Go", "github.com/x/y/v2", "< 1.0.0", "1.0.0")),  # out of range either way
    )
    go = [c for cs in ix.by_repo.values() for c in cs]
    got = {f.ghsa_id: f.affected for f in match(dep("go", "github.com/x/y", "1.1.0"), ix, "x/y", go)}
    assert got == {"GHSA-5": True, "GHSA-6": None}  # /v2 is a different module (F-052)


def test_repository_match_only_when_the_name_is_unusable() -> None:
    ix = index(
        rec("GHSA-7", "labredescefetrj/wegia", ("Packagist", "WeGIA", "< 3.4.0", "3.4.0"), valid=False),
        rec("GHSA-8", "acme/mono", ("npm", "@acme/a", "< 9", None)),
        rec("GHSA-11", "napi-rs/napi-rs", ("crates.io", "napi", ">= 2.0.0", None)),
    )
    [f] = match(dep("composer", "labredescefetrj/wegia", "3.2.0"), ix, "labredescefetrj/wegia")
    assert f.match is MatchKind.REPOSITORY and f.affected is True and "WeGIA" in f.evidence
    assert match(dep("composer", "labredescefetrj/wegia", "3.4.0"), ix, "labredescefetrj/wegia") == []
    assert match(dep("npm", "@acme/b", "1.0.0"), ix, "acme/mono") == []  # names another package of the repo
    assert match(dep("npm", "@napi-rs/wasm-runtime", "1.1.6"), ix, "napi-rs/napi-rs") == []  # a crate, not this


def _zip(*records: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for r in records:
            z.writestr(f"{r['id']}.json", json.dumps(r))
    return buf.getvalue()


def test_feed_zip_round_trip() -> None:
    [c] = from_feed_zip(_zip(rec("GHSA-9", "o/r", ("crates.io", "serde", "< 1", None))))
    assert c.adv.packages[0].ecosystem == "rust" and c.source == "feed"


async def test_scan_polls_only_repos_the_tracker_doesnt_cover(no_sleep: Any) -> None:
    feed = _zip(rec("GHSA-10", "lodash/lodash", ("npm", "lodash", "< 4.17.21", "4.17.21")))
    inv = Inventory(
        dependencies=(
            dep("npm", "lodash", "4.17.20"),
            dep("go", "github.com/dlclark/regexp2", "1.11.5"),
            dep("npm", "unmapped", "1.0.0"),
        )
    )
    watch = {"lodash/lodash": "2026-11-04T13:00:00Z"}  # fresh: not polled again
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        source = {"projectKey": {"id": "github.com/lodash/lodash"}, "relationProvenance": "UNVERIFIED_METADATA",
                  "relationType": "SOURCE_REPO"}  # fmt: skip
        router.get(url__startswith="https://api.deps.dev/v3/systems/npm/packages/lodash/").mock(
            return_value=httpx.Response(200, json={"relatedProjects": [source]})
        )
        router.get(url__startswith="https://api.deps.dev/v3/systems/npm/packages/unmapped/").mock(
            return_value=httpx.Response(404, json={})
        )
        lodash = router.get(url__startswith=f"{GH}/repos/lodash/lodash/")
        router.get(url__startswith=f"{GH}/repos/dlclark/regexp2/security-advisories").mock(
            return_value=httpx.Response(200, json=load("repo_advisories_regexp2.json"))
        )
        router.get(url__startswith="https://api.osv.dev/v1/vulns/").mock(return_value=httpx.Response(404, json={}))
        router.get("https://cveawg.mitre.org/api/cve/CVE-2026-77299").mock(
            return_value=httpx.Response(404, json=load("cve_not_found.json"))
        )
        router.get("https://cveawg.mitre.org/api/cve-id/CVE-2026-77299").mock(
            return_value=httpx.Response(200, json=load("cve_id_CVE-2026-77299.json"))
        )
        async with HttpClient(sleep=no_sleep) as http:
            res = await scan(inv, http, feed_zip=feed, watchlist=watch, now=NOW)
    assert not lodash.called
    got = {(f.dependency.name, f.ghsa_id, f.source, f.cve) for f in res.findings}
    assert got == {
        ("lodash", "GHSA-10", "feed", CveLabel.NONE),
        ("github.com/dlclark/regexp2", "GHSA-wq9v-j77v-qr26", "github", CveLabel.RESERVED),
    }
    assert [(u.reason, u.name) for u in res.unresolved] == [(Unchecked.NO_REPO, "unmapped")]
    assert res.stats["repos_polled"] == 1 and res.stats["repos_on_watchlist"] == 1


async def test_fetch_reuses_the_cached_feed(tmp_path: Any, no_sleep: Any) -> None:
    url = "https://limbo.watch/feed/all.zip"
    with respx.mock(assert_all_mocked=True) as router:
        route = router.get(url).mock(
            side_effect=[httpx.Response(200, content=b"zip", headers={"etag": '"e1"'}), httpx.Response(304)]
        )
        async with HttpClient(sleep=no_sleep) as http:
            assert await fetch(http, url, tmp_path) == b"zip"
            assert await fetch(http, url, tmp_path) == b"zip"
    assert route.calls[1].request.headers["if-none-match"] == '"e1"'
