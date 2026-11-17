"""End to end, offline: the `limbowatch` CLI on a project that takes C code by git submodule and CMake, against a
recorded limbo feed (PHASE0_PLAN §13.18; FINDINGS F-138 to F-142).

Real: the upstream detectors, the commits-only clone and its git queries (from local repos), feed parsing, matching,
every output format, exit codes and org-wide mode. Stubbed: OSV-Scanner (not installed in CI; the project has no
lockfile anyway) and HTTP (respx; an unexpected request fails the test).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from limbowatch.classify import assess
from limbowatch.models import AdvisoryPackage, Facts, Inventory, RepoAdvisory
from limbowatch.publish import Item
from limbowatch.publish.feed import record
from limbowatch.watch import scan as watch_scan
from limbowatch.watch import upstream_check
from typer.testing import CliRunner

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           **dict.fromkeys(("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"), "t"),
           **dict.fromkeys(("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"), "t@example.com")}  # fmt: skip
NOW = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, env=GIT_ENV).stdout


def upstream(root: Path, repo: str, tags: list[str]) -> dict[str, str]:
    """A repo with one commit per tag (annotated, as zlib's are); tag → commit."""
    d = root / repo
    d.mkdir(parents=True)
    git(d, "init", "-q", "-b", "main")
    out = {}
    for i, tag in enumerate(tags):
        (d / "src.c").write_text(f"int v = {i};\n")
        git(d, "add", "src.c")
        git(d, "commit", "-qm", tag)
        git(d, "tag", "-a", tag, "-m", tag)
        out[tag] = git(d, "rev-parse", "HEAD").strip()
    return out


def project(root: Path, lib_commit: str) -> Path:
    p = root / "app"
    p.mkdir()
    git(p, "init", "-q", "-b", "main")
    (p / ".gitmodules").write_text(
        '[submodule "lib"]\n\tpath = third_party/lib\n\turl = https://github.com/acme/lib.git\n'
    )
    git(p, "update-index", "--add", "--cacheinfo", f"160000,{lib_commit},third_party/lib")
    (p / "CMakeLists.txt").write_text(
        "include(FetchContent)\nFetchContent_Declare(lib2 GIT_REPOSITORY https://github.com/acme/lib2.git "
        "GIT_TAG v2.0.0)\n"
    )
    git(p, "add", ".gitmodules", "CMakeLists.txt")
    git(p, "commit", "-qm", "app")
    return p


def advisory(gid: str, pkgs: tuple[AdvisoryPackage, ...], cve: str | None = None) -> dict[str, Any]:
    adv = RepoAdvisory(ghsa_id=gid, repo="acme/lib", state="published", severity="high", cve_id=cve, packages=pkgs,
                       published_at=datetime(2026, 11, 1, tzinfo=UTC),
                       html_url=f"https://github.com/acme/lib/security/advisories/{gid}")  # fmt: skip
    f = Facts(ghsa_id=gid, repo="acme/lib", repo_state="published", reviewed=False, in_osv=False, cited_cve=cve)
    return record(Item(adv, f, assess(adv, f), "2026-11-01T00:00:00Z"), NOW)


def feed_zip(records: list[dict[str, Any]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for r in records:
            z.writestr(f"{r['id']}.json", json.dumps(r))
    return buf.getvalue()


RECORDS = [
    # about the C code: affected below 1.2.0
    advisory(
        "GHSA-c000-0000-0001",
        (AdvisoryPackage(ecosystem="c", name="lib", vulnerable_version_range="< 1.2.0", patched_versions="1.2.0"),),
        cve="CVE-2026-1001",
    ),
    # about a registry package built from the same repo: its users' to match, not a submodule's
    advisory(
        "GHSA-c000-0000-0002", (AdvisoryPackage(ecosystem="pip", name="acme-lib", vulnerable_version_range="< 9"),)
    ),
]


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    ups = tmp_path / "upstreams"
    tags = upstream(ups, "acme/lib", ["v1.0.0", "v1.1.0", "v1.2.0"])
    upstream(ups, "acme/lib2", ["v2.0.0"])
    monkeypatch.setattr(upstream_check, "CLONE_URL", f"file://{ups}/{{repo}}")
    from limbowatch_cli import main as cli

    monkeypatch.setattr(cli.osv_scanner, "run", lambda *a, **k: Inventory(tool="osv-scanner 2.7.0"))
    monkeypatch.setattr(cli, "_check_osv_scanner", lambda binary: None)
    for v in ("LIMBOWATCH_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    return {"tmp": tmp_path, "tags": tags, "cache": tmp_path / "cache"}


def mocked(router: respx.MockRouter, osv_hits: list[str] | None = None) -> respx.Route:
    router.get(watch_scan.FEED_URL).mock(return_value=httpx.Response(200, content=feed_zip(RECORDS)))
    router.get(watch_scan.WATCHLIST_URL).mock(return_value=httpx.Response(200, json={
        "generated_at": NOW, "repos": {"acme/lib": NOW, "acme/lib2": NOW}}))  # fresh: not polled  # fmt: skip
    return router.post("https://api.osv.dev/v1/querybatch").mock(return_value=httpx.Response(200, json={
        "results": [{"vulns": [{"id": i} for i in osv_hits or []]}]}))  # fmt: skip


def run(args: list[str]) -> Any:
    from limbowatch_cli.main import app

    return CliRunner().invoke(app, args, catch_exceptions=False)


def test_scan_finds_the_submodule_affected_and_writes_every_report(world: dict[str, Any]) -> None:
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    out = world["tmp"] / "out"
    with respx.mock(assert_all_called=True) as router:
        osv = mocked(router)
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--fail-on", "low", "--color", "never",
                 *[x for f in ("json", "sarif", "markdown", "codequality", "junit", "csv", "cyclonedx", "html")
                   for x in ("-o", f"{f}={out}/report.{f}")]])  # fmt: skip
    assert r.exit_code == 1, r.output
    assert "1 dependency" not in r.output and "0 dependencies and 2 upstream sources scanned" in r.output
    assert "github.com/acme/lib" in r.output and "→ 1.2.0" in r.output  # the table, and "To fix"
    rep = json.loads((out / "report.json").read_text())
    (f,) = rep["findings"]
    assert (f["ghsa_id"], f["affected"], f["match"], f["source"]) == ("GHSA-c000-0000-0001", True, "upstream source",
                                                                     "feed")  # fmt: skip
    assert (f["dependency"]["name"], f["dependency"]["version"]) == (
        "github.com/acme/lib",
        world["tags"]["v1.1.0"][:12],
    )
    assert (f["path"], f["dependency"]["line"]) == (".gitmodules", 1)
    assert "is in the affected range" in f["evidence"]  # v1.1.0 is itself an affected release
    assert rep["summary"]["upstreams"] == 2 and rep["unresolved"] == []  # lib2 checked: nothing in limbo
    sarif = json.loads((out / "report.sarif").read_text())["runs"][0]["results"]
    assert sarif[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".gitmodules"
    assert json.loads((out / "report.codequality").read_text())[0]["location"]["path"] == ".gitmodules"
    for fmt in ("markdown", "junit", "csv", "cyclonedx", "html"):
        assert "GHSA-c000-0000-0001" in (out / f"report.{fmt}").read_text(), fmt
    sent = json.loads(osv.calls.last.request.content)  # only the pinned commit goes to OSV
    assert sent == {"queries": [{"commit": world["tags"]["v1.1.0"]}]}
    assert (world["cache"] / "git").is_dir()  # the clone is cached for the next run


def test_scan_passes_the_fixed_release_and_osv_by_commit_can_only_raise(world: dict[str, Any]) -> None:
    p = project(world["tmp"], world["tags"]["v1.2.0"])
    with respx.mock(assert_all_called=False) as router:
        mocked(router)
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--fail-on", "low"])
    assert r.exit_code == 0, r.output
    # OSV says the fixed commit is affected by the CVE the advisory cites: OSV's GIT ranges win (F-136)
    with respx.mock(assert_all_called=False) as router:
        mocked(router, osv_hits=["CVE-2026-1001"])
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--fail-on", "low", "--format", "json"])
    assert r.exit_code == 1
    (f,) = json.loads(r.stdout)["findings"]
    assert f["affected"] is True and "OSV lists" in f["evidence"]


def test_no_osv_commits_keeps_commits_local(world: dict[str, Any]) -> None:
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    with respx.mock(assert_all_called=False) as router:
        osv = mocked(router)
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--no-osv-commits", "--format", "json"])
    assert r.exit_code == 1 and not osv.called


def test_no_upstream_check_reports_every_source_as_unchecked(world: dict[str, Any]) -> None:
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    with respx.mock(assert_all_called=False) as router:
        router.get(watch_scan.FEED_URL).mock(return_value=httpx.Response(200, content=feed_zip(RECORDS)))
        router.get(watch_scan.WATCHLIST_URL).mock(return_value=httpx.Response(200, json={"repos": {}}))
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--no-upstream", "--format", "json"])
    rep = json.loads(r.stdout)
    assert r.exit_code == 0 and rep["findings"] == []
    assert sorted(u["reason"] for u in rep["unresolved"]) == ["upstream source not checked (--no-upstream)"] * 2


def test_inventory_lists_upstream_sources(world: dict[str, Any]) -> None:
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    r = run(["inventory", str(p)])
    assert r.exit_code == 0, r.output
    assert "2 upstream sources" in r.output and "github.com/acme/lib" in r.output and "CMakeLists.txt:2" in r.output
    js = json.loads(run(["inventory", str(p), "--format", "json"]).stdout)
    assert [(u["kind"], u["repo"]) for u in js["upstreams"]] == [("git submodule", "acme/lib"),
                                                                  ("CMake FetchContent", "acme/lib2")]  # fmt: skip


def test_watch_checks_upstream_sources_across_projects(world: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    from limbowatch.hosts import git as git_host

    p = project(world["tmp"], world["tags"]["v1.1.0"])
    # the project's https URL is cloned from the local repo (shallow, no submodules, as watch does)
    monkeypatch.setattr(git_host, "command", lambda project, dest: [
        "git", "clone", "--depth", "1", "--no-recurse-submodules", "--quiet", f"file://{p}", str(dest)])  # fmt: skip
    with respx.mock(assert_all_called=False) as router:
        mocked(router)
        r = run(["watch", "--git", "https://git.example.org/acme/app.git", "--cache", str(world["cache"]),
                 "--fail-on", "low", "--state", str(world["tmp"] / "state"), "--format", "json"])  # fmt: skip
    assert r.exit_code == 1, r.output
    rep = json.loads(r.stdout)
    (proj,) = rep["projects"]
    assert [f["ghsa_id"] for f in proj["report"]["findings"]] == ["GHSA-c000-0000-0001"]
    assert proj["report"]["summary"]["upstreams"] == 2 and rep["summary"]["findings"] == 1


def small_state(tmp_path: Path) -> Path:
    """A tracker state with one C advisory in limbo, for acme/lib below 1.2.0, its tags resolved."""
    from limbowatch.store import Advisory, FactSnapshot, GitTag, Store

    store = Store()
    pkg = AdvisoryPackage(ecosystem="c", name="lib", vulnerable_version_range="< 1.2.0", patched_versions="1.2.0")
    adv = RepoAdvisory(ghsa_id="GHSA-c000-0000-0001", repo="acme/lib", state="published", severity="high",
                       packages=(pkg,), published_at=datetime(2026, 11, 1, tzinfo=UTC),
                       html_url="https://github.com/acme/lib/security/advisories/GHSA-c000-0000-0001")  # fmt: skip
    facts = Facts(ghsa_id=adv.ghsa_id, repo="acme/lib", repo_state="published", reviewed=False, in_osv=False)
    with store.session() as s:
        s.add(Advisory(ghsa_id=adv.ghsa_id, repo=adv.repo, data=adv.model_dump(mode="json"), first_seen=NOW,
                       last_seen=NOW))  # fmt: skip
        s.add(FactSnapshot(ghsa_id=adv.ghsa_id, facts=facts.model_dump(mode="json"), facts_hash="h", observed_at=NOW))
        s.add(GitTag(repo="acme/lib", versions={"1.2.0": ["v1.2.0", "f" * 40]}, checked_at=NOW))
    store.export_jsonl(tmp_path / "state")
    return tmp_path / "state"


def test_publish_and_report_from_a_small_state(tmp_path: Path) -> None:
    """The tracker's `publish` and `report` on a state with one C advisory: the feed gives it a GIT package and GIT
    ranges from the resolved tags (F-138, F-140), and older watchers' reader takes it."""
    from limbowatch.watch.candidates import from_feed_zip

    state, out = small_state(tmp_path), tmp_path / "site"
    r = run(["publish", "--state", str(state), "--out", str(out)])
    assert r.exit_code == 0, r.output
    z = zipfile.ZipFile(out / "feed" / "all.zip")
    rec = json.loads(z.read("GHSA-c000-0000-0001.json"))
    (a,) = rec["affected"]
    assert a["package"] == {"ecosystem": "GIT", "name": "https://github.com/acme/lib"}
    assert a["ranges"] == [{"type": "GIT", "repo": "https://github.com/acme/lib",
                            "events": [{"introduced": "0"}, {"fixed": "f" * 40}]}]  # fmt: skip
    (c,) = from_feed_zip((out / "feed" / "all.zip").read_bytes())
    # each folder's SHA256SUMS.txt lists its downloads, as `sha256sum -c` reads it
    for folder, expect in (("feed", {"all.zip", "index.json", "watchlist.json"}), ("osv", {"limbo-db.zip"})):
        lines = (out / folder / "SHA256SUMS.txt").read_text().splitlines()
        sums = dict(reversed(line.split("  ", 1)) for line in lines)
        assert expect <= set(sums) and list(sums) == sorted(sums)
        assert all(hashlib.sha256((out / folder / n).read_bytes()).hexdigest() == h for n, h in sums.items())
    assert any(n.endswith("/all.zip") for n in (out / "osv" / "SHA256SUMS.txt").read_text().split())
    assert c.adv.packages[0].vulnerable_version_range == "< 1.2.0"
    r = run(["report", "--state", str(state), "--out", str(tmp_path / "reports")])
    assert r.exit_code == 0, r.output
    assert (tmp_path / "reports" / "latest.md").exists()

    # the next build, given this feed, leaves the unchanged record's file as it was (F-174)
    record_file = out / "feed" / "GHSA-c000-0000-0001.json"
    first = record_file.read_bytes()
    time.sleep(1.1)  # so that "now" differs from the first build's
    r = run(["publish", "--state", str(state), "--out", str(tmp_path / "site2"),
             "--previous-feed", str(out / "feed" / "all.zip")])  # fmt: skip
    assert r.exit_code == 0, r.output
    assert "feed: 1 of 1 records unchanged since the previous feed" in r.stderr
    assert (tmp_path / "site2" / "feed" / "GHSA-c000-0000-0001.json").read_bytes() == first
    assert (tmp_path / "site2" / "feed" / "all.zip").read_bytes() == (out / "feed" / "all.zip").read_bytes()

    # no previous feed to read: still published, with a warning, and modified is now
    (tmp_path / "bad.zip").write_text("<html>")
    for prev in (tmp_path / "missing.zip", tmp_path / "bad.zip"):
        r = run(["publish", "--state", str(state), "--out", str(tmp_path / "site3"), "--previous-feed", str(prev)])
        assert r.exit_code == 0, r.output
        assert f"warning: previous feed {prev} not read" in r.stderr
        assert (tmp_path / "site3" / "feed" / "GHSA-c000-0000-0001.json").read_bytes() != first


def test_issues_dry_run_for_an_upstream_finding(world: dict[str, Any]) -> None:
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    api = "https://gitea.example/api/v1/repos/acme/app"
    with respx.mock(assert_all_called=False) as router:
        mocked(router)
        router.get(api).mock(return_value=httpx.Response(200, json={"private": True}))
        router.get(f"{api}/labels").mock(return_value=httpx.Response(200, json=[]))
        router.get(f"{api}/issues").mock(return_value=httpx.Response(200, json=[]))
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--issues", "gitea", "--issues-url",
                 "https://gitea.example", "--issues-project", "acme/app", "--issues-dry-run",
                 "--format", "json"])  # fmt: skip
    assert r.exit_code == 1, r.output
    assert "would create: [limbo] GHSA-c000-0000-0001: upstream github.com/acme/lib" in r.stderr


# --- the second review (F-142) ---------------------------------------------------------------------------------------


def test_a_rate_limited_upstream_is_still_matched_against_the_feed(world: dict[str, Any]) -> None:
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    with respx.mock(assert_all_called=False) as router:
        router.get(watch_scan.FEED_URL).mock(return_value=httpx.Response(200, content=feed_zip(RECORDS)))
        router.get(watch_scan.WATCHLIST_URL).mock(return_value=httpx.Response(200, json={"repos": {}}))  # stale
        router.get(url__startswith="https://api.github.com/").mock(return_value=httpx.Response(
            403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"}))  # fmt: skip
        router.post("https://api.osv.dev/v1/querybatch").mock(return_value=httpx.Response(200, json={
            "results": [{"vulns": []}]}))  # fmt: skip
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--format", "json"])
    rep = json.loads(r.stdout)
    assert r.exit_code == 1, r.output  # the feed's advisory still fails the build
    assert [f["ghsa_id"] for f in rep["findings"]] == ["GHSA-c000-0000-0001"]
    assert {u["reason"] for u in rep["unresolved"]} == {
        "source repository not checked (GitHub rate limit); checked against the feed by name only"}  # fmt: skip


def test_a_path_that_isnt_utf8_doesnt_crash_the_scan(world: dict[str, Any]) -> None:
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    blob = git(p, "hash-object", "-w", "CMakeLists.txt").strip()
    subprocess.run(["git", "update-index", "--add", "--cacheinfo", f"100644,{blob},caf\xe9.txt".encode("latin-1")],
                   cwd=p, check=True, env=GIT_ENV)  # fmt: skip
    r = run(["inventory", str(p), "--format", "json"])
    assert r.exit_code == 0, r.output
    assert len(json.loads(r.stdout)["upstreams"]) == 2


def test_upstream_issues_close_only_when_their_source_was_checked(world: dict[str, Any]) -> None:
    from limbowatch.watch.issues import marker

    fixed = project(world["tmp"], world["tags"]["v1.2.0"])
    api = "https://gitea.example/api/v1/repos/acme/app"
    meta = {"key": "k1", "ghsa_id": "GHSA-c000-0000-0001", "ecosystem": "upstream", "package": "github.com/acme/lib"}
    issue = {"number": 7, "state": "open", "body": marker(meta), "labels": [{"name": "limbowatch"}]}

    def dry(*extra: str) -> Any:
        with respx.mock(assert_all_called=False) as router:
            mocked(router)
            router.get("https://api.osv.dev/v1/vulns/GHSA-c000-0000-0001").mock(return_value=httpx.Response(404))
            router.get(api).mock(return_value=httpx.Response(200, json={"private": True}))
            router.get(f"{api}/labels").mock(return_value=httpx.Response(200, json=[]))
            router.get(f"{api}/issues").mock(return_value=httpx.Response(200, json=[issue]))
            return run(["scan", str(fixed), "--cache", str(world["cache"]), "--issues", "gitea", "--issues-url",
                        "https://gitea.example", "--issues-project", "acme/app", "--issues-dry-run",
                        *extra])  # fmt: skip

    assert "would close: #7" in dry().stderr  # updated to the fixed release, and checked: fixed
    assert "would close" not in dry("--no-upstream").stderr  # not checked: left open


def test_a_vcpkg_port_pulled_in_twice_is_one_dependency() -> None:
    from limbowatch.models import Upstream, UpstreamKind
    from limbowatch.watch.candidates import Index
    from limbowatch.watch.scan import Shared, assess

    root = Upstream(kind=UpstreamKind.VCPKG, name="curl", source="vcpkg.json", line=3, baseline="b")
    other = root.model_copy(update={"name": "libpng", "line": 4})
    z1 = root.model_copy(update={"name": "zlib", "via": "a dependency of curl"})
    z2 = other.model_copy(update={"name": "zlib", "via": "a dependency of libpng"})
    sh = Shared(Index(), upstream_check=False)
    sh.upstreams = {root: [root, z1], other: [other, z2]}
    res = assess(Inventory(upstreams=(root, other)), sh)
    assert sorted(u.name for u in res.upstreams) == ["curl", "libpng", "zlib"]


# --- no feed (--feed none, F-214) ------------------------------------------------------------------------------------


def test_with_no_feed_the_scan_never_asks_limbo_watch(world: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """Every upstream repo is read on GitHub; limbo.watch isn't contacted (respx fails any request not mocked)."""
    from limbowatch_cli import main as cli
    from test_cli import _plain

    monkeypatch.setattr(cli, "_token", lambda: None)  # no token, not even from gh
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    gh = {"id": 1, "ghsa_id": "GHSA-c000-0000-0001", "cve_id": "CVE-2026-1001", "state": "published",
          "severity": "high", "published_at": "2026-11-01T00:00:00Z", "withdrawn_at": None,
          "html_url": "https://github.com/acme/lib/security/advisories/GHSA-c000-0000-0001",
          "vulnerabilities": [{"package": {"ecosystem": "other", "name": "lib"},
                               "vulnerable_version_range": "< 1.2.0", "patched_versions": "1.2.0"}]}  # fmt: skip
    with respx.mock(assert_all_called=False) as router:
        lib = router.get(url__startswith="https://api.github.com/repos/acme/lib/security-advisories").mock(
            return_value=httpx.Response(200, json=[gh]))  # fmt: skip
        router.get(url__startswith="https://api.github.com/repos/acme/lib2/security-advisories").mock(
            return_value=httpx.Response(200, json=[]))  # fmt: skip
        router.get("https://api.osv.dev/v1/vulns/GHSA-c000-0000-0001").mock(return_value=httpx.Response(404))
        router.get(url__startswith="https://cveawg.mitre.org/api/cve").mock(return_value=httpx.Response(404, json={}))
        router.post("https://api.osv.dev/v1/querybatch").mock(return_value=httpx.Response(200, json={
            "results": [{"vulns": []}]}))  # fmt: skip
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--feed", "none", "--format", "json"])
    assert lib.called
    rep = json.loads(r.stdout)
    assert r.exit_code == 1, r.output
    assert [(f["ghsa_id"], f["source"]) for f in rep["findings"]] == [("GHSA-c000-0000-0001", "github")]
    assert rep["feed"] is None and rep["feed_generated_at"] is None
    assert "read from GitHub by this scan" in rep["attribution"]
    assert "allows 60 requests an hour without a token" in r.stderr  # the fixture runs with no GitHub token
    assert not (world["cache"] / "all.zip").exists()

    monkeypatch.setenv("LIMBOWATCH_FEED", "none")  # the same from the environment, as the integrations pass it
    r = run(["scan", str(p), "--no-upstream"])
    assert r.exit_code == 2 and "--no-upstream would leave nothing to check" in _plain(r.output)
    r = run(["scan", str(p), "--feed", "http://feed.example/"])
    assert r.exit_code == 2 and "is plain http: use https" in _plain(r.output)
    r = run(["scan", str(p), "--feed", "https://feed.example/", "--verify-feed", "require"])
    assert r.exit_code == 2 and "a feed you build has none" in _plain(r.output)


# --- a feed of your own (--feed URL or directory, docs/OWN_FEED.md) --------------------------------------------------


def _quiet_github(router: respx.MockRouter) -> None:
    """The project's two upstream repos have no advisories of their own on GitHub; OSV knows no commit."""
    for repo in ("acme/lib", "acme/lib2"):
        router.get(url__startswith=f"https://api.github.com/repos/{repo}/security-advisories").mock(
            return_value=httpx.Response(200, json=[]))  # fmt: skip
    router.post("https://api.osv.dev/v1/querybatch").mock(return_value=httpx.Response(200, json={
        "results": [{"vulns": []}]}))  # fmt: skip


def test_a_feed_built_with_publish_feed_only_is_scanned_from_a_directory_or_a_url(
    world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`publish --feed-only` writes the feed and nothing of the website; `scan --feed` reads it from a directory, or
    from a URL, with no request to limbo.watch and no attestation lookup (there's none to check)."""
    state, out = small_state(world["tmp"]), world["tmp"] / "own"
    r = run(["publish", "--state", str(state), "--out", str(out), "--feed-only"])
    assert r.exit_code == 0, r.output
    assert "(feed only)" in r.stdout and not (out / "index.html").exists() and not (out / "assets").exists()
    for name in ("all.zip", "watchlist.json", "index.json", "SHA256SUMS.txt"):
        assert (out / "feed" / name).exists(), name
    assert (out / "osv" / "limbo-db.zip").exists()

    p = project(world["tmp"], world["tags"]["v1.1.0"])
    with respx.mock(assert_all_called=False) as router:  # anything not mocked, limbo.watch included, fails the test
        _quiet_github(router)
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--feed", str(out / "feed"), "--format", "json"])
    rep = json.loads(r.stdout)
    assert r.exit_code == 1, r.output
    assert [(f["ghsa_id"], f["source"]) for f in rep["findings"]] == [("GHSA-c000-0000-0001", "feed")]
    assert rep["feed"] == str((out / "feed").resolve()) and rep["feed_generated_at"]
    assert "via a feed built with Limbowatch" in rep["attribution"]

    base = "https://feeds.acme.example/limbo/"
    monkeypatch.setenv("LIMBOWATCH_VERIFY_FEED", "auto")  # auto still asks nothing of GitHub for an own feed
    with respx.mock(assert_all_called=False) as router:
        _quiet_github(router)
        zipped = router.get(base + "all.zip").mock(
            return_value=httpx.Response(200, content=(out / "feed" / "all.zip").read_bytes()))  # fmt: skip
        router.get(base + "watchlist.json").mock(
            return_value=httpx.Response(200, content=(out / "feed" / "watchlist.json").read_bytes()))  # fmt: skip
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--feed", base + "all.zip", "-o", "table"])
    assert zipped.called and r.exit_code == 1, r.output
    assert f"feed {base} of" in r.stdout and "GHSA-c000-0000-0001" in r.stdout
    assert not (world["cache"] / "all.zip").exists()  # its own folder: never mixed with the limbo feed's files
    assert list((world["cache"] / "feeds").glob("*/all.zip"))

    r = run(["scan", str(p), "--cache", str(world["cache"]), "--feed", str(world["tmp"] / "nowhere")])
    assert r.exit_code == 2 and "publish --feed-only" in r.stderr


@pytest.mark.parametrize(
    ("spec", "base", "local"),
    [
        ("limbo.watch", "https://limbo.watch/feed/", False),
        ("https://limbo.watch/feed/all.zip", "https://limbo.watch/feed/", False),
        ("https://feeds.acme.example/limbo", "https://feeds.acme.example/limbo/", False),
        ("https://feeds.acme.example/limbo/all.zip", "https://feeds.acme.example/limbo/", False),
        ("http://localhost:8080/feed/", "http://localhost:8080/feed/", False),
    ],
)
def test_feed_source(spec: str, base: str, local: bool) -> None:
    src = watch_scan.feed_source(spec)
    assert src is not None and (src.base, src.local) == (base, local)
    assert src.feed == base + "all.zip" and src.watchlist == base + "watchlist.json"
    assert src.limbo == (base == "https://limbo.watch/feed/")


def test_feed_source_refuses(tmp_path: Path) -> None:
    assert watch_scan.feed_source("none") is None
    local = watch_scan.feed_source(str(tmp_path / "feed" / "all.zip"))
    assert local is not None and local.local and local.feed == str((tmp_path / "feed" / "all.zip").resolve())
    assert local.cache(tmp_path) is not None and local.cache(tmp_path) != tmp_path
    for bad, why in (("http://feeds.acme.example/", "plain http"), ("ftp://x/feed/", "https:// URL"),
                     ("https://u:p@feeds.acme.example/", "no credentials"), ("https://x/feed/?t=1", "query"),
                     ("", "empty")):  # fmt: skip
        with pytest.raises(ValueError, match=why):
            watch_scan.feed_source(bad)


def test_repos_lists_a_projects_source_repositories(world: dict[str, Any]) -> None:
    """`limbowatch repos` on the project: its two upstream sources' repos; no GitHub request (respx fails any)."""
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    out = world["tmp"] / "seeds" / "seeds.txt"
    with respx.mock():
        r = run(["repos", str(p), "-o", str(out)])
    assert r.exit_code == 0, r.output
    assert [ln for ln in out.read_text().splitlines() if not ln.startswith("#")] == ["acme/lib", "acme/lib2"]
    assert "repos: 2 GitHub repositories from 1 project(s)" in r.stderr
    with respx.mock():
        r = run(["repos", "--git", "http://git.example/acme/app.git", "-o", str(out)])
    assert r.exit_code == 2  # nothing could be listed or read: an error, not an empty seed file
