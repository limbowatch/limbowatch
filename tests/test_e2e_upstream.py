"""End to end, offline: the `limbowatch` CLI on a project that takes C code by git submodule and CMake, against a
recorded limbo feed (PHASE0_PLAN §13.18; FINDINGS F-138 to F-142).

Real: the upstream detectors, the commits-only clone and its git queries (from local repos), feed parsing, matching,
every output format, exit codes and org-wide mode. Stubbed: OSV-Scanner (not installed in CI; the project has no
lockfile anyway) and HTTP (respx; an unexpected request fails the test).
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
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


def test_publish_and_report_from_a_small_state(tmp_path: Path) -> None:
    """The tracker's `publish` and `report` on a state with one C advisory: the feed gives it a GIT package and GIT
    ranges from the resolved tags (F-138, F-140), and older watchers' reader takes it."""
    from limbowatch.store import Advisory, FactSnapshot, GitTag, Store
    from limbowatch.watch.candidates import from_feed_zip

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
    state, out = tmp_path / "state", tmp_path / "site"
    store.export_jsonl(state)
    r = run(["publish", "--state", str(state), "--out", str(out)])
    assert r.exit_code == 0, r.output
    z = zipfile.ZipFile(out / "feed" / "all.zip")
    rec = json.loads(z.read("GHSA-c000-0000-0001.json"))
    (a,) = rec["affected"]
    assert a["package"] == {"ecosystem": "GIT", "name": "https://github.com/acme/lib"}
    assert a["ranges"] == [{"type": "GIT", "repo": "https://github.com/acme/lib",
                            "events": [{"introduced": "0"}, {"fixed": "f" * 40}]}]  # fmt: skip
    (c,) = from_feed_zip((out / "feed" / "all.zip").read_bytes())
    assert c.adv.packages[0].vulnerable_version_range == "< 1.2.0"
    r = run(["report", "--state", str(state), "--out", str(tmp_path / "reports")])
    assert r.exit_code == 0, r.output
    assert (tmp_path / "reports" / "latest.md").exists()


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
        "source repository not checked (GitHub rate limit); checked against the limbo feed by name only"}  # fmt: skip


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
