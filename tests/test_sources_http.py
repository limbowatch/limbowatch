"""Sources and the HTTP client's failure paths, from recorded or synthetic responses (no network): git tags by
ls-remote (a local repo), OSV, NVD, GitHub pagination, polling with renamed repos, retries and rate limits."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from conftest import load
from limbowatch.http import BudgetExhausted, HttpClient
from limbowatch.sources import github, gitrefs, nvd, osv
from limbowatch.watch import upstream

GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           **dict.fromkeys(("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"), "t"),
           **dict.fromkeys(("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"), "t@example.com")}  # fmt: skip


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
async def test_ls_remote_tags_of_a_local_repo(tmp_path: Path) -> None:
    def git(*a: str) -> str:
        return subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True, text=True,
                              env=GIT_ENV).stdout.strip()  # fmt: skip

    git("init", "-q")
    (tmp_path / "f").write_text("x")
    git("add", "f")
    git("commit", "-qm", "x")
    head = git("rev-parse", "HEAD")
    git("tag", "-a", "v1.0", "-m", "v1.0")  # annotated: listed under its own object, peeled to the commit
    git("tag", "light")
    assert await gitrefs.tags(f"file://{tmp_path}") == {"v1.0": head, "light": head}
    assert await gitrefs.tags(f"file://{tmp_path}/missing") is None


async def test_osv(no_sleep: Any) -> None:
    with respx.mock() as r:
        r.get(f"{osv.API}/vulns/GHSA-a").mock(return_value=httpx.Response(200, json={}))
        r.get(f"{osv.API}/vulns/GHSA-b").mock(return_value=httpx.Response(404))
        r.get(f"{osv.API}/vulns/GHSA-c").mock(return_value=httpx.Response(400))
        hit = httpx.Response(200, json={"vulns": [{"id": "GHSA-x", "aliases": ["CVE-1"]}]})
        q = r.post(f"{osv.API}/query").mock(side_effect=[hit, httpx.Response(400)])
        b = r.post(f"{osv.API}/querybatch").mock(side_effect=[
            httpx.Response(200, json={"results": [{"vulns": [{"id": "CVE-2"}]}, {}]}),
            httpx.Response(200, json={"results": []})])  # fmt: skip
        async with HttpClient(sleep=no_sleep) as http:
            assert [await osv.present(http, g) for g in ("GHSA-a", "GHSA-b", "GHSA-c")] == [True, False, None]
            assert await osv.affecting(http, "npm", "x", "1.0.0") == {"GHSA-x", "CVE-1"}
            assert await osv.affecting(http, "npm", "x", "1.0.0") is None
            assert await osv.by_commit(http, ["a" * 40, "b" * 40]) == {"a" * 40: {"CVE-2"}, "b" * 40: set()}
            assert await osv.by_commit(http, ["a" * 40]) is None  # a short answer isn't trusted
    assert q.call_count == 2 and b.call_count == 2


async def test_nvd(no_sleep: Any) -> None:
    rec = {
        "vulnerabilities": [{"cve": {"vulnStatus": "Analyzed", "metrics": {"cvssMetricV31": [{"type": "Primary"}]}}}]
    }
    with respx.mock() as r:
        r.get(url__startswith=nvd.API).mock(side_effect=[
            httpx.Response(200, json=rec), httpx.Response(404, json={}), httpx.Response(400)])  # fmt: skip
        async with HttpClient(sleep=no_sleep, nvd_api_key="k") as http:
            assert await nvd.status(http, "CVE-1") == nvd.NvdStatus("Analyzed", True)
            assert await nvd.status(http, "CVE-2") == nvd.NvdStatus("absent", False)
            assert await nvd.status(http, "CVE-3") is None


async def test_github_follows_pages(no_sleep: Any) -> None:
    raw = load("repo_advisories_regexp2.json")
    url = f"{github.API}/repos/dlclark/regexp2/security-advisories?state=published&per_page=100"
    with respx.mock() as r:
        r.get(url).mock(return_value=httpx.Response(200, json=raw[:1], headers={
            "etag": '"e1"', "link": '<https://api.github.com/page2>; rel="next"'}))  # fmt: skip
        r.get("https://api.github.com/page2").mock(return_value=httpx.Response(200, json=raw[1:]))
        async with HttpClient(sleep=no_sleep) as http:
            res = await github.repo_advisories(http, "dlclark/regexp2")
    assert res.status == 200 and res.etag == '"e1"' and len(res.advisories or []) == len(raw)


async def test_polling_records_a_renamed_repo_and_stops_at_the_budget(no_sleep: Any) -> None:
    raw = load("repo_advisories_regexp2.json")[:1]  # its html_url names dlclark/regexp2
    with respx.mock() as r:
        r.get(url__startswith=f"{github.API}/repos/old/name/").mock(return_value=httpx.Response(200, json=raw))
        r.get(url__startswith=f"{osv.API}/vulns/").mock(return_value=httpx.Response(404))
        r.get(url__startswith="https://cveawg.mitre.org/").mock(return_value=httpx.Response(404))
        async with HttpClient(sleep=no_sleep) as http:
            got = await upstream.poll(http, {"old/name"})
        assert got.polled == {"old/name"} and got.aliases == {"old/name": "dlclark/regexp2"}
        async with HttpClient(sleep=no_sleep, github_budget=0) as http:
            stopped = await upstream.poll(http, {"a/b", "c/d"})
        assert stopped.not_polled == {"a/b", "c/d"} and not stopped.polled


async def test_retries_and_rate_limits(no_sleep: Any) -> None:
    slept: list[float] = []

    async def sleep(s: float) -> None:
        slept.append(s)

    with respx.mock() as r:
        r.get("https://x.example/a").mock(side_effect=[httpx.Response(503), httpx.Response(200, json={"ok": 1})])
        r.get("https://x.example/b").mock(side_effect=[httpx.ConnectError("down"), httpx.Response(200, text="plain")])
        r.get("https://x.example/c").mock(side_effect=httpx.ConnectError("down"))
        secondary = httpx.Response(403, text="secondary rate limit", headers={"retry-after": "3"})
        r.get(f"{github.API}/s").mock(side_effect=[secondary, httpx.Response(200, json=[])])
        r.get(f"{github.API}/limit").mock(return_value=httpx.Response(
            403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"}))  # fmt: skip
        r.put("https://x.example/req").mock(side_effect=[httpx.Response(429, headers={"retry-after": "1"}),
                                                          httpx.Response(201, json={"id": 1})])  # fmt: skip
        r.get("https://x.example/req-down").mock(side_effect=httpx.ConnectError("down"))
        async with HttpClient(sleep=sleep, max_rate_limit_wait=60) as http:
            assert (await http.get("https://x.example/a")).body == {"ok": 1}
            assert (await http.get("https://x.example/b")).body == "plain"
            down = await http.get("https://x.example/c")
            assert down.status == -1 and http.stats.failures == 1
            assert (await http.get(f"{github.API}/s")).ok
            with pytest.raises(BudgetExhausted):  # the reset is further away than we wait
                await http.get(f"{github.API}/limit")
            made = await http.request("PUT", "https://x.example/req", auth=("Authorization", "token x"))
            assert (made.status, made.body) == (201, {"id": 1})
            assert (await http.request("GET", "https://x.example/req-down", auth=None)).status == -1
    assert 4 in slept and 1 in slept  # retry-after honoured (+1 for GitHub's secondary limit)
