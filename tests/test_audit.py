"""The network record (`--audit-log`, `--show-network`): every way out is recorded, and no secret is (no network:
respx and local git repos)."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from limbowatch import audit
from limbowatch.hosts import HostKind, Project
from limbowatch.hosts import git as git_host
from limbowatch.http import HttpClient
from limbowatch.inventory import osv_scanner
from limbowatch.sources import gitrefs
from limbowatch.watch import gitgraph

GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           **dict.fromkeys(("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"), "t"),
           **dict.fromkeys(("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"), "t@example.com")}  # fmt: skip
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def repo(path: Path) -> Path:
    path.mkdir(parents=True)
    for args in (["init", "-q", "-b", "main"], ["commit", "-q", "--allow-empty", "-m", "x"], ["tag", "v1"]):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True, env=GIT_ENV)
    return path


class Collect:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def __call__(self, entry: dict[str, Any]) -> None:
        self.entries.append(entry)

    def of(self, kind: str) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["kind"] == kind]


def test_redact_drops_credentials_and_keeps_the_rest() -> None:
    assert audit.redact("https://user:pw@git.example.org/a/b.git") == "https://***@git.example.org/a/b.git"
    assert audit.redact("https://h/x?per_page=100&access_token=s3cret&apiKey=k") == (
        "https://h/x?per_page=100&access_token=%2A%2A%2A&apiKey=%2A%2A%2A"
    )
    assert audit.redact("https://api.osv.dev/v1/querybatch") == "https://api.osv.dev/v1/querybatch"
    assert audit.host_of("file:///tmp/x") == "local" and audit.host_of("https://limbo.watch/feed") == "limbo.watch"


def test_nothing_is_recorded_unless_asked() -> None:
    assert not audit.active()
    audit.http("GET", "https://limbo.watch/")  # no sink: nothing happens, nothing raises
    with audit.recording(sink := Collect()):
        assert audit.active()
    assert not audit.active() and [e["kind"] for e in sink.entries] == ["run", "summary"]


async def test_every_http_attempt_redirect_and_failure_is_recorded(no_sleep: Any) -> None:
    sink = Collect()
    with respx.mock() as r, audit.recording(sink, command="scan"):
        r.get("https://api.github.com/repos/o/r").mock(side_effect=[httpx.Response(502), httpx.Response(200, json={})])
        r.get("https://limbo.watch/old").mock(
            return_value=httpx.Response(301, headers={"location": "https://limbo.watch/new"})
        )
        r.get("https://limbo.watch/new").mock(return_value=httpx.Response(200, json={}))
        r.post("https://api.osv.dev/v1/querybatch").mock(side_effect=httpx.ConnectError("refused"))
        r.post("https://gitlab.example.com/api/v4/projects/1/issues").mock(return_value=httpx.Response(201, json={}))
        async with HttpClient("ghp_secret_token", sleep=no_sleep) as http:
            assert (await http.get("https://api.github.com/repos/o/r")).ok
            assert (await http.get("https://limbo.watch/old")).ok
            assert (await http.get("https://api.osv.dev/v1/querybatch", json_body={"q": 1}, patient=False)).status == -1
            await http.request("POST", "https://gitlab.example.com/api/v4/projects/1/issues",
                               auth=("PRIVATE-TOKEN", "glpat-secret"), json_body={"title": "t"})  # fmt: skip
    calls = sink.of("http")
    assert [(c["method"], c["url"], c.get("status") or c.get("error")) for c in calls] == [
        ("GET", "https://api.github.com/repos/o/r", 502),  # the retry is a call of its own
        ("GET", "https://api.github.com/repos/o/r", 200),
        ("GET", "https://limbo.watch/old", 301),  # and so is each redirect hop
        ("GET", "https://limbo.watch/new", 200),
        ("POST", "https://api.osv.dev/v1/querybatch", "ConnectError"),
        ("POST", "https://gitlab.example.com/api/v4/projects/1/issues", 201),
    ]
    assert calls[0]["credential"] == "authorization" and "credential" not in calls[2]  # the token isn't sent there
    assert calls[5]["credential"] == "private-token" and calls[5]["sent_bytes"] > 0
    assert all(c["ms"] >= 0 and c["time"].endswith("Z") for c in calls)
    assert sink.entries[0] == {**sink.entries[0], "kind": "run", "command": "scan"}
    assert sink.entries[-1]["hosts"] == {"api.github.com": 2, "limbo.watch": 2, "api.osv.dev": 1,
                                         "gitlab.example.com": 1}  # fmt: skip
    text = json.dumps(sink.entries)
    assert "secret" not in text and "ghp_" not in text and "glpat" not in text


@needs_git
async def test_git_ls_remote_clone_and_fetch_are_recorded(tmp_path: Path) -> None:
    up = repo(tmp_path / "up")
    sink = Collect()
    with audit.recording(sink):
        assert await gitrefs.tags(f"file://{up}")
        assert await gitrefs.tags(f"file://{tmp_path}/missing") is None
        assert gitgraph._clone(f"file://{up}", tmp_path / "cache" / "up.git") is not None
        assert gitgraph._clone(f"file://{up}", tmp_path / "cache" / "up.git") is not None  # cached: a fetch
        project = Project(HostKind.GIT, "file://", "up", f"file://{up}", "")
        git_host.clone(project, tmp_path / "checkout", "tok-secret")
    assert [(e["op"], e["url"].removeprefix(f"file://{tmp_path}"), e.get("exit")) for e in sink.of("git")] == [
        ("ls-remote", "/up", 0), ("ls-remote", "/missing", 128), ("clone", "/up", 0), ("fetch", "/up", 0),
        ("clone", "/up", 0),
    ]  # fmt: skip
    assert sink.of("git")[-1]["credential"] == "Authorization" and "tok-secret" not in json.dumps(sink.entries)
    assert sink.entries[-1]["hosts"] == {"local": 5}


def test_osv_scanner_resolution_is_recorded_with_its_hosts() -> None:
    sink = Collect()
    with audit.recording(sink):
        osv_scanner._resolve([sys.executable, "-c", "print('{}')"], timeout=30)
    (run,) = sink.of("osv-scanner")
    assert run["hosts"] == list(audit.MAVEN_RESOLVER_HOSTS) and run["exit"] == 0
    assert sink.entries[-1]["via_osv_scanner"] == sorted(audit.MAVEN_RESOLVER_HOSTS)


def test_json_lines_and_readable_lines() -> None:
    buf, lines = io.StringIO(), []
    with audit.recording(audit.JsonLines(buf), audit.Readable(lines.append)):
        audit.http("get", "https://user:pw@limbo.watch/feed/all.zip", status=200, ms=431.25)
        audit.http("POST", "https://api.github.com/x", error="ConnectTimeout", ms=10_000, credential="authorization")
        audit.git("clone", "https://github.com/madler/zlib.git", exit_code=0, ms=2_100)
        audit.osv_scanner("resolve pom.xml dependencies", audit.MAVEN_RESOLVER_HOSTS, exit_code=0, ms=5)
    rows = [json.loads(ln) for ln in buf.getvalue().splitlines()]
    assert [r["kind"] for r in rows] == ["run", "http", "http", "git", "osv-scanner", "summary"]
    assert rows[1]["url"] == "https://***@limbo.watch/feed/all.zip" and rows[1]["ms"] == 431.2
    assert lines == [
        "limbowatch: network: GET https://***@limbo.watch/feed/all.zip -> 200 (431.2 ms)",
        "limbowatch: network: POST https://api.github.com/x -> ConnectTimeout (10.0 s, sent authorization)",
        "limbowatch: network: git clone https://github.com/madler/zlib.git -> exit 0 (2.1 s)",
        "limbowatch: network: osv-scanner resolve pom.xml dependencies, which can contact api.deps.dev, "
        "repo.maven.apache.org, repo1.maven.org -> exit 0 (5 ms)",
        "limbowatch: network: 3 calls to api.github.com (1), github.com (1), limbo.watch (1); OSV-Scanner could "
        "contact api.deps.dev, repo.maven.apache.org, repo1.maven.org",
    ]
    lines.clear()
    with audit.recording(audit.Readable(lines.append)):
        pass
    assert lines == ["limbowatch: network: no network calls"]
