"""End-to-end test of the watcher's issue lifecycle against a throwaway local Gitea (PHASE0_PLAN §13.8).

Not part of the test suite: it needs Docker, OSV-Scanner on PATH, and the network (the live limbo feed).
Everything it creates lives in a container bound to 127.0.0.1 and is removed at the end. It also runs org-wide
mode (`limbowatch watch`) on a private org: listing and cloning with a token, per-project state and issues.

    uv run python scripts/e2e_gitea.py

Uses a Go module pinned to github.com/andybalholm/brotli v1.2.1, affected by GHSA-c9gr-gmg4-2vqv
(in limbo on 2026-11-05, FINDINGS F-082). If that advisory has been reviewed since, pick another.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

IMAGE = "gitea/gitea:28.3.0"
NAME = "limbowatch-e2e-gitea"
PORT = 13001
BASE = f"http://127.0.0.1:{PORT}"
USER = "lwtest"
GO_MOD = "module example.com/e2e\n\ngo 1.22\n\nrequire github.com/andybalholm/brotli {v}\n"
GHSA = "GHSA-c9gr-gmg4-2vqv"


def sh(*cmd: str, **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False, **kw)


def api(token: str, method: str, path: str, data: Any = None) -> Any:
    req = urllib.request.Request(f"{BASE}/api/v1{path}", method=method, data=json.dumps(data).encode() if data else None,
                                 headers={"Authorization": f"token {token}", "Content-Type": "application/json"})  # fmt: skip
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (a local container)
        body = r.read()
    return json.loads(body) if body else None


def scan(project: Path, repo: str, token: str, state: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ | {"LIMBOWATCH_ISSUES_TOKEN": token}
    return sh("uv", "run", "limbowatch", "scan", str(project), "--state", str(state), "--fail-on", "none",
              "--issues", "gitea", "--issues-url", BASE, "--issues-project", repo, env=env)  # fmt: skip


def issues(token: str, repo: str) -> list[dict[str, Any]]:
    return list(api(token, "GET", f"/repos/{repo}/issues?state=all&type=issues&labels=limbowatch") or [])


def check(cond: bool, what: str) -> None:
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        raise SystemExit(1)


def watch(token: str | None, state: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("LIMBOWATCH_")}
    if token:
        env |= {"LIMBOWATCH_SOURCE_TOKEN": token, "LIMBOWATCH_ISSUES_TOKEN": token}
    return sh("uv", "run", "limbowatch", "watch", "--gitea-org", f"{BASE}/lworg", "--state", str(state),
              "--fail-on", "none", "-f", "json", *extra, env=env)  # fmt: skip


def org_wide(token: str, tmp: Path) -> None:
    """`limbowatch watch` on a private org: listed and cloned with the token only, issues in each repo."""
    api(token, "POST", "/orgs", {"username": "lworg", "visibility": "private"})
    for name in ("svc", "old"):
        api(token, "POST", "/orgs/lworg/repos", {"name": name, "private": True, "auto_init": True,
                                                 "default_branch": "main"})  # fmt: skip
        content = base64.b64encode(GO_MOD.format(v="v1.2.1").encode()).decode()
        api(token, "POST", f"/repos/lworg/{name}/contents/go.mod", {"content": content, "message": "go.mod"})
    api(token, "PATCH", "/repos/lworg/old", {"archived": True})
    api(token, "POST", "/orgs/lworg/repos", {"name": "empty", "private": True})

    anon = watch(None, tmp / "w0")
    check(anon.returncode == 2, f"without a token, the private org can't be listed (exit {anon.returncode})")

    r = watch(token, tmp / "w1", "--issues")
    print(r.stderr.strip())
    doc = json.loads(r.stdout)
    checked = {p["project"]: p for p in doc["projects"]}
    skipped = {p["project"]: p["reason"] for p in doc["not_checked"]}
    host = f"127.0.0.1:{PORT}"
    check(list(checked) == [f"{host}/lworg/svc"] and checked[f"{host}/lworg/svc"]["error"] is None,
          "the private repo is listed and cloned with the token")  # fmt: skip
    check(skipped.get(f"{host}/lworg/old", "").startswith("archived") and
          skipped.get(f"{host}/lworg/empty") == "empty repository", "archived and empty repos are listed, not checked")  # fmt: skip
    found = [f["ghsa_id"] for f in checked[f"{host}/lworg/svc"]["report"]["findings"]]
    check(GHSA in found, "the org-wide run finds the advisory")
    got = issues(token, "lworg/svc")
    check(len(got) == 1 and GHSA in got[0]["title"], "an issue opens in the project itself")
    check((tmp / "w1" / host.replace(":", "_") / "lworg" / "svc.json").exists(), "state is kept per project")
    r = watch(token, tmp / "w1", "--issues")
    again = json.loads(r.stdout)["projects"][0]["report"]["changes"]
    check(again == [] and len(issues(token, "lworg/svc")) == 1, "a second run changes nothing")


def main() -> None:
    sh("docker", "rm", "-f", NAME)
    started = sh("docker", "run", "-d", "--name", NAME, "-p", f"127.0.0.1:{PORT}:3000",
                 "-e", "GITEA__security__INSTALL_LOCK=true", "-e", "GITEA__database__DB_TYPE=sqlite3", IMAGE)  # fmt: skip
    if started.returncode:
        sys.exit(f"docker run failed: {started.stderr.strip()}")
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"{BASE}/api/v1/version", timeout=2)  # noqa: S310
                break
            except OSError:
                time.sleep(1)
        password = secrets.token_urlsafe(18)
        sh("docker", "exec", "-u", "git", NAME, "gitea", "admin", "user", "create", "--username", USER,
           "--password", password, "--email", "lwtest@example.test", "--admin", "--must-change-password=false")  # fmt: skip
        token = sh("docker", "exec", "-u", "git", NAME, "gitea", "admin", "user", "generate-access-token",
                   "--username", USER, "--token-name", "e2e", "--scopes", "all", "--raw").stdout.strip()  # fmt: skip
        api(token, "POST", "/user/repos", {"name": "app", "private": True})
        api(token, "POST", "/user/repos", {"name": "public-app", "private": False})
        with tempfile.TemporaryDirectory() as tmp:
            proj, st = Path(tmp) / "proj", Path(tmp) / "state.json"
            proj.mkdir()
            (proj / "go.mod").write_text(GO_MOD.format(v="v1.2.1"))
            repo = f"{USER}/app"

            r = scan(proj, repo, token, st)
            print(r.stderr.strip())
            got = issues(token, repo)
            check(len(got) == 1 and GHSA in got[0]["title"] and got[0]["state"] == "open", "opens one issue")
            check("<!-- limbowatch {" in got[0]["body"], "the issue carries the finding marker")

            r = scan(proj, repo, token, st)
            got2 = issues(token, repo)
            check(len(got2) == 1 and got2[0]["comments"] == got[0]["comments"], "a second run changes nothing")

            (proj / "go.mod").write_text(GO_MOD.format(v="v1.2.7"))
            r = scan(proj, repo, token, st)
            print(r.stderr.strip())
            got3 = issues(token, repo)
            check(got3[0]["state"] == "closed" and got3[0]["comments"] == 1, "upgrading past the fix closes it")

            (proj / "go.mod").write_text(GO_MOD.format(v="v1.2.1"))
            scan(proj, repo, token, st)
            got4 = issues(token, repo)
            check(len(got4) == 1 and got4[0]["state"] == "open", "finding it again reopens the same issue")

            r = scan(proj, f"{USER}/public-app", token, Path(tmp) / "state2.json")
            check(issues(token, f"{USER}/public-app") == [] and "are public" in r.stderr,
                  "a public repo gets no issues by default")  # fmt: skip

            org_wide(token, Path(tmp))
        print("e2e passed")
    finally:
        sh("docker", "rm", "-f", NAME)


if __name__ == "__main__":
    main()
