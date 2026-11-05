"""End-to-end test of the watcher's issue lifecycle against a throwaway local Gitea (PHASE0_PLAN §13.8).

Not part of the test suite: it needs Docker, OSV-Scanner on PATH, and the network (the live limbo feed).
Everything it creates lives in a container bound to 127.0.0.1 and is removed at the end.

    uv run python scripts/e2e_gitea.py

Uses a Go module pinned to github.com/andybalholm/brotli v1.2.1, affected by GHSA-c9gr-gmg4-2vqv
(in limbo on 2026-11-05, FINDINGS F-082). If that advisory has been reviewed since, pick another.
"""

from __future__ import annotations

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
        print("e2e passed")
    finally:
        sh("docker", "rm", "-f", NAME)


if __name__ == "__main__":
    main()
