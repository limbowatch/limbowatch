"""End-to-end test of the watcher's GitLab issues on a real GitLab (FINDINGS Q19, F-087).

Not part of the test suite: it needs the network, OSV-Scanner on PATH and a GitLab token with `api` scope
in LIMBOWATCH_ISSUES_TOKEN (never printed). It uses a *private* project, created if missing:

    LIMBOWATCH_ISSUES_TOKEN=… uv run python scripts/e2e_gitlab.py [--url https://gitlab.com] [--project group/name]

Each run closes the issues it opened, so the project is left with closed confidential issues only.
Uses a Go module pinned to github.com/andybalholm/brotli v1.2.1 (GHSA-c9gr-gmg4-2vqv, in limbo on 2026-11-06).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

GO_MOD = "module example.com/e2e\n\ngo 1.22\n\nrequire github.com/andybalholm/brotli {v}\n"
GHSA = "GHSA-c9gr-gmg4-2vqv"


class GitLab:
    def __init__(self, url: str, token: str) -> None:
        self.base, self.token = url.rstrip("/") + "/api/v4", token

    def __call__(self, method: str, path: str, data: dict[str, Any] | None = None) -> Any:
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(self.base + path, method=method, data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
        return json.loads(body) if body else None


def scan(proj: Path, url: str, project: str, state: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["uv", "run", "limbowatch", "scan", str(proj), "--state", str(state), "--fail-on", "none",
                           "--no-upstream", "--issues", "gitlab", "--issues-url", url, "--issues-project", project],
                          capture_output=True, text=True, check=False)  # fmt: skip


def check(cond: bool, what: str, detail: str = "") -> None:
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        print(detail[-2000:])
        raise SystemExit(1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="https://gitlab.com")
    ap.add_argument("--project", default="limbowatch/limbowatch-e2e")
    a = ap.parse_args()
    token = os.environ.get("LIMBOWATCH_ISSUES_TOKEN") or ""
    if not token:
        raise SystemExit("set LIMBOWATCH_ISSUES_TOKEN")
    gl = GitLab(a.url, token)
    enc = urllib.parse.quote(a.project, safe="")
    try:
        p = gl("GET", f"/projects/{enc}")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        group, name = a.project.rsplit("/", 1)
        ns = gl("GET", f"/namespaces/{urllib.parse.quote(group, safe='')}")
        what = "Limbowatch end-to-end test of GitLab issues (scripts/e2e_gitlab.py)"
        p = gl("POST", "/projects", {"name": name, "path": name, "namespace_id": ns["id"], "visibility": "private",
                                      "description": what})  # fmt: skip
    check(p["visibility"] == "private", f"{a.project} is private")

    def ours(state: str = "all") -> list[dict[str, Any]]:
        return list(gl("GET", f"/projects/{p['id']}/issues?labels=limbowatch&state={state}&per_page=100") or [])

    for old in ours("opened"):  # leftovers from an interrupted run
        gl("PUT", f"/projects/{p['id']}/issues/{old['iid']}", {"state_event": "close"})
    before = {i["iid"] for i in ours()}

    with tempfile.TemporaryDirectory() as tmp:
        proj, st = Path(tmp) / "proj", Path(tmp) / "state.json"
        proj.mkdir()
        (proj / "go.mod").write_text(GO_MOD.format(v="v1.2.1"))

        r = scan(proj, a.url, a.project, st)
        print(r.stderr.strip())
        new = [i for i in ours() if i["iid"] not in before]
        check(len(new) == 1 and GHSA in new[0]["title"] and new[0]["state"] == "opened", "opens one issue", r.stderr)
        issue = new[0]
        check(issue["confidential"] is True, "the issue is confidential")
        check("<!-- limbowatch {" in issue["description"], "the issue carries the finding marker")
        check("limbowatch" in issue["labels"], "the issue has the limbowatch label")
        notes = len(gl("GET", f"/projects/{p['id']}/issues/{issue['iid']}/notes?per_page=100"))

        scan(proj, a.url, a.project, st)
        again = [i for i in ours() if i["iid"] not in before]
        notes2 = len(gl("GET", f"/projects/{p['id']}/issues/{issue['iid']}/notes?per_page=100"))
        check(len(again) == 1 and notes2 == notes, "a second run changes nothing")

        (proj / "go.mod").write_text(GO_MOD.format(v="v1.2.7"))
        r = scan(proj, a.url, a.project, st)
        print(r.stderr.strip())
        closed = gl("GET", f"/projects/{p['id']}/issues/{issue['iid']}")
        check(closed["state"] == "closed", "upgrading past the fix closes it", r.stderr)

        (proj / "go.mod").write_text(GO_MOD.format(v="v1.2.1"))
        r = scan(proj, a.url, a.project, st)
        reopened = [i for i in ours() if i["iid"] not in before]
        check(len(reopened) == 1 and reopened[0]["state"] == "opened" and reopened[0]["iid"] == issue["iid"],
              "finding it again reopens the same issue", r.stderr)  # fmt: skip

        gl("PUT", f"/projects/{p['id']}/issues/{issue['iid']}", {"state_event": "close"})
    print(f"e2e passed ({a.project}#{issue['iid']}, closed)")


if __name__ == "__main__":
    main()
