"""End-to-end test of the watcher on GitHub: issues and org-wide mode (PHASE0_PLAN §13.19; FINDINGS F-145 to F-147).

Not part of the test suite: it needs the network, OSV-Scanner on PATH and a GitHub token that can write issues in
a *private* repo and read the org (`gh auth token`, or LIMBOWATCH_ISSUES_TOKEN; never printed):

    PATH=research/2026-10-state-of-the-gap/.cache/bin:$PATH uv run python scripts/e2e_github.py [--repo owner/name]

The repo must exist and be private (limbowatch/limbowatch-e2e holds a go.mod pinned to brotli v1.2.1). Each run
closes the issues it opened. GitHub lists a new issue a few seconds late (F-147), so the script waits between runs,
as two CI runs of one repo should never overlap (a `concurrency` group).
Uses github.com/andybalholm/brotli v1.2.1 (GHSA-c9gr-gmg4-2vqv, in limbo on 2026-11-12).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

GO_MOD = "module example.com/e2e\n\ngo 1.22\n\nrequire github.com/andybalholm/brotli {v}\n"
GHSA = "GHSA-c9gr-gmg4-2vqv"
API = "https://api.github.com"
LAG = 10  # seconds: GitHub's issue list shows a new issue 3 to 7 seconds late (F-147)


class GitHub:
    def __init__(self, token: str) -> None:
        self.token = token

    def __call__(self, method: str, path: str, data: dict[str, Any] | None = None) -> Any:
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json"}
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(API + path, method=method, data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
        return json.loads(raw) if raw else None


def limbowatch(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["uv", "run", "limbowatch", *args], capture_output=True, text=True, check=False, env=env)


def check(cond: bool, what: str, detail: str = "") -> None:
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        print(detail[-3000:])
        raise SystemExit(1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="limbowatch/limbowatch-e2e")
    ap.add_argument("--pushless", default="google/brotli", help="a public repo the token's user can't push to")
    a = ap.parse_args()
    token = os.environ.get("LIMBOWATCH_ISSUES_TOKEN") or subprocess.run(
        ["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()  # fmt: skip
    gh = GitHub(token)
    owner = a.repo.split("/")[0]
    repo = gh("GET", f"/repos/{a.repo}")
    check(repo["visibility"] == "private" and repo["has_issues"], f"{a.repo} is private, with issues")
    env = {**os.environ, "LIMBOWATCH_ISSUES_TOKEN": token, "LIMBOWATCH_SOURCE_TOKEN": token}
    for v in ("GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_API_URL", "GITHUB_SERVER_URL", "CI_SERVER_URL"):
        env.pop(v, None)
    issue_args = ["--issues", "github", "--issues-project", a.repo, "--no-upstream", "--fail-on", "none"]

    def ours(state: str = "all") -> list[dict[str, Any]]:
        got = gh("GET", f"/repos/{a.repo}/issues?labels=limbowatch&state={state}&per_page=100") or []
        return [i for i in got if "pull_request" not in i]

    for old in ours("open"):  # leftovers from an interrupted run
        gh("PATCH", f"/repos/{a.repo}/issues/{old['number']}", {"state": "closed", "state_reason": "completed"})

    def mine() -> list[dict[str, Any]]:  # the finding's issue: opened by the first run, reopened by later ones
        return [i for i in ours() if GHSA in i["title"]]

    with tempfile.TemporaryDirectory() as tmp:
        proj, st = Path(tmp) / "proj", Path(tmp) / "state.json"
        proj.mkdir()
        (proj / "go.mod").write_text(GO_MOD.format(v="v1.2.1"))

        def scan(*extra: str) -> subprocess.CompletedProcess[str]:
            r = limbowatch("scan", str(proj), "--state", str(st), *issue_args, *extra, env=env)
            print("  " + r.stderr.strip().replace("\n", "\n  "))
            time.sleep(LAG)
            return r

        r = scan()
        new = mine()
        check(len(new) == 1 and new[0]["state"] == "open", "opens one issue (or reopens it from an earlier run)",
              r.stderr)  # fmt: skip
        issue = new[0]
        labels = {lb["name"] for lb in issue["labels"]}
        check({"limbowatch", "security"} <= labels, "the issue has the limbowatch and security labels", str(labels))
        check("<!-- limbowatch {" in issue["body"], "the issue carries the finding marker")
        notes = issue["comments"]

        r = scan()
        again = mine()
        now = gh("GET", f"/repos/{a.repo}/issues/{issue['number']}")
        check(len(again) == 1 and now["comments"] == notes, "a second run changes nothing", r.stderr)

        (proj / "go.mod").write_text(GO_MOD.format(v="v1.2.7"))
        r = scan()
        closed = gh("GET", f"/repos/{a.repo}/issues/{issue['number']}")
        check(closed["state"] == "closed" and closed["state_reason"] == "completed",
              "upgrading past the fix comments and closes it", r.stderr)  # fmt: skip

        (proj / "go.mod").write_text(GO_MOD.format(v="v1.2.1"))
        r = scan()
        reopened = mine()
        check(len(reopened) == 1 and reopened[0]["state"] == "open" and reopened[0]["number"] == issue["number"],
              "finding it again reopens the same issue", r.stderr)  # fmt: skip

        # org-wide mode: list the whole org (private repos too, with the token), check only the test repo
        names = [p["full_name"] for p in gh("GET", f"/orgs/{owner}/repos?type=all&per_page=100")]
        exclude = [x for n in names if n != a.repo for x in ("--exclude", n)]
        r = limbowatch("watch", "--github-org", owner, *exclude, "--no-upstream", "--fail-on", "none", "--issues",
                       "--issues-dry-run", "--format", "json", env=env)  # fmt: skip
        check(r.returncode == 0, "watch --github-org runs", r.stdout[-1500:] + r.stderr)
        rep = json.loads(r.stdout)
        (src,) = rep["sources"]
        check(src["error"] is None and src["note"] is None, "the org is listed in full", json.dumps(src))
        checked = [p["project"] for p in rep["projects"]]
        listed = len(checked) + len(rep["not_checked"])
        check(
            checked == [f"github.com/{a.repo}"] and listed == len(names),
            f"every repo listed ({listed}, private ones too), the test repo checked",
            json.dumps(rep["not_checked"]),
        )
        (pr,) = rep["projects"]
        check([f["ghsa_id"] for f in pr["report"]["findings"]] == [GHSA], "the repo's own go.mod is found affected")
        check("would create" not in r.stderr and "would reopen" not in r.stderr,
              "the dry run sees the open issue: nothing new", r.stderr)  # fmt: skip

        # a token whose user can't push to the repo: GitHub would drop the labels, so nothing is opened (F-150).
        # A dry run only reads; the public repo is one the token's user can read but not push to.
        perms = gh("GET", f"/repos/{a.pushless}")["permissions"]
        check(perms["pull"] and not perms["push"], f"the token's user can read {a.pushless} but not push to it")
        r = limbowatch("scan", str(proj), "--issues", "github", "--issues-project", a.pushless, "--issues-public",
                       "--issues-dry-run", "--fail-on", "none", env=env)  # fmt: skip
        check(r.returncode == 0 and f"warning: no new issues opened in {a.pushless}" in r.stderr
              and "wouldn't create (see the warning)" in r.stderr and "would create" not in r.stderr,
              "a token without push access opens nothing, and says why", r.stderr)  # fmt: skip

        gh("PATCH", f"/repos/{a.repo}/issues/{issue['number']}", {"state": "closed", "state_reason": "completed"})
    print(f"e2e passed ({a.repo}#{issue['number']}, closed)")


if __name__ == "__main__":
    main()
