# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx"]
# ///
"""Build the "top 100 projects" seed.

  uv run tracker/seeds/make_seed.py select              # -> tracker/seeds/top100-projects.txt
  # map their dependencies with the research pipeline (s1, s2), PROJECT_SET=top100
  uv run tracker/seeds/make_seed.py upstreams <snapshot> # -> tracker/seeds/top100-upstreams.txt

Selection rule: the most-starred public GitHub repositories (not archived, not forks) with at least one
lockfile the research pipeline can read, outside test/fixture/vendor directories. The rule is mechanical so
anyone can reproduce or dispute the list.
"""

from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys
import time
from datetime import date
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
RESEARCH = HERE.parent.parent / "research" / "2026-10-state-of-the-gap"
WANT = 100
# Same list as research/.../s1_inventory.py LOCKFILES, minus requirements*.txt (often docs or examples).
LOCKFILES = [
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock",
    "uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock", "pylock.toml",
    "go.mod", "Cargo.lock", "composer.lock", "Gemfile.lock",
]
SKIP_DIRS = {"testdata", "fixtures", "__fixtures__", "test-fixtures", "node_modules", "vendor", "examples", "example", "docs"}


def token() -> str:
    t = os.environ.get("GITHUB_TOKEN") or subprocess.run(["gh", "auth", "token"], capture_output=True, text=True).stdout.strip()
    if not t:
        raise SystemExit("need GITHUB_TOKEN or `gh auth login`")
    return t


def lockfiles(c: httpx.Client, slug: str, branch: str) -> tuple[list[str], bool]:
    r = c.get(f"/repos/{slug}/git/trees/{branch}", params={"recursive": "1"})
    if r.status_code != 200:
        return [], False
    tree = r.json()
    found = []
    for e in tree.get("tree", []):
        if e["type"] != "blob":
            continue
        parts = e["path"].split("/")
        if SKIP_DIRS & {p.lower() for p in parts[:-1]}:
            continue
        if any(fnmatch.fnmatch(parts[-1], pat) for pat in LOCKFILES):
            found.append(e["path"])
    return found, bool(tree.get("truncated"))


def select() -> None:
    c = httpx.Client(base_url="https://api.github.com", timeout=60,
                     headers={"Authorization": f"Bearer {token()}", "Accept": "application/vnd.github+json",
                              "User-Agent": "limbowatch-seed (+https://github.com/limbowatch/limbowatch)"})
    picked: list[tuple[str, int, str, int]] = []
    skipped = 0
    page = 1
    while len(picked) < WANT and page <= 10:  # search returns at most 1,000 results
        r = c.get("/search/repositories", params={"q": "stars:>10000 archived:false fork:false", "sort": "stars",
                                                    "order": "desc", "per_page": 100, "page": page})
        r.raise_for_status()
        for repo in r.json()["items"]:
            files, truncated = lockfiles(c, repo["full_name"], repo["default_branch"])
            if files:
                picked.append((repo["full_name"], repo["stargazers_count"], repo.get("language") or "", len(files)))
                print(f"{len(picked):3} {repo['full_name']} ({len(files)} lockfiles{', tree truncated' if truncated else ''})", file=sys.stderr)
                if len(picked) == WANT:
                    break
            else:
                skipped += 1
        page += 1
        time.sleep(2)  # search API: 30 requests/minute
    out = HERE / "top100-projects.txt"
    lines = [
        f"# Top {WANT} projects, selected {date.today()} by tracker/seeds/make_seed.py: the most-starred public GitHub repos",
        f"# (not archived, not forks) with a readable lockfile outside test/vendor/example/docs dirs. {skipped} higher-starred",
        "# repos had no such lockfile and were skipped. Columns: repo, stars at selection, primary language, lockfiles.",
        *(f"{s}\t{n}\t{lang}\t{k}" for s, n, lang, k in picked),
    ]
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out} ({len(picked)} projects, {skipped} skipped)", file=sys.stderr)


def upstreams(snapshot: str) -> None:
    mapping = json.loads((RESEARCH / "data" / snapshot / "mapping.json").read_text())["mapping"]
    repos = sorted({m["repo"].lower() for m in mapping.values() if m.get("repo")})
    out = HERE / "top100-upstreams.txt"
    out.write_text(f"# Upstream repos of the dependencies of tracker/seeds/top100-projects.txt (research snapshot {snapshot}),\n"
                   "# mapped via deps.dev / Go module paths. Regenerate with make_seed.py.\n" + "\n".join(repos) + "\n")
    print(f"wrote {out} ({len(repos)} repos)", file=sys.stderr)


if __name__ == "__main__":
    match sys.argv[1:]:
        case ["select"]:
            select()
        case ["upstreams", snap]:
            upstreams(snap)
        case _:
            raise SystemExit(__doc__)
