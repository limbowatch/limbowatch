# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.27"]
# ///
"""Phase 6, step 0 (FINDINGS Q26): which limbo advisories without a package are about libraries other projects
build from, and can their fixed versions be found among the upstream's git tags?

1. The limbo feed (limbo.watch/feed/all.zip) and the tracker's advisories (tracker-data branch, state/advisories.jsonl).
   A record "has no package" when the feed's `affected` is empty.
2. A repo counts as a library when a vcpkg port, Bazel Central Registry module or conan-center recipe builds from it
   (.cache/indexes.json from indexes.py). That's a lower bound: projects also take code by submodule or copy.
3. For each library repo, its tags (`git ls-remote --tags`, no API quota). Each advisory's patched versions are
   looked up among them: exactly (`1.2.3`, `v1.2.3`), or by the numbers in the tag (`curl-8_10_0` → 8.10.0).

Run from the repo root:  uv run research/2026-11-upstream-watch/libraries.py
Writes libraries.json beside this file (counts only, no advisory text); raw data stays in .cache/ (gitignored).
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import httpx

HERE = Path(__file__).parent
CACHE = HERE / ".cache"
TAGS = CACHE / "tags"
REPO_ROOT = HERE.parent.parent
VERSION = re.compile(r"\d+(?:[._-]\d+)*(?:[.-]?(?:a|b|rc|alpha|beta|pre|p|patch)\.?\d*)?", re.I)


def feed() -> zipfile.ZipFile:
    f = CACHE / "feed-all.zip"
    if not f.exists():
        r = httpx.get("https://limbo.watch/feed/all.zip", follow_redirects=True, timeout=120,
                      headers={"User-Agent": "limbowatch-research (https://limbo.watch)"})
        r.raise_for_status()
        f.write_bytes(r.content)
    return zipfile.ZipFile(f)


def advisories() -> dict[str, dict]:
    f = CACHE / "advisories.jsonl"
    if not f.exists():
        subprocess.run(["git", "-C", str(REPO_ROOT), "fetch", "-q", "origin", "tracker-data"], check=True)
        f.write_bytes(subprocess.run(["git", "-C", str(REPO_ROOT), "show", "origin/tracker-data:state/advisories.jsonl"],
                                     check=True, capture_output=True).stdout)
    return {d["ghsa_id"]: d for d in map(json.loads, f.open())}


async def tags(repo: str, sem: asyncio.Semaphore) -> list[str] | None:
    """Tag names of github.com/<repo>, cached; None when the repo can't be listed."""
    f = TAGS / (repo.replace("/", "__") + ".txt")
    if f.exists():
        text = f.read_text()
        return None if text.startswith("#error") else text.split()
    async with sem:
        p = await asyncio.create_subprocess_exec(
            "git", "ls-remote", "--tags", "--refs", f"https://github.com/{repo}.git",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"})
        out, err = await p.communicate()
    if p.returncode:
        f.write_text("#error " + err.decode(errors="replace")[:200])
        return None
    names = [ln.split("refs/tags/", 1)[1] for ln in out.decode().splitlines() if "refs/tags/" in ln]
    f.write_text("\n".join(names))
    return names


def numbers(s: str) -> tuple[str, ...] | None:
    """The version in a tag or version string as a tuple of its parts, e.g. curl-8_10_0 → ('8', '10', '0')."""
    m = None
    for m in VERSION.finditer(s):
        pass  # the last version-looking run: "openssl-3.0.15" → 3.0.15, "v2" → 2
    if not m:
        return None
    parts = re.split(r"[._-]", m.group(0).lower())
    while len(parts) > 1 and parts[-1] == "0":  # 1.2.0 == 1.2
        parts.pop()
    return tuple(p for p in parts if p)


def fixes(pkgs: list[dict]) -> list[str]:
    out = []
    for p in pkgs:
        for v in re.split(r"[,;]|\bor\b|\band\b", p.get("patched_versions") or ""):
            v = v.strip().lstrip(">=v ").strip()
            if v and re.search(r"\d", v):
                out.append(v)
    return out


def lookup(v: str, names: list[str], by_num: dict[tuple[str, ...], list[str]]) -> str:
    if v in names or f"v{v}" in names:
        return "exact"
    n = numbers(v)
    if n and n in by_num:
        return "by numbers" if len(by_num[n]) == 1 else "by numbers, several tags"
    return "missing"


async def main() -> None:
    TAGS.mkdir(parents=True, exist_ok=True)
    idx = json.loads((CACHE / "indexes.json").read_text())
    in_index: dict[str, set[str]] = defaultdict(set)
    for name, d in idx.items():
        for e in d.values():
            if e["repo"] and e["repo"].startswith("github.com/"):
                in_index[e["repo"].removeprefix("github.com/")].add(name)
    z, advs = feed(), advisories()
    nopkg: dict[str, list[str]] = defaultdict(list)
    withpkg: Counter[str] = Counter()
    total = 0
    for n in z.namelist():
        r = json.loads(z.read(n))
        total += 1
        repo = r["database_specific"]["limbowatch"]["repository"].lower()
        if r["affected"]:
            withpkg[repo] += 1
        else:
            nopkg[repo].append(r["id"])
    libs = {r: ids for r, ids in nopkg.items() if r in in_index}
    sem = asyncio.Semaphore(16)
    tag_lists = dict(zip(libs, await asyncio.gather(*(tags(r, sem) for r in libs))))

    per_adv: Counter[str] = Counter()
    per_fix: Counter[str] = Counter()
    repo_ok: Counter[str] = Counter()
    for repo, ids in libs.items():
        names = tag_lists[repo]
        if names is None:
            per_adv["repo not listable"] += len(ids)
            continue
        if not names:
            per_adv["repo has no tags"] += len(ids)
            continue
        by_num: dict[tuple[str, ...], list[str]] = defaultdict(list)
        for t in names:
            if (k := numbers(t)) is not None:
                by_num[k].append(t)
        found_any = False
        for gid in ids:
            fx = fixes(((advs.get(gid) or {}).get("data") or {}).get("packages") or [])
            if not fx:
                per_adv["no patched version"] += 1
                continue
            res = [lookup(v, names, by_num) for v in fx]
            per_fix.update(res)
            if all(x != "missing" for x in res):
                per_adv["every fix found"] += 1
                found_any = True
            elif any(x != "missing" for x in res):
                per_adv["some fixes found"] += 1
                found_any = True
            else:
                per_adv["no fix found"] += 1
        repo_ok["some advisory mapped" if found_any else "none mapped"] += 1

    summary = {
        "feed_records": total,
        "package_less": {"records": sum(map(len, nopkg.values())), "repos": len(nopkg)},
        "package_less_in_an_index": {
            "records": sum(map(len, libs.values())), "repos": len(libs),
            "repos_by_index": dict(Counter(i for r in libs for i in in_index[r])),
        },
        "with_package_in_an_index": {"records": sum(withpkg[r] for r in withpkg if r in in_index),
                                     "repos": sum(1 for r in withpkg if r in in_index)},
        "index_repos_github": len(in_index),
        "advisories_by_fix_lookup": dict(per_adv),
        "fix_versions_by_lookup": dict(per_fix),
        "library_repos_by_lookup": dict(repo_ok),
        "top_library_repos": sorted(((r, len(i)) for r, i in libs.items()), key=lambda x: -x[1])[:30],
    }
    (HERE / "libraries.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "top_library_repos"}, indent=1))
    print("top:", summary["top_library_repos"][:20])


if __name__ == "__main__":
    asyncio.run(main())
