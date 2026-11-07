# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.27"]
# ///
"""Phase 5, step 1 (FINDINGS Q20): what would watching the source repos of the most-used packages add?

1. Top packages per ecosystem from ecosyste.ms, ranked by dependent repositories (CC BY-SA 4.0 data, used here
   for measurement only; nothing from it is republished).
2. Their GitHub repos, compared with the tracker's watchlist (tracker-data branch).
3. A random sample of the repos not yet watched, polled on GitHub for published repository advisories; an
   advisory counts as in limbo when GitHub's reviewed list (tracker-data) doesn't have it.

Run from the repo root:  uv run research/2026-11-coverage/measure.py [--top 50000] [--sample 150]
Needs a GitHub token (GITHUB_TOKEN or `gh auth token`), never printed. Writes summary.json beside this file;
raw responses stay in .cache/ (gitignored).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import subprocess
from pathlib import Path

import httpx

HERE = Path(__file__).parent
CACHE = HERE / ".cache"
ECOSYSTEMS = {  # ecosyste.ms registry -> GHSA ecosystem
    "npmjs.org": "npm", "pypi.org": "pip", "proxy.golang.org": "go", "repo1.maven.org": "maven",
    "crates.io": "rust", "nuget.org": "nuget", "rubygems.org": "rubygems", "packagist.org": "composer",
}  # fmt: skip
BUCKETS = (1_000, 10_000, 50_000)
GITHUB = re.compile(r"^(?:git\+)?(?:https?|git|ssh)://(?:[^@/]+@)?(?:www\.)?github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$", re.I)
UA = {"User-Agent": "limbowatch-research (https://limbo.watch)"}


def github_repo(url: str | None) -> str | None:
    m = GITHUB.match((url or "").strip())
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


async def top_packages(client: httpx.AsyncClient, registry: str, n: int) -> list[dict]:
    out: list[dict] = []
    per = 1000
    for page in range(1, n // per + 1):
        f = CACHE / "ecosystems" / registry / f"{page:03d}.json"
        if f.exists():
            batch = json.loads(f.read_text())
        else:
            for attempt in range(4):
                try:
                    r = await client.get(f"https://packages.ecosyste.ms/api/v1/registries/{registry}/packages",
                                         params={"sort": "dependent_repos_count", "order": "desc", "per_page": per, "page": page})
                    r.raise_for_status()
                    break
                except httpx.HTTPError:
                    if attempt == 3:
                        raise
                    await asyncio.sleep(5 * (attempt + 1))
            batch = [{"name": p["name"], "repository_url": p.get("repository_url"),
                      "dependent_repos_count": p.get("dependent_repos_count")} for p in r.json()]  # fmt: skip
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(json.dumps(batch))
        out += batch
        if len(batch) < per:
            break
    return out


def tracker_file(name: str) -> list[dict]:
    text = subprocess.run(["git", "show", f"origin/tracker-data:state/{name}.jsonl"], capture_output=True, text=True, check=True).stdout
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def token() -> str:
    tok = os.environ.get("GITHUB_TOKEN") or subprocess.run(["gh", "auth", "token"], capture_output=True, text=True).stdout.strip()
    if not tok:
        raise SystemExit("needs GITHUB_TOKEN or gh auth")
    return tok


async def poll(client: httpx.AsyncClient, repo: str) -> dict:
    f = CACHE / "github" / (repo.replace("/", "__") + ".json")
    if f.exists():
        return json.loads(f.read_text())
    r = await client.get(f"https://api.github.com/repos/{repo}/security-advisories", params={"state": "published", "per_page": 100})
    rec = {"status": r.status_code, "advisories": []}
    if r.status_code == 200:
        rec["advisories"] = [{"ghsa_id": a["ghsa_id"], "published_at": a.get("published_at"),
                              "ecosystems": sorted({(v.get("package") or {}).get("ecosystem") or "" for v in a.get("vulnerabilities") or []})}
                             for a in r.json()]  # fmt: skip
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(rec))
    return rec


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=50_000)
    ap.add_argument("--sample", type=int, default=150, help="not-yet-watched repos to poll per ecosystem, from the top 10,000")
    a = ap.parse_args()
    subprocess.run(["git", "fetch", "-q", "origin", "tracker-data"], check=True)
    watched = {r["full_name"].lower() for r in tracker_file("repos")}
    reviewed = {r["ghsa_id"] for r in tracker_file("reviewed")}
    summary: dict = {"method": __doc__.strip().splitlines()[0], "top": a.top, "watchlist": len(watched), "ecosystems": {}}
    rng = random.Random(20261107)
    async with httpx.AsyncClient(timeout=90, headers=UA) as eco_client, httpx.AsyncClient(
        timeout=30, headers=UA | {"Authorization": f"Bearer {token()}", "Accept": "application/vnd.github+json"}) as gh:
        sem = asyncio.Semaphore(3)
        gsem = asyncio.Semaphore(8)

        async def fetch(reg: str) -> tuple[str, list[dict]]:
            async with sem:
                return reg, await top_packages(eco_client, reg, a.top)

        tops = dict(await asyncio.gather(*(fetch(reg) for reg in ECOSYSTEMS)))
        all_new: set[str] = set()
        for reg, pkgs in tops.items():
            eco = summary["ecosystems"][ECOSYSTEMS[reg]] = {"registry": reg, "packages_fetched": len(pkgs), "buckets": {}}
            for b in BUCKETS:
                part = pkgs[:b]
                repos = {r for p in part if (r := github_repo(p["repository_url"]))}
                new = repos - watched
                eco["buckets"][str(b)] = {
                    "packages": len(part),
                    "with_github_repo": sum(1 for p in part if github_repo(p["repository_url"])),
                    "distinct_repos": len(repos),
                    "already_watched": len(repos & watched),
                    "not_watched": len(new),
                    "min_dependent_repos": min((p.get("dependent_repos_count") or 0 for p in part), default=0),
                }
                if b == BUCKETS[-1]:
                    all_new |= new
            # yield: poll a sample of the top-10,000 repos we don't watch yet
            pool = sorted({r for p in pkgs[:10_000] if (r := github_repo(p["repository_url"]))} - watched)
            sample = rng.sample(pool, min(a.sample, len(pool)))
            async def one(repo: str) -> dict:
                async with gsem:
                    return await poll(gh, repo)

            recs = await asyncio.gather(*(one(r) for r in sample))
            ok = [x for x in recs if x["status"] == 200]
            advs = [adv for x in ok for adv in x["advisories"]]
            limbo = [adv for adv in advs if adv["ghsa_id"] not in reviewed]
            eco["sample"] = {
                "from": "top 10,000, not watched", "repos": len(sample), "polled_ok": len(ok),
                "status": {str(s): sum(1 for x in recs if x["status"] == s) for s in sorted({x["status"] for x in recs})},
                "repos_with_advisories": sum(1 for x in ok if x["advisories"]),
                "advisories": len(advs), "not_in_reviewed_list": len(limbo),
                "not_in_reviewed_list_since_2026": sum(1 for adv in limbo if (adv["published_at"] or "") >= "2026"),
            }  # fmt: skip
        summary["not_watched_union_top"] = len(all_new)
    (HERE / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    asyncio.run(main())
