# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx", "univers"]
# ///
"""Stage 3: list published repository security advisories for every mapped upstream repo.

One paginated `GET /repos/{owner}/{repo}/security-advisories?state=published` per repo.
Output: data/<snapshot>/repo_advisories.json (status per repo + advisories for repos that have any)
"""

from __future__ import annotations

import asyncio
from collections import Counter

from common import DATA, SNAPSHOT, Http, load_json, log, save_json


async def poll(http: Http, repo: str) -> tuple[str, str, list]:
    url = f"https://api.github.com/repos/{repo}/security-advisories?state=published&per_page=100"
    status, body, _ = await http.get(url)
    if status != 200:
        return repo, f"http_{status}", []
    advs = list(body)
    if len(advs) == 100:  # more pages
        advs = await http.gh_paginate(url)
    return repo, "ok", advs


async def main() -> None:
    mapping = load_json(DATA / SNAPSHOT / "mapping.json")["mapping"]
    repos = sorted({m["repo"] for m in mapping.values() if m["repo"]})
    log(f"polling {len(repos)} repos")
    http = Http(concurrency=8)
    try:
        res = await asyncio.gather(*(poll(http, r) for r in repos))
    finally:
        await http.close()
    status = {r: s for r, s, _ in res}
    advisories = {r: a for r, s, a in res if a}
    log(f"status {dict(Counter(status.values()))}; repos with advisories {len(advisories)}; "
        f"advisories {sum(len(a) for a in advisories.values())}; http {http.stats}")
    save_json(DATA / SNAPSHOT / "repo_advisories.json", {"status": status, "advisories": advisories})


if __name__ == "__main__":
    asyncio.run(main())
