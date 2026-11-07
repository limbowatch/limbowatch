# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.27"]
# ///
"""Phase 5, step 1 (FINDINGS Q21): are advisories published close to a release of the package they cover?

If most advisories appear within a day or two of a release, the tracker could check a repo when its package
releases instead of re-polling every repo blindly. Sample: advisories in the tracker state published in the last
30 days with one npm, PyPI, Go, Maven, crates.io or NuGet package; release times from deps.dev
(GET /v3/systems/{system}/packages/{name}, versions[].publishedAt).

  uv run research/2026-11-coverage/release_timing.py [--sample 300]   (from the repo root)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import httpx

HERE = Path(__file__).parent
CACHE = HERE / ".cache" / "depsdev"
SYSTEM = {"npm": "npm", "pip": "pypi", "go": "go", "maven": "maven", "rust": "cargo", "nuget": "nuget"}


def tracker_file(name: str) -> list[dict]:
    text = subprocess.run(["git", "show", f"origin/tracker-data:state/{name}.jsonl"], capture_output=True, text=True, check=True).stdout
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


async def releases(client: httpx.AsyncClient, system: str, name: str) -> list[datetime] | None:
    f = CACHE / system / (quote(name, safe="") + ".json")
    if f.exists():
        data = json.loads(f.read_text())
    else:
        r = await client.get(f"https://api.deps.dev/v3/systems/{system}/packages/{quote(name, safe='')}")
        data = r.json() if r.status_code == 200 else None
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps(data))
    if not data:
        return None
    return [ts(v["publishedAt"]) for v in data.get("versions") or [] if v.get("publishedAt")]


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=300)
    a = ap.parse_args()
    adv = tracker_file("advisories")
    end = max(ts(r["finished_at"]) for r in tracker_file("runs") if r.get("finished_at"))
    pool = []
    for x in adv:
        d = x["data"]
        pkgs = {(p.get("ecosystem") or "", p.get("name") or "") for p in d.get("packages") or []}
        if len(pkgs) != 1 or not d.get("published_at"):
            continue
        eco, name = next(iter(pkgs))
        if eco in SYSTEM and name and end - timedelta(days=30) <= ts(d["published_at"]) <= end:
            pool.append((x["ghsa_id"], SYSTEM[eco], name.strip(), ts(d["published_at"])))
    sample = random.Random(20261107).sample(pool, min(a.sample, len(pool)))
    sem = asyncio.Semaphore(8)
    async with httpx.AsyncClient(timeout=60, headers={"User-Agent": "limbowatch-research (https://limbo.watch)"}) as client:

        async def one(item: tuple) -> tuple:
            async with sem:
                return item, await releases(client, item[1], item[2])

        results = await asyncio.gather(*(one(i) for i in sample))
    known = [(i, rel) for i, rel in results if rel]
    gaps = []  # days from the advisory to the nearest release before it (negative) or after it (positive)
    within = {"release within 1 day before or after": 0, "within 3 days": 0, "within 7 days": 0}
    for (_, _, _, pub), rel in known:
        nearest = min(rel, key=lambda t: abs((t - pub).total_seconds()))
        g = (nearest - pub).total_seconds() / 86400
        gaps.append(round(g, 2))
        within["release within 1 day before or after"] += abs(g) <= 1
        within["within 3 days"] += abs(g) <= 3
        within["within 7 days"] += abs(g) <= 7
    summary = {
        "window": f"advisories published in the 30 days to {end:%Y-%m-%d}",
        "pool": len(pool), "sample": len(sample), "with_release_data": len(known),
        "counts": within,
        "share": {k: round(v / max(1, len(known)), 3) for k, v in within.items()},
        "release_before_advisory": sum(1 for g in gaps if g <= 0),
    }  # fmt: skip
    (HERE / "release_timing.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    asyncio.run(main())
