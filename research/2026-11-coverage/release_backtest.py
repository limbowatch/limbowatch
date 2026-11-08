# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.27"]
# ///
"""Backtest of release-triggered checks (docs/RELEASE_CHECKS.md, step 3) on the last 30 days of tracker data.

For every advisory published in the window whose package deps.dev knows, compare when it would have been found:
- release-triggered: checks about 20 hours and about 3 days after each release of the package (schedule.RELEASE_CHECKS);
- routine: the repo's tier at publication (daily if it already had an advisory in limbo, every 3 days if it had
  other advisories, weekly if none), found on average half an interval after publication;
- step 4's proposal: quiet repos re-checked every 30 days, plus release checks.

  uv run research/2026-11-coverage/release_backtest.py      (from the repo root; reuses release_timing.py's cache)
"""

from __future__ import annotations

import asyncio
import json
import statistics
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import httpx

HERE = Path(__file__).parent
CACHE = HERE / ".cache" / "depsdev"
SYSTEM = {"npm": "npm", "pip": "pypi", "go": "go", "maven": "maven", "rust": "cargo", "nuget": "nuget", "rubygems": "rubygems"}
CHECKS = (timedelta(hours=20), timedelta(days=3) - timedelta(hours=2))
INTERVAL = {"daily": 1.0, "3-day": 3.0, "weekly": 7.0}


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
    return [ts(v["publishedAt"]) for v in (data or {}).get("versions") or [] if v.get("publishedAt")] or None


def release_delay(pub: datetime, rel: list[datetime]) -> float | None:
    """Days from publication to the first release check at or after it, within 7 days; None if none."""
    hits = [r + c for r in rel for c in CHECKS if pub <= r + c <= pub + timedelta(days=7)]
    return (min(hits) - pub).total_seconds() / 86400 if hits else None


async def main() -> None:
    adv = tracker_file("advisories")
    reviewed = {r["ghsa_id"]: r.get("reviewed_at") for r in tracker_file("reviewed")}
    end = max(ts(r["finished_at"]) for r in tracker_file("runs") if r.get("finished_at"))
    by_repo: dict[str, list[tuple[datetime, str]]] = {}
    for a in adv:
        if p := a["data"].get("published_at"):
            by_repo.setdefault(a["repo"].lower(), []).append((ts(p), a["ghsa_id"]))
    pool = []
    for a in adv:
        d = a["data"]
        pkgs = {(p.get("ecosystem") or "", (p.get("name") or "").strip()) for p in d.get("packages") or []}
        if len(pkgs) != 1 or not d.get("published_at"):
            continue
        eco, name = next(iter(pkgs))
        pub = ts(d["published_at"])
        if eco in SYSTEM and name and end - timedelta(days=30) <= pub <= end - timedelta(days=7):
            earlier = [(t, g) for t, g in by_repo[a["repo"].lower()] if t < pub]
            in_limbo = any(reviewed.get(g) is None or ts(reviewed[g]) > pub for _, g in earlier)
            tier = "daily" if earlier and in_limbo else "3-day" if earlier else "weekly"
            pool.append((a["ghsa_id"], SYSTEM[eco], name, pub, tier))
    sem = asyncio.Semaphore(8)
    async with httpx.AsyncClient(timeout=60, headers={"User-Agent": "limbowatch-research (https://limbo.watch)"}) as client:

        async def one(item: tuple) -> tuple:
            async with sem:
                return item, await releases(client, item[1], item[2])

        results = await asyncio.gather(*(one(i) for i in pool))
    rows = [(item, release_delay(item[3], rel)) for item, rel in results if rel]
    out: dict = {"window": f"advisories published 2026-10-08 to {end - timedelta(days=7):%Y-%m-%d} (each had 7 days to be found)",
                 "advisories": len(pool), "with_release_data": len(rows), "by_tier": {}}  # fmt: skip
    for tier in ("daily", "3-day", "weekly"):
        part = [d for (item, d) in rows if item[4] == tier]
        caught = [d for d in part if d is not None]
        routine = INTERVAL[tier] / 2
        out["by_tier"][tier] = {
            "advisories": len(part),
            "caught_by_release_checks": len(caught),
            "share_caught": round(len(caught) / max(1, len(part)), 3),
            "release_delay_days_median": round(statistics.median(caught), 2) if caught else None,
            "routine_delay_days_average": routine,
            "sooner_than_routine": sum(1 for d in caught if d < routine),
        }
    weekly = [d for (item, d) in rows if item[4] == "weekly"]
    # step 4: quiet repos every 30 days plus release checks; found at min(release delay, 15 days on average)
    combined = [min(d, 15.0) if d is not None else 15.0 for d in weekly]
    out["step4_quiet_repos"] = {
        "now_weekly_average_days": 3.5,
        "proposed_average_days": round(statistics.mean(combined), 2) if combined else None,
        "found_later_than_today": sum(1 for d in weekly if d is None or d > 3.5),
        "found_sooner_than_today": sum(1 for d in weekly if d is not None and d < 3.5),
    }
    (HERE / "release_backtest.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    asyncio.run(main())
