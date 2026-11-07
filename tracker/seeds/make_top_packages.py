# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.27"]
# ///
"""Build the "top packages" seed: the GitHub source repos of the most-used packages in each ecosystem.

  uv run tracker/seeds/make_top_packages.py --top 1000    # -> tracker/seeds/top-packages.txt

Selection rule (PHASE0_PLAN §13.11, FINDINGS F-099): for each of npm, PyPI, Go, Maven, crates.io, NuGet, RubyGems and
Packagist, the top N packages by dependent repositories as ranked by ecosyste.ms, keeping those whose registry
metadata names a GitHub repository. Mechanical, so anyone can reproduce or dispute the list. The ranking is
ecosyste.ms data under CC BY-SA 4.0, so this file and the published watchlist carry that license (§13.12).
"""

from __future__ import annotations

import argparse
import re
import time
from datetime import date
from pathlib import Path

import httpx

OUT = Path(__file__).resolve().parent / "top-packages.txt"
REGISTRIES = ["npmjs.org", "pypi.org", "proxy.golang.org", "repo1.maven.org", "crates.io", "nuget.org",
              "rubygems.org", "packagist.org"]  # fmt: skip
GITHUB = re.compile(r"^(?:git\+)?(?:https?|git|ssh)://(?:[^@/]+@)?(?:www\.)?github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$", re.I)


def github_repo(url: str | None) -> str | None:
    m = GITHUB.match((url or "").strip())
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


def top(client: httpx.Client, registry: str, n: int) -> list[dict]:
    out: list[dict] = []
    per = min(n, 1000)
    for page in range(1, -(-n // per) + 1):
        for attempt in range(4):
            try:
                r = client.get(f"https://packages.ecosyste.ms/api/v1/registries/{registry}/packages",
                               params={"sort": "dependent_repos_count", "order": "desc", "per_page": per, "page": page})
                r.raise_for_status()
                break
            except httpx.HTTPError:
                if attempt == 3:
                    raise
                time.sleep(5 * (attempt + 1))
        batch = r.json()
        out += batch
        if len(batch) < per:
            break
    return out[:n]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=1000, help="packages per ecosystem")
    a = ap.parse_args()
    repos: set[str] = set()
    counts = []
    with httpx.Client(timeout=120, headers={"User-Agent": "limbowatch-seed (https://limbo.watch)"}) as client:
        for reg in REGISTRIES:
            found = {r for p in top(client, reg, a.top) if (r := github_repo(p.get("repository_url")))}
            counts.append(f"{reg} {len(found):,}")
            repos |= found
    head = [
        f"# Source repos of the top {a.top:,} packages per ecosystem by dependent repositories, as ranked by",
        "# ecosyste.ms (https://ecosyste.ms), GitHub repos only. Data: ecosyste.ms, CC BY-SA 4.0; this list is CC BY-SA 4.0.",
        f"# Generated {date.today()} by tracker/seeds/make_top_packages.py --top {a.top}. Repos per registry: {'; '.join(counts)}.",
        f"# {len(repos):,} distinct repos.",
    ]
    OUT.write_text("\n".join(head + sorted(repos)) + "\n")
    print(f"wrote {OUT} ({len(repos):,} repos)")


if __name__ == "__main__":
    main()
