# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Phase 6, step 1: what the watcher's upstream detectors (limbowatch.inventory.upstream) and registry mapping
(limbowatch.watch.registries) make of the 85 surveyed projects (survey.py's clones in .cache/projects/).

Run from the repo root:  uv run python research/2026-11-upstream-watch/detectors.py
Contacts bcr.bazel.build, raw.githubusercontent.com and center2.conan.io (registry names only). Writes detectors.json
(counts only).
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from pathlib import Path

from limbowatch.http import HttpClient
from limbowatch.inventory import upstream as up
from limbowatch.models import Unchecked
from limbowatch.watch.registries import Registries

HERE = Path(__file__).parent
PROJ = HERE / ".cache" / "projects"


def outcome(u: up.Upstream) -> str:
    if u.repo and u.ref:
        return "repo and commit" if u.ref_is_commit else "repo and tag"
    if u.repo and u.version:
        return "repo and version (no tag)"
    if u.repo:
        return "repo only"
    return "repo unknown"


async def main() -> None:
    dets = {d.name.replace("__", "/"): up.detect(d) for d in sorted(PROJ.iterdir())}
    async with HttpClient() as http:
        resolved = await Registries(http).resolve([u for det in dets.values() for u in det.upstreams])
        requests = dict(http.stats.requests)
    by_kind: dict[str, Counter[str]] = {}
    projects: Counter[str] = Counter()
    vendored = 0
    for det in dets.values():
        seen = set()
        for u in det.upstreams:
            for r in resolved[u]:
                k = (r.kind, r.name, r.repo, r.ref or r.version)
                if k in seen:
                    continue
                seen.add(k)
                by_kind.setdefault(r.kind.value, Counter())[outcome(r)] += 1
        projects["with upstream sources" if det.upstreams else "without"] += 1
        vendored += sum(1 for x in det.unresolved if x.reason is Unchecked.VENDORED)
    total = Counter[str]()
    for c in by_kind.values():
        total.update(c)
    out = {"projects": dict(projects), "upstreams": dict(total), "by_kind": {k: dict(v) for k, v in by_kind.items()},
           "vendored_copies": vendored, "registry_requests": requests}  # fmt: skip
    (HERE / "detectors.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    asyncio.run(main())
