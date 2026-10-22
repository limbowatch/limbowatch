# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx", "univers"]
# ///
"""Stage 2: map each package-version to its upstream GitHub repo.

Chain: Go `github.com/` module path -> deps.dev relatedProjects SOURCE_REPO (attested provenance
preferred over UNVERIFIED_METADATA). Unmapped packages keep a reason; nothing is dropped.
Output: data/<snapshot>/mapping.json
"""

from __future__ import annotations

import asyncio
from collections import Counter
from urllib.parse import quote

from common import DATA, ECOSYSTEMS, SNAPSHOT, Http, load_json, log, save_json


async def map_one(http: Http, eco: str, name: str, version: str) -> dict:
    if eco == "Go" and name.startswith("github.com/"):
        parts = name.split("/")
        if len(parts) >= 3:
            return {"repo": f"{parts[1]}/{parts[2]}".lower(), "method": "go_module_path"}
    system = ECOSYSTEMS.get(eco, (None, None, None))[1]
    if not system:
        return {"repo": None, "method": f"no_mapper:{eco}"}
    url = (f"https://api.deps.dev/v3/systems/{system}/packages/{quote(name, safe='')}"
           f"/versions/{quote(version, safe='')}")
    status, body, _ = await http.get(url)
    if status != 200 or not isinstance(body, dict):
        return {"repo": None, "method": f"depsdev_{status}"}
    rel = [p for p in body.get("relatedProjects", []) if p.get("relationType") == "SOURCE_REPO"]
    rel.sort(key=lambda p: p.get("relationProvenance") == "UNVERIFIED_METADATA")  # attested first
    for p in rel:
        pid = p["projectKey"]["id"]
        if pid.startswith("github.com/"):
            return {"repo": pid.split("/", 1)[1].lower(), "method": f"depsdev:{p.get('relationProvenance')}"}
    if rel:
        return {"repo": None, "method": f"non_github:{rel[0]['projectKey']['id'].split('/')[0]}"}
    return {"repo": None, "method": "depsdev_no_repo"}


async def main() -> None:
    inv = load_json(DATA / SNAPSHOT / "inventory.json")["projects"]
    keys = sorted({(p["ecosystem"], p["name"], p["version"]) for v in inv.values() for p in v["packages"]
                   if p["version"] and p["ecosystem"] in ECOSYSTEMS})
    unresolved = sorted({(p["ecosystem"], p["name"], p["lockfile"]) for v in inv.values() for p in v["packages"]
                         if not p["version"] or p["ecosystem"] not in ECOSYSTEMS})
    log(f"{len(keys)} unique package-versions to map; {len(unresolved)} entries without a version or a supported ecosystem")
    http = Http(concurrency=48)
    try:
        res = await asyncio.gather(*(map_one(http, *k) for k in keys))
    finally:
        await http.close()
    mapping = {"|".join(k): r for k, r in zip(keys, res)}
    meth = Counter(r["method"].split(":")[0] if r["method"].startswith(("non_github", "no_mapper")) else r["method"] for r in res)
    repos = {r["repo"] for r in res if r["repo"]}
    log(f"mapped to GitHub: {sum(1 for r in res if r['repo'])}/{len(res)}; methods {dict(meth.most_common())}; unique repos {len(repos)}")
    save_json(DATA / SNAPSHOT / "mapping.json", {"mapping": mapping, "unresolved": [list(u) for u in unresolved]})


if __name__ == "__main__":
    asyncio.run(main())
