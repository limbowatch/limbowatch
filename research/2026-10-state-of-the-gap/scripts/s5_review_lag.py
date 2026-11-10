# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx", "univers", "limbowatch"]
#
# [tool.uv.sources]
# limbowatch = { path = "../../../packages/core" }
# ///
"""Stage 5: review lag for recently reviewed advisories that originated as repo advisories.

The global `published_at` equals `github_reviewed_at` (F-009), so lag = repo advisory
`published_at` -> global `github_reviewed_at`. Also CVE record datePublished (CVE Services).
Sample: the most recent REVIEW_SAMPLE reviewed advisories (sorted by published = reviewed time).
Output: data/<snapshot>/review_lag.json
"""

from __future__ import annotations

import asyncio
from collections import Counter

from common import DATA, SNAPSHOT, Http, log, save_json

REVIEW_SAMPLE = 1000


async def main() -> None:
    gh, http = Http(concurrency=8), Http(concurrency=16)
    try:
        reviewed = await gh.gh_paginate("https://api.github.com/advisories?type=reviewed&sort=published&direction=desc&per_page=100",
                                        max_pages=REVIEW_SAMPLE // 100)
        log(f"reviewed advisories fetched: {len(reviewed)} "
            f"(reviewed {reviewed[-1]['github_reviewed_at']} -> {reviewed[0]['github_reviewed_at']})")
        from_repo = [a for a in reviewed if a.get("repository_advisory_url")]
        res = await asyncio.gather(*(gh.get(a["repository_advisory_url"]) for a in from_repo))
        cves = sorted({a["cve_id"] for a in from_repo if a.get("cve_id")})
        cres = await asyncio.gather(*(http.get(f"https://cveawg.mitre.org/api/cve/{c}") for c in cves))
        cve_pub = {c: (b.get("cveMetadata", {}).get("datePublished") if s == 200 else None) for c, (s, b, _) in zip(cves, cres)}
        cna = {c: (b.get("cveMetadata", {}).get("assignerShortName") if s == 200 else None) for c, (s, b, _) in zip(cves, cres)}
        rows = []
        for a, (s, ra, _) in zip(from_repo, res):
            rows.append({
                "ghsa": a["ghsa_id"], "cve": a.get("cve_id"), "cna": cna.get(a.get("cve_id")),
                "ecosystems": sorted({(v.get("package") or {}).get("ecosystem") or "" for v in a.get("vulnerabilities") or []}),
                "severity": a.get("severity"), "github_reviewed_at": a.get("github_reviewed_at"),
                "global_published_at": a.get("published_at"),
                "repo_published_at": ra.get("published_at") if s == 200 and isinstance(ra, dict) else None,
                "repo_status": s, "cve_published_at": cve_pub.get(a.get("cve_id")),
            })
        log(f"from repo advisories: {len(from_repo)}/{len(reviewed)}; repo fetch {dict(Counter(r['repo_status'] for r in rows))}; "
            f"no CVE: {sum(1 for a in reviewed if not a.get('cve_id'))}")
        save_json(DATA / SNAPSHOT / "review_lag.json", {"sample_size": len(reviewed), "from_repo": len(from_repo),
                                                         "no_cve_reviewed": sum(1 for a in reviewed if not a.get("cve_id")),
                                                         "rows": rows})
    finally:
        await gh.close()
        await http.close()


if __name__ == "__main__":
    asyncio.run(main())
