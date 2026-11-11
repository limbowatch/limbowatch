# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Phase 6 (FINDINGS Q27): do the watcher's upstream verdicts agree with OSV's own, where OSV has one?

For limbo advisories about a library's code that cite a CVE OSV holds with GIT ranges on the same repo, OSV decides
independently whether a commit is affected (it walks its ranges on the repo's history). For several libraries pinned
at older releases, compare the watcher's verdict (from tags and the advisory's versions; OSV's commit lookup turned
off) with OSV's. OSV's reference is the version ranges it extracted for the CVE (NVD's CPE ranges, or the CVE record's
affected field: `database_specific.extracted_events`), evaluated at the pin's release. Its GIT ranges can't be read
literally (fixes on release branches; OSV resolves those with its own branch and cherry-pick analysis), and its commit
lookup's index lags for some repos (FreeRDP: no CVE at all for 3.10.0's commit; F-139); both are recorded too.

Run from the repo root:  uv run python research/2026-11-upstream-watch/agreement.py FEED_ZIP
FEED_ZIP is a feed `all.zip` carrying the versions of advisories without a package (limbo.watch/feed/all.zip since
2026-11-11). Clones go to .cache/git. Writes agreement.json (counts and IDs only).
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

from limbowatch.http import HttpClient
from limbowatch.models import Upstream, UpstreamKind
from limbowatch.sources import osv
from limbowatch.watch import upstream_check as uc
from limbowatch.watch.candidates import Index, from_feed_zip
from limbowatch.watch.gitgraph import graphs

HERE = Path(__file__).parent
PINS = {  # repo -> tags to pin it at (older releases, so there's something to be affected)
    "freerdp/freerdp": ["3.10.0", "3.20.0"],
    "imagemagick/imagemagick": ["7.1.1-30", "7.1.2-0"],
    "vim/vim": ["v9.1.0000", "v9.1.1000"],
    "exiv2/exiv2": ["v0.28.0"],
    "strukturag/libheif": ["v1.17.0"],
    "academysoftwarefoundation/openexr": ["v3.2.0"],
    "c-ares/c-ares": ["cares-1_19_0"],
    "madler/zlib": ["v1.2.11"],
}


def in_version_ranges(version: str | None, ranges: list[list[dict]]) -> bool | None:
    """Is the release in any of OSV's extracted version ranges (introduced / fixed / last_affected)?"""
    from limbowatch.versions import UpstreamVersion as V

    if not version:
        return None
    try:
        v = V(version)
        for evs in ranges:
            lo = next((e["introduced"] for e in evs if "introduced" in e), "0")
            fix = next((e["fixed"] for e in evs if "fixed" in e), None)
            last = next((e["last_affected"] for e in evs if "last_affected" in e), None)
            if (lo == "0" or V(lo) <= v) and (fix is None or v < V(fix)) and (last is None or v <= V(last)):
                return True
        return False
    except ValueError:
        return None


async def main(feed: Path) -> None:
    index = Index()
    for c in from_feed_zip(feed.read_bytes()):
        index.add(c)
    gs = await graphs({r: f"https://github.com/{r}.git" for r in PINS}, HERE / ".cache" / "git")
    rows, tally = [], Counter[str]()
    async with HttpClient() as http:
        osv_git: dict[str, list[dict]] = {}
        for repo, tags in PINS.items():
            g = gs[repo]
            if g is None:
                tally["clone failed"] += 1
                continue
            for tag in tags:
                u = Upstream(kind=UpstreamKind.SUBMODULE, name=repo, source="x", host="github.com", repo=repo,
                             ref=tag)  # fmt: skip
                pn = uc.pin(u, g)
                if pn.commit is None:
                    tally["pin not in the history"] += 1
                    continue
                cands = [c for c in uc.candidates(u, index) if c.cves]
                cves = sorted({cv for c in cands for cv in c.cves if cv.startswith("CVE-")})
                for cv in cves:  # does OSV hold this CVE with GIT ranges on this repo?
                    if cv not in osv_git:
                        r = await http.get(f"{osv.API}/vulns/{cv}")
                        rec = r.body if r.ok and isinstance(r.body, dict) else {}
                        osv_git[cv] = [x["range"] for a in rec.get("affected") or [] for rg in a.get("ranges") or []
                                       if rg.get("type") == "GIT" and repo in (rg.get("repo") or "").lower()
                                       for x in (rg.get("database_specific") or {}).get("extracted_events") or []
                                       if x.get("source") in ("CPE_RANGE", "AFFECTED_FIELD")
                                       and any("introduced" in e for e in x.get("range") or [])]  # fmt: skip
                hits = (await osv.by_commit(http, [pn.commit]) or {}).get(pn.commit, set())
                ours = {f.ghsa_id: f.affected for f in uc.findings(u, pn, cands, g, None)}
                for c in cands:
                    for cv in c.cves:
                        if not osv_git.get(cv):
                            continue
                        o = in_version_ranges(pn.version, osv_git[cv])
                        api = cv in hits
                        w = ours.get(c.adv.ghsa_id, False)
                        kind = ("unknown to OSV's ranges" if o is None else "agree" if w is o else "possible"
                                if w is None else "we say affected, OSV not" if w else "OSV says affected, we not")  # fmt: skip
                        tally[kind] += 1
                        tally["OSV's lookup agrees with its ranges" if api is o else "OSV's lookup differs from its ranges"] += 1
                        rows.append({"repo": repo, "pin": tag, "ghsa": c.adv.ghsa_id, "cve": cv, "ours": w,
                                     "osv_ranges": o, "osv_lookup": api, "outcome": kind})  # fmt: skip
    out = {"compared": len(rows), "outcomes": dict(tally), "rows": rows}
    (HERE / "agreement.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k != "rows"}, indent=1))
    for r in rows:
        if r["outcome"] not in ("agree",):
            print(r)


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1])))
