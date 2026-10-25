# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx", "univers"]
# ///
"""Stage 9: follow-up. What happened to a snapshot's advisories in limbo since the snapshot?

For every advisory in limbo in data/<snapshot>/advisories.csv, checked live today (no cache):
  - repository advisory: still published? which CVE does it cite now?
  - GitHub global database: reviewed yet?   OSV: imported yet?
  - CVE: state of the cited CVE now (CVE Services: published record, else cve-id state)
  - CVE List (bulk export CVELIST_RELEASE): any CVE record referencing the advisory that it doesn't cite
The snapshot's own files are not changed. Output: data/<snapshot>/followup-<date>.csv and .json
Env: SNAPSHOT_DATE (which snapshot to follow up), CVELIST_RELEASE (today's cvelistV5 release).
"""

from __future__ import annotations

import asyncio
import csv
import time
from collections import Counter

from common import DATA, SNAPSHOT, Http, log, save_json
from s8_verify import CVELIST_RELEASE, build_index

TODAY = time.strftime("%Y-%m-%d", time.gmtime())


def now_status(repo_state: str, global_type: str | None, in_osv: bool) -> str:
    if global_type == "reviewed" or in_osv:
        return "reviewed"
    if repo_state != "published":
        return f"repo advisory {repo_state}"
    return "still in limbo"


async def cve_state(http: Http, cve: str) -> tuple[str, str | None, str | None]:
    s, b, _ = await http.get(f"https://cveawg.mitre.org/api/cve/{cve}", use_cache=False)
    if s == 200 and isinstance(b, dict):
        md = b.get("cveMetadata", {})
        return md.get("state") or "PUBLISHED", md.get("datePublished"), md.get("assignerShortName")
    s, b, _ = await http.get(f"https://cveawg.mitre.org/api/cve-id/{cve}", use_cache=False)
    return ((b or {}).get("state") if s == 200 and isinstance(b, dict) else f"http_{s}"), None, None


async def main() -> None:
    d = DATA / SNAPSHOT
    snap_rows = {r["ghsa_id"]: r for r in csv.DictReader((d / "advisories.csv").open()) if r["in_limbo"] == "True"}
    ver = {r["ghsa_id"]: r for r in csv.DictReader((d / "verification.csv").open())}
    limbo = sorted(snap_rows)
    log(f"following up {len(limbo)} advisories that were in limbo in snapshot {SNAPSHOT}; CVE List {CVELIST_RELEASE}")
    idx = build_index({snap_rows[g]["repo"] for g in limbo}, set(limbo))

    gh, http = Http(concurrency=8, refresh=True), Http(concurrency=16, refresh=True)
    try:
        checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        repo = await asyncio.gather(*(gh.get(f"https://api.github.com/repos/{snap_rows[g]['repo']}/security-advisories/{g}", use_cache=False)
                                      for g in limbo))
        glob = await asyncio.gather(*(gh.get(f"https://api.github.com/advisories/{g}", use_cache=False) for g in limbo))
        osv = await asyncio.gather(*(http.get(f"https://api.osv.dev/v1/vulns/{g}", use_cache=False) for g in limbo))
        cited_now = {g: ((rb.get("cve_id") or None) if rs == 200 and isinstance(rb, dict) else None) for g, (rs, rb, _) in zip(limbo, repo)}
        cves = sorted({c for c in cited_now.values() if c})
        states = dict(zip(cves, await asyncio.gather(*(cve_state(http, c) for c in cves))))
    finally:
        await gh.close()
        await http.close()

    rows = []
    for g, (rs, rb, _), (gs, gb, _), (os_, _ob, _) in zip(limbo, repo, glob, osv):
        snap, v = snap_rows[g], ver.get(g, {})
        repo_state = rb.get("state") if rs == 200 and isinstance(rb, dict) else f"http_{rs}"
        gtype = gb.get("type") if gs == 200 and isinstance(gb, dict) else None
        status = now_status(repo_state, gtype, os_ == 200)
        cited = cited_now.get(g)
        cstate, cpub, ccna = states.get(cited, (None, None, None)) if cited else (None, None, None)
        uncited = sorted(c for c in idx["by_ghsa"].get(g.upper(), [])
                         if c != cited and idx["records"].get(c, {}).get("state") == "PUBLISHED")
        if cited and cstate == "PUBLISHED":
            cve_now = "published, cited by the advisory"
        elif cited and cstate == "RESERVED":
            cve_now = "reserved (RBP), cited by the advisory"
        elif uncited:
            cve_now = "published by another CNA, not cited by the advisory"
        elif cited:
            cve_now = f"cited, state {cstate}"
        else:
            cve_now = "no CVE anywhere"
        snap_cve = (snap["cve_state"] if snap["cve_id"] else ("uncited CVE in CVE List" if v.get("verdict") == "IN_LIMBO_CVE_FOUND_IN_CVE_LIST" else "none"))
        changes = []
        if status != "still in limbo":
            changes.append(status if status != "reviewed" else f"reviewed{' (global DB ' + gb.get('github_reviewed_at', '')[:10] + ')' if gtype == 'reviewed' else ' (in OSV)'}")
        if (snap["cve_id"] or None) != cited:
            changes.append(f"advisory now cites {cited or 'no CVE'} (was {snap['cve_id'] or 'none'})")
        if snap["cve_state"] == "RESERVED" and cstate == "PUBLISHED":
            changes.append("reserved CVE was published")
        if uncited and v.get("verdict") != "IN_LIMBO_CVE_FOUND_IN_CVE_LIST":
            changes.append(f"new CVE by another CNA: {';'.join(uncited)}")
        rows.append({
            "ghsa_id": g, "repo": snap["repo"], "severity": snap["severity"], "checked_at": checked_at,
            "snapshot_class": snap["class"], "snapshot_cve": snap["cve_id"], "snapshot_cve_status": snap_cve,
            "status_now": status, "repo_advisory_now": repo_state, "global_db_now": gtype or (str(gs) if gs != 200 else ""),
            "in_osv_now": os_ == 200, "cited_cve_now": cited or "", "cited_cve_state_now": cstate or "",
            "cited_cve_published": (cpub or "")[:10], "cited_cve_cna": ccna or "",
            "uncited_cves_in_cve_list": ";".join(uncited), "cve_now": cve_now,
            "changes": " | ".join(changes) or "no change", "advisory_url": snap["advisory_url"],
        })
    with (d / f"followup-{TODAY}.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    still = [r for r in rows if r["status_now"] == "still in limbo"]
    summary = {
        "snapshot": SNAPSHOT, "checked_at": checked_at, "cve_list_release": CVELIST_RELEASE, "followed_up": len(rows),
        "status_now": Counter(r["status_now"] for r in rows),
        "still_in_limbo_cve_now": Counter(r["cve_now"] for r in still),
        "transitions": Counter(f"{r['snapshot_class']} -> {r['status_now']}" for r in rows),
        "cve_changes": Counter(c.split(":")[0].split(" (was")[0] for r in rows for c in r["changes"].split(" | ")
                               if c != "no change" and not c.startswith(("reviewed", "repo advisory"))),
    }
    save_json(d / f"followup-{TODAY}.json", summary)
    log(f"checked {len(rows)} at {checked_at}: {dict(summary['status_now'])}")
    log(f"  still in limbo, CVE now: {dict(summary['still_in_limbo_cve_now'])}")
    log(f"  CVE changes: {dict(summary['cve_changes'])}")


if __name__ == "__main__":
    asyncio.run(main())
