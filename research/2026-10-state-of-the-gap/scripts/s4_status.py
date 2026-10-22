# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx", "univers"]
# ///
"""Stage 4: status of every repo advisory across sources, and matching to dependency versions.

1. OSV presence by GHSA ID for all advisories (free, quota-less filter; F-026).
2. GitHub global DB for every OSV-missing advisory, plus a random sample of OSV-present ones
   to re-validate the OSV proxy.
3. CVE state via CVE Services: published record, else cve-id state (RESERVED = RBP; F-029).
4. Match advisories to (package, version) in each project; tolerant range evaluation (F-030);
   record whether OSV-Scanner flagged that package for that advisory.
5. Duplicate detection for limbo hits against reviewed advisories of the same package (F-028):
   shared CVE, shared reference URL, or summary similarity.
6. NVD status for all limbo-hit CVEs and a random sample of reviewed-hit CVEs.
Output: data/<snapshot>/status.json
"""

from __future__ import annotations

import asyncio
import difflib
import os
import random
import re
from collections import Counter
from urllib.parse import quote

from common import DATA, ECOSYSTEMS, SNAPSHOT, Http, affected, load_json, log, name_matches, save_json

OSV_PROXY_SAMPLE = 200
NVD_REVIEWED_SAMPLE = 60
WORDS = re.compile(r"[a-z0-9_]{3,}")


def similarity(a: str, b: str) -> float:
    a, b = a.lower(), b.lower()
    wa, wb = set(WORDS.findall(a)), set(WORDS.findall(b))
    jac = len(wa & wb) / max(1, len(wa | wb))
    return max(jac, difflib.SequenceMatcher(None, a, b).ratio())


def match_hits(inv: dict, mapping: dict, repo_adv: dict) -> list[dict]:
    hits = []
    for project, pv in inv.items():
        self_repo = project.lower()
        for p in pv["packages"]:
            eco = ECOSYSTEMS.get(p["ecosystem"], (None,))[0]
            m = mapping.get(f"{p['ecosystem']}|{p['name']}|{p['version']}")
            if not eco or not m or not m["repo"] or m["repo"] == self_repo:
                continue
            for a in repo_adv.get(m["repo"], []):
                vulns = a.get("vulnerabilities") or []
                pkg_entries = [v for v in vulns if (v.get("package") or {}).get("name")
                               and (v["package"].get("ecosystem") or "other") != "other"]
                base = {"project": project, "ecosystem": p["ecosystem"], "name": p["name"], "version": p["version"],
                        "lockfile": p["lockfile"], "repo": m["repo"], "map_method": m["method"], "ghsa": a["ghsa_id"]}
                if not pkg_entries:
                    hits.append({**base, "match": "repo_only", "eval": None, "range": None, "patched": None})
                    continue
                for v in pkg_entries:
                    if v["package"]["ecosystem"] != eco or not name_matches(eco, v["package"]["name"], p["name"]):
                        continue
                    res = affected(eco, p["version"], v.get("vulnerable_version_range"))
                    if res is not False:
                        hits.append({**base, "match": "package_and_repo", "eval": res,
                                     "range": v.get("vulnerable_version_range"), "patched": v.get("patched_versions")})
    # osv-scanner verdict for the exact package entry
    flagged = {(proj, p["ecosystem"], p["name"], p["version"]): set(p["osv_ids"])
               for proj, pv in inv.items() for p in pv["packages"]}
    for h in hits:
        h["osv_scanner_ids"] = sorted(flagged.get((h["project"], h["ecosystem"], h["name"], h["version"]), set()))
    return hits


async def main() -> None:
    random.seed(20261021)
    d = DATA / SNAPSHOT
    inv = load_json(d / "inventory.json")["projects"]
    mapping = load_json(d / "mapping.json")["mapping"]
    repo_adv = load_json(d / "repo_advisories.json")["advisories"]
    advs = {a["ghsa_id"]: {"repo": r, **a} for r, lst in repo_adv.items() for a in lst}
    http = Http(concurrency=24)
    gh = Http(concurrency=8)
    try:
        # 1) OSV presence
        ids = sorted(advs)
        res = await asyncio.gather(*(http.get(f"https://api.osv.dev/v1/vulns/{g}") for g in ids))
        osv = {g: {"present": s == 200, "aliases": (b or {}).get("aliases", []) if s == 200 else []} for g, (s, b, _) in zip(ids, res)}
        missing = [g for g in ids if not osv[g]["present"]]
        log(f"advisories {len(ids)}; in OSV {len(ids) - len(missing)}; not in OSV {len(missing)}")
        # 2) global DB: all OSV-missing + random sample of OSV-present
        sample = random.sample([g for g in ids if osv[g]["present"]], min(OSV_PROXY_SAMPLE, len(ids) - len(missing)))
        check = missing + sample
        res = await asyncio.gather(*(gh.get(f"https://api.github.com/advisories/{g}") for g in check))
        glob = {}
        for g, (s, b, _) in zip(check, res):
            glob[g] = {"status": s, "type": b.get("type") if s == 200 else None,
                       "github_reviewed_at": b.get("github_reviewed_at") if s == 200 else None,
                       "cve_id": b.get("cve_id") if s == 200 else None}
        proxy_ok = sum(1 for g in sample if glob[g]["type"] == "reviewed")
        log(f"global DB for OSV-missing: {dict(Counter(str(glob[g]['type'] or glob[g]['status']) for g in missing))}; "
            f"OSV-present sample reviewed: {proxy_ok}/{len(sample)}")
        # 4) matching
        hits = match_hits(inv, mapping, repo_adv)
        log(f"hits (affected or unknown): {len(hits)}; eval {dict(Counter(str(h['eval']) for h in hits))}; "
            f"match {dict(Counter(h['match'] for h in hits))}")
        in_limbo = {g for g in ids if not osv[g]["present"] and glob.get(g, {}).get("type") != "reviewed"}
        # 3) CVE state: all limbo advisories with a CVE + all hit advisories with a CVE
        cves = sorted({advs[g]["cve_id"] for g in in_limbo | {h["ghsa"] for h in hits} if advs[g].get("cve_id")})
        res = await asyncio.gather(*(http.get(f"https://cveawg.mitre.org/api/cve/{c}") for c in cves))
        cve_state: dict[str, dict] = {}
        need_id = []
        for c, (s, b, _) in zip(cves, res):
            if s == 200:
                md = b.get("cveMetadata", {})
                cve_state[c] = {"state": md.get("state"), "published": md.get("datePublished"), "cna": md.get("assignerShortName")}
            else:
                need_id.append(c)
        res = await asyncio.gather(*(http.get(f"https://cveawg.mitre.org/api/cve-id/{c}") for c in need_id))
        for c, (s, b, _) in zip(need_id, res):
            cve_state[c] = {"state": (b or {}).get("state", f"http_{s}") if isinstance(b, dict) else f"http_{s}", "published": None, "cna": None}
        log(f"CVE states: {dict(Counter(v['state'] for v in cve_state.values()))}")
        # 5) duplicates for limbo hits
        limbo_hits = [h for h in hits if h["ghsa"] in in_limbo]
        pkgs = sorted({(ECOSYSTEMS[h["ecosystem"]][0], h["name"]) for h in limbo_hits if h["match"] == "package_and_repo"})
        res = await asyncio.gather(*(gh.get(f"https://api.github.com/advisories?type=reviewed&ecosystem={e}&affects={quote(n, safe='')}&per_page=100")
                                     for e, n in pkgs))
        reviewed_by_pkg = {k: (b if s == 200 and isinstance(b, list) else []) for k, (s, b, _) in zip(pkgs, res)}
        dups = {}
        for g in sorted({h["ghsa"] for h in limbo_hits if h["match"] == "package_and_repo"}):
            a = advs[g]
            refs = {r.rstrip("/") for r in re.findall(r"https?://\S+", a.get("description") or "")} | \
                   {u.rstrip("/") for u in [a.get("html_url")] if u}
            best = {"signal": None, "score": 0.0, "candidate": None}
            for e, n in {(ECOSYSTEMS[h["ecosystem"]][0], h["name"]) for h in limbo_hits if h["ghsa"] == g}:
                for c in reviewed_by_pkg.get((e, n), []):
                    if c["ghsa_id"] == g:
                        continue
                    if a.get("cve_id") and c.get("cve_id") == a["cve_id"]:
                        best = {"signal": "same_cve", "score": 1.0, "candidate": c["ghsa_id"]}
                        break
                    crefs = {r.rstrip("/") for r in c.get("references") or []}
                    commit_refs = {r for r in refs & crefs if "/commit/" in r or "/pull/" in r}
                    if commit_refs:
                        best = {"signal": "same_fix_reference", "score": 0.95, "candidate": c["ghsa_id"]}
                        continue
                    sc = similarity(a.get("summary") or "", c.get("summary") or "")
                    if sc > best["score"] and best["signal"] not in ("same_cve", "same_fix_reference"):
                        best = {"signal": "summary_similarity", "score": round(sc, 3), "candidate": c["ghsa_id"]}
            dups[g] = best
        log(f"dup check for {len(dups)} limbo advisories: "
            f"{dict(Counter(v['signal'] if v['signal'] != 'summary_similarity' else ('sim>=0.6' if v['score'] >= 0.6 else 'sim<0.6') for v in dups.values()))}")
        status = {"osv": osv, "global": glob, "osv_proxy_sample": sample, "in_limbo": sorted(in_limbo),
                  "cve_state": cve_state, "hits": hits, "duplicates": dups, "nvd": {}}
        save_json(d / "status.json", status)
        log("checkpoint saved (pre-NVD)")
        # 6) NVD (cached per CVE, so reruns resume)
        limbo_cves = sorted({advs[h["ghsa"]]["cve_id"] for h in limbo_hits if advs[h["ghsa"]].get("cve_id")})
        rev_cves = sorted({advs[h["ghsa"]]["cve_id"] for h in hits if h["ghsa"] not in in_limbo and advs[h["ghsa"]].get("cve_id")})
        nvd_list = limbo_cves + random.sample(rev_cves, min(NVD_REVIEWED_SAMPLE, len(rev_cves)))
        delay = 0.7 if os.environ.get("NVD_API_KEY") else 6.5
        log(f"NVD: {len(limbo_cves)} limbo + {min(NVD_REVIEWED_SAMPLE, len(rev_cves))} reviewed-sample CVEs, {delay}s spacing")
        nvd_http = Http(concurrency=1)
        for i, c in enumerate(nvd_list):
            cached = nvd_http._cache_path("GET", f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={c}", None).exists()
            s, b, _ = await nvd_http.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={c}")
            if s == 200 and isinstance(b, dict) and b.get("vulnerabilities"):
                cv = b["vulnerabilities"][0]["cve"]
                status["nvd"][c] = {"status": cv.get("vulnStatus"), "group": "limbo" if c in limbo_cves else "reviewed",
                                    "nist_cvss": any(m.get("type") == "Primary" for k, ms in cv.get("metrics", {}).items() if k.startswith("cvss") for m in ms),
                                    "cna_cvss": any(m.get("type") == "Secondary" for k, ms in cv.get("metrics", {}).items() if k.startswith("cvss") for m in ms),
                                    "cpe_configs": bool(cv.get("configurations"))}
            else:
                status["nvd"][c] = {"status": "absent" if s in (200, 404) else f"error_{s}", "group": "limbo" if c in limbo_cves else "reviewed"}
            if not cached:
                await asyncio.sleep(delay)
            if i % 20 == 19:
                save_json(d / "status.json", status)
        await nvd_http.close()
        save_json(d / "status.json", status)
        log(f"NVD: {dict(Counter((v['group'], v['status']) for v in status['nvd'].values()))}")
        log(f"http stats {http.stats} {gh.stats}")
    finally:
        await http.close()
        await gh.close()


if __name__ == "__main__":
    asyncio.run(main())
