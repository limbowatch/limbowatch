# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx", "univers"]
# ///
"""Stage 8: automated verification of every advisory in limbo. No manual checking.

For each advisory in limbo:
  1. Live re-check (no cache): GitHub global DB by GHSA, OSV by GHSA.
  2. Cited CVE consistency: CVE Services state, and whether the CVE List record for the cited
     CVE references this GHSA or this repo. A record pointing elsewhere is a CONFLICT.
  3. Reverse lookup in the full CVE List (cvelistV5 bulk export): other CVE records that
     reference this GHSA ID, or cover the same repo with a near-identical title.
  4. Cross-ID review: GitHub global DB by each linked CVE. A reviewed advisory under another
     GHSA ID is a duplicate.
Output: data/<snapshot>/verification.csv (+ .json for stage 6), every check timestamped.
"""

from __future__ import annotations

import asyncio
import csv
import json
import re
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from common import CACHE, DATA, SNAPSHOT, Http, load_json, log, save_json
from s4_status import similarity

CVELIST_RELEASE = "cve_2026-10-22_0800Z"
CVELIST_ASSET = "2026-10-22_all_CVEs_at_midnight.zip.zip"
GHSA_RE = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}", re.I)
GH_REPO_RE = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", re.I)
TITLE_SIM = 0.7  # word-set Jaccard; see s4_status.similarity


def cvelist_zip() -> Path:
    d = CACHE / "cvelist"
    outer = d / "all.zip.zip"
    if not outer.exists():
        raise SystemExit(f"download https://github.com/CVEProject/cvelistV5/releases/download/{CVELIST_RELEASE}/{CVELIST_ASSET} to {outer}")
    inner = d / "cves.zip"
    if not inner.exists():
        with zipfile.ZipFile(outer) as z:
            z.extract("cves.zip", d)
    return inner


def summarize(rec: dict, hit_g: set[str], hit_r: set[str]) -> dict:
    md = rec.get("cveMetadata", {})
    cna = (rec.get("containers") or {}).get("cna") or {}
    desc = next((x.get("value", "") for x in cna.get("descriptions") or [] if x.get("lang", "").startswith("en")), "")
    text = json.dumps(cna)
    all_repos = sorted({f"{o}/{r}".lower().removesuffix(".git") for o, r in GH_REPO_RE.findall(text)})
    products = " ".join(f"{a.get('vendor', '')} {a.get('product', '')} {a.get('packageName', '')}" for a in cna.get("affected") or [])
    return {"state": md.get("state"), "published": md.get("datePublished"), "cna": md.get("assignerShortName"),
            "title": cna.get("title") or desc[:200], "ghsas": sorted(hit_g), "repos": sorted(hit_r),
            "all_github_repos": all_repos, "products": products}


WORD = re.compile(r"[a-z0-9]{3,}")
GENERIC = {"the", "for", "and", "lib", "library", "js", "node", "nodejs", "core", "github", "com", "org", "inc", "project"}


def tokens(s: str) -> set[str]:
    return {w for w in WORD.findall(s.lower().replace("-", " ").replace("_", " ")) if w not in GENERIC} | \
           {w for w in WORD.findall(s.lower()) if w not in GENERIC}


def build_index(repos: set[str], ghsas: set[str]) -> dict:
    """Scan every CVE record once; keep only what touches our repos or GHSA IDs."""
    ghsas = {g.upper() for g in ghsas}  # GHSA IDs are case-insensitive; CVE records vary
    cache = CACHE / "cvelist" / f"index-v2-{CVELIST_RELEASE}-{len(repos)}-{len(ghsas)}.json"
    if cache.exists():
        return load_json(cache)
    by_ghsa: dict[str, list[str]] = defaultdict(list)
    by_repo: dict[str, list[str]] = defaultdict(list)
    records: dict[str, dict] = {}
    n = 0
    with zipfile.ZipFile(cvelist_zip()) as z:
        for name in z.namelist():
            if not name.endswith(".json") or "/CVE-" not in name:
                continue
            n += 1
            raw = z.read(name)
            text = raw.decode("utf-8", "replace")
            hit_g = {g.upper() for g in GHSA_RE.findall(text)} & ghsas
            hit_r = {f"{o}/{r}".lower().removesuffix(".git") for o, r in GH_REPO_RE.findall(text)} & repos
            rec = json.loads(raw)
            md = rec.get("cveMetadata", {})
            cna = (rec.get("containers") or {}).get("cna") or {}
            if md.get("assignerShortName") == "GitHub_M":
                for a in cna.get("affected") or []:
                    vp = f"{a.get('vendor', '')}/{a.get('product', '')}".lower()
                    if vp in repos:
                        hit_r.add(vp)
            if not (hit_g or hit_r):
                continue
            cid = md.get("cveId")
            records[cid] = summarize(rec, hit_g, hit_r)
            for g in hit_g:
                by_ghsa[g].append(cid)
            for r in hit_r:
                by_repo[r].append(cid)
    log(f"scanned {n:,} CVE records; kept {len(records):,}")
    idx = {"release": CVELIST_RELEASE, "scanned": n, "records": records, "by_ghsa": by_ghsa, "by_repo": by_repo}
    save_json(cache, idx)
    return idx


async def main() -> None:
    d = DATA / SNAPSHOT
    ra = load_json(d / "repo_advisories.json")["advisories"]
    stt = load_json(d / "status.json")
    advs = {a["ghsa_id"]: {"repo": r, **a} for r, lst in ra.items() for a in lst}
    limbo = sorted(stt["in_limbo"])
    idx = build_index({advs[g]["repo"] for g in limbo}, set(limbo))
    recs = idx["records"]

    live = Http(concurrency=8, refresh=True)
    http = Http(concurrency=16)
    try:
        checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        g_res = await asyncio.gather(*(live.get(f"https://api.github.com/advisories/{g}", use_cache=False) for g in limbo))
        o_res = await asyncio.gather(*(live.get(f"https://api.osv.dev/v1/vulns/{g}", use_cache=False) for g in limbo))
        r_res = await asyncio.gather(*(live.get(f"https://api.github.com/repos/{advs[g]['repo']}/security-advisories/{g}", use_cache=False)
                                       for g in limbo))
        # linked CVEs per advisory
        linked: dict[str, dict[str, str]] = {}
        for g in limbo:
            a = advs[g]
            links: dict[str, str] = {}
            if a.get("cve_id"):
                links[a["cve_id"]] = "cited"
            for c in idx["by_ghsa"].get(g.upper(), []):
                links.setdefault(c, "cve_list_references_ghsa")
            for c in idx["by_repo"].get(a["repo"], []):
                if c not in links and similarity(a.get("summary") or "", recs[c]["title"] or "") >= TITLE_SIM:
                    links[c] = "same_repo_similar_title"
            linked[g] = links
        missing = sorted({advs[g]["cve_id"] for g in limbo if advs[g].get("cve_id") and advs[g]["cve_id"] not in recs
                          and stt["cve_state"].get(advs[g]["cve_id"], {}).get("state") == "PUBLISHED"})
        lr = await asyncio.gather(*(http.get(f"https://cveawg.mitre.org/api/cve/{c}") for c in missing))
        for c, (s, b, _) in zip(missing, lr):
            if s == 200 and isinstance(b, dict):
                txt = json.dumps(b)
                recs[c] = {**summarize(b, {x.upper() for x in GHSA_RE.findall(txt)}, set()), "source": "cve_services_live"}
        log(f"cited CVEs newer than the bulk snapshot, fetched live: {len(missing)}")
        all_cves = sorted({c for v in linked.values() for c in v})
        gc_res = await asyncio.gather(*(http.get(f"https://api.github.com/advisories?cve_id={c}&per_page=100") for c in all_cves))
        global_by_cve = {c: [(x["ghsa_id"], x["type"]) for x in (b if s == 200 and isinstance(b, list) else [])] for c, (s, b, _) in zip(all_cves, gc_res)}
        save_json(d / "verification_cve_globals.json", global_by_cve)
    finally:
        await live.close()
        await http.close()

    rows, out = [], {}
    for g, (gs, gb, _), (os_, ob, _), (rs, rb, _) in zip(limbo, g_res, o_res, r_res):
        a = advs[g]
        live_global = gb.get("type") if gs == 200 and isinstance(gb, dict) else str(gs)
        live_osv = os_ == 200
        cited = a.get("cve_id")
        cited_state = stt["cve_state"].get(cited, {}).get("state") if cited else None
        notes, verdict = [], "VERIFIED_IN_LIMBO"
        live_repo_state = rb.get("state") if rs == 200 and isinstance(rb, dict) else f"http_{rs}"
        if rs == 200 and isinstance(rb, dict) and (rb.get("cve_id") or None) != (cited or None):
            notes.append(f"repo advisory now cites {rb.get('cve_id')} (snapshot: {cited})")
        if live_global == "reviewed" or live_osv:
            verdict = "REVIEWED_SINCE_SNAPSHOT"
        elif live_repo_state != "published":
            verdict = "NO_LONGER_PUBLISHED"
        conflict, cited_link = False, ""
        if cited and cited in recs:
            r = recs[cited]
            ours = tokens(a["repo"] + " " + " ".join((v.get("package") or {}).get("name") or "" for v in a.get("vulnerabilities") or []))
            if g.upper() in r["ghsas"] or a["repo"] in r["all_github_repos"]:
                cited_link = "links_back"
            elif r["all_github_repos"]:
                conflict, cited_link = True, "points_to_other_repo"
                notes.append(f"cited {cited} references {', '.join(r['all_github_repos'][:3])}, not {a['repo']}")
            elif not (tokens(r["products"] + " " + r["title"]) & ours):
                conflict, cited_link = True, "names_other_product"
                notes.append(f"cited {cited} is about '{r['products'].strip() or r['title'][:60]}', which shares no name with {a['repo']}")
            else:
                cited_link = "unlinked_same_product"
        elif cited and cited_state == "PUBLISHED":
            cited_link = "record_unavailable"
        strong = {c for c, how in linked[g].items() if how in ("cited", "cve_list_references_ghsa")}
        weak = {c for c, how in linked[g].items() if how == "same_repo_similar_title"}
        dup_of = sorted({og for c in strong for og, typ in global_by_cve.get(c, []) if og != g and typ == "reviewed"})
        maybe_dup = sorted({og for c in weak for og, typ in global_by_cve.get(c, []) if og != g and typ == "reviewed"} - set(dup_of))
        uncited = sorted(c for c in strong if c != cited and recs.get(c, {}).get("state") == "PUBLISHED")
        other_cves = sorted(uncited)
        if verdict == "VERIFIED_IN_LIMBO":
            if dup_of:
                verdict = "DUPLICATE_SAME_CVE_REVIEWED"
            elif conflict:
                verdict = "IN_LIMBO_CITED_CVE_CONFLICT"
            elif uncited and not cited:
                verdict = "IN_LIMBO_CVE_FOUND_IN_CVE_LIST"
            elif maybe_dup:
                verdict = "IN_LIMBO_POSSIBLE_DUPLICATE"
        row = {"ghsa_id": g, "repo": a["repo"], "checked_at": checked_at, "verdict": verdict,
               "live_repo_advisory": live_repo_state, "live_global_db": live_global, "live_in_osv": live_osv, "cited_cve": cited or "",
               "cited_cve_state": cited_state or "", "cited_cve_link": cited_link,
               "other_cves": ";".join(other_cves),
               "link_methods": ";".join(f"{c}:{how}" for c, how in sorted(linked[g].items())),
               "reviewed_under_other_ghsa": ";".join(dup_of), "possible_duplicate_of": ";".join(maybe_dup),
               "notes": " | ".join(notes),
               "cve_list_release": idx["release"]}
        rows.append(row)
        out[g] = row
    with (d / "verification.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    save_json(d / "verification.json", {"checked_at": checked_at, "cve_list_release": idx["release"],
                                         "cve_records_scanned": idx["scanned"], "advisories": out})
    log(f"verified {len(rows)} limbo advisories at {checked_at}: {dict(Counter(r['verdict'] for r in rows))}")
    for r in rows:
        if r["verdict"] not in ("VERIFIED_IN_LIMBO", "IN_LIMBO_POSSIBLE_DUPLICATE"):
            log(f"  {r['verdict']:32s} {r['ghsa_id']} {r['repo']}  cited={r['cited_cve'] or '-'} other={r['other_cves'] or '-'} "
                f"dup={r['reviewed_under_other_ghsa'] or '-'} {r['notes']}")


if __name__ == "__main__":
    asyncio.run(main())
