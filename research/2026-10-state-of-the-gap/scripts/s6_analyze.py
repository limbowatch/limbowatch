# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx", "univers"]
# ///
"""Stage 6: classify, compute headline numbers, write the open dataset.

Outputs in data/<snapshot>/:
  summary.json      every number the report cites
  advisories.csv    one row per upstream repo advisory (IDs, dates, states; no advisory text)
  findings.csv      advisory x project x package-version hits
  review_lag.csv    recently reviewed advisories: repo publication -> review
  nvd.csv           NVD status for sampled CVEs
  unresolved.csv    packages that could not be checked, with the reason (never dropped)
"""

from __future__ import annotations

import csv
import statistics as st
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from common import DATA, SNAPSHOT, load_json, log, save_json

GHSA_SUPPORTED = {"npm", "pip", "go", "rust", "maven", "nuget", "composer", "rubygems", "erlang", "actions", "pub", "swift"}
AGE_BUCKETS = [("< 3 days", 0, 3), ("3–7 days", 3, 7), ("1–2 weeks", 7, 14), ("2–4 weeks", 14, 30),
               ("1–2 months", 30, 60), ("2–3 months", 60, 90), ("> 3 months", 90, 10**6)]


def ts(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def days(a: datetime | None, b: datetime | None) -> float | None:
    return None if a is None or b is None else (b - a).total_seconds() / 86400


def q(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))]


def dist(xs: list[float]) -> dict:
    if not xs:
        return {"n": 0}
    return {"n": len(xs), "min": round(min(xs), 2), "p25": round(q(xs, .25), 2), "median": round(st.median(xs), 2),
            "p75": round(q(xs, .75), 2), "p90": round(q(xs, .9), 2), "max": round(max(xs), 2)}


def buckets(xs: list[float]) -> dict:
    return {name: sum(1 for x in xs if lo <= x < hi) for name, lo, hi in AGE_BUCKETS}


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    d = DATA / SNAPSHOT
    now = ts(f"{SNAPSHOT}T12:00:00Z")
    inv = load_json(d / "inventory.json")
    mp = load_json(d / "mapping.json")
    ra = load_json(d / "repo_advisories.json")
    stt = load_json(d / "status.json")
    lag = load_json(d / "review_lag.json")
    advs = {a["ghsa_id"]: {"repo": r, **a} for r, lst in ra["advisories"].items() for a in lst}
    limbo = set(stt["in_limbo"])
    dup = stt["duplicates"]
    ver_path = d / "verification.json"
    ver = load_json(ver_path) if ver_path.exists() else {"advisories": {}, "checked_at": None}
    verdict = {g: v["verdict"] for g, v in ver["advisories"].items()}

    def likely_dup(g: str) -> bool:
        # Strong evidence only: the same CVE is reviewed under another GHSA ID (s8), or a shared
        # CVE / fix reference with a reviewed advisory of the same package (s4). Text-only = possible.
        v = dup.get(g) or {}
        return verdict.get(g) == "DUPLICATE_SAME_CVE_REVIEWED" or v.get("signal") in ("same_cve", "same_fix_reference")

    def possible_dup(g: str) -> bool:
        v = dup.get(g) or {}
        return not likely_dup(g) and (verdict.get(g) == "IN_LIMBO_POSSIBLE_DUPLICATE"
                                      or (v.get("signal") == "summary_similarity" and v.get("score", 0) >= 0.6))

    def cve_state(g: str) -> str:
        c = advs[g].get("cve_id")
        return "none" if not c else (stt["cve_state"].get(c, {}).get("state") or "unchecked")

    def adv_class(g: str) -> str:
        if g not in limbo:
            return "REVIEWED_NO_CVE" if not advs[g].get("cve_id") else "REVIEWED_WITH_CVE"
        cs = cve_state(g)
        if cs == "PUBLISHED":
            return "LIMBO_CVE"
        if cs == "RESERVED":
            return "LIMBO_ADVISORY_RBP"
        return "LIMBO_ADVISORY"

    # ---- advisories.csv
    adv_rows = []
    for g, a in sorted(advs.items()):
        ecos = sorted({(v.get("package") or {}).get("ecosystem") or "none" for v in a.get("vulnerabilities") or []} or {"none"})
        age = days(ts(a.get("published_at")), now)
        adv_rows.append({
            "ghsa_id": g, "repo": a["repo"], "repo_published_at": a.get("published_at"), "severity": a.get("severity"),
            "ecosystems": ";".join(ecos), "cve_id": a.get("cve_id") or "", "cve_state": cve_state(g),
            "in_osv": stt["osv"][g]["present"], "global_db": (stt["global"].get(g) or {}).get("type") or ("reviewed (OSV proxy)" if stt["osv"][g]["present"] else str((stt["global"].get(g) or {}).get("status", ""))),
            "class": adv_class(g), "in_limbo": g in limbo, "days_since_repo_publication": round(age, 1) if age is not None else "",
            "supported_ecosystem": any(e in GHSA_SUPPORTED for e in ecos),
            "duplicate_signal": (dup.get(g) or {}).get("signal") or "", "duplicate_score": (dup.get(g) or {}).get("score") or "",
            "duplicate_candidate": (dup.get(g) or {}).get("candidate") or "", "likely_duplicate": likely_dup(g),
            "possible_duplicate": possible_dup(g) if g in limbo else "", "verification": verdict.get(g, ""),
            "advisory_url": a.get("html_url"),
        })
    write_csv(d / "advisories.csv", adv_rows)

    # ---- findings.csv (hits on project dependencies)
    find_rows = []
    for h in stt["hits"]:
        g = h["ghsa"]
        a = advs[g]
        seen = bool({g, *(stt["osv"][g]["aliases"]), *([a["cve_id"]] if a.get("cve_id") else [])} & set(h["osv_scanner_ids"]))
        find_rows.append({
            "project": h["project"], "ecosystem": h["ecosystem"], "package": h["name"], "version": h["version"], "lockfile": h["lockfile"],
            "upstream_repo": h["repo"], "map_method": h["map_method"], "ghsa_id": g, "cve_id": a.get("cve_id") or "",
            "class": adv_class(g), "severity": a.get("severity"), "match": h["match"],
            "version_affected": {True: "yes", None: "unknown"}[h["eval"]], "range": h["range"] or "", "patched": h["patched"] or "",
            "osv_scanner_reports_this_advisory": seen, "osv_scanner_reports_package_clean": not h["osv_scanner_ids"],
            "likely_duplicate": likely_dup(g) if g in limbo else "", "possible_duplicate": possible_dup(g) if g in limbo else "",
            "verification": verdict.get(g, ""),
            "days_since_repo_publication": round(days(ts(a.get("published_at")), now) or 0, 1),
        })
    write_csv(d / "findings.csv", find_rows)

    # ---- review lag
    lag_rows = []
    for r in lag["rows"]:
        lag_d = days(ts(r["repo_published_at"]), ts(r["github_reviewed_at"]))
        c = days(ts(r["cve_published_at"]), ts(r["github_reviewed_at"])) if r.get("cve_published_at") else None
        lag_rows.append({**{k: r[k] for k in ("ghsa", "cve", "cna", "severity", "repo_published_at", "github_reviewed_at", "cve_published_at")},
                         "ecosystems": ";".join(r["ecosystems"]), "review_lag_days": round(lag_d, 2) if lag_d is not None else "",
                         "cve_published_before_review_days": round(c, 2) if c is not None else ""})
    write_csv(d / "review_lag.csv", lag_rows)
    lags = [r["review_lag_days"] for r in lag_rows if r["review_lag_days"] != ""]
    cve_lead = [r["cve_published_before_review_days"] for r in lag_rows if r["cve_published_before_review_days"] != ""]

    # ---- nvd.csv
    write_csv(d / "nvd.csv", [{"cve_id": c, **v} for c, v in sorted(stt["nvd"].items())])

    # ---- unresolved.csv
    unres = [{"ecosystem": e, "package": n, "version": "", "where": lf, "reason": "no_resolved_version_or_unsupported_ecosystem"}
             for e, n, lf in mp["unresolved"]]
    unres += [{"ecosystem": k.split("|")[0], "package": k.split("|")[1], "version": k.split("|")[2], "where": "", "reason": m["method"]}
              for k, m in sorted(mp["mapping"].items()) if not m["repo"]]
    write_csv(d / "unresolved.csv", unres)

    # ---- summary
    pk_total = {p: len(v["packages"]) for p, v in inv["projects"].items()}
    limbo_rows = [r for r in adv_rows if r["in_limbo"]]
    limbo_ages = [r["days_since_repo_publication"] for r in limbo_rows if r["days_since_repo_publication"] != ""]
    rbp = [r for r in limbo_rows if r["class"] == "LIMBO_ADVISORY_RBP"]
    per_project = {}
    for p in inv["projects"]:
        f = [r for r in find_rows if r["project"] == p and r["class"].startswith("LIMBO")]
        sure = [r for r in f if r["version_affected"] == "yes"]
        sure_nodup = [r for r in sure if not r["likely_duplicate"]]
        pk = {(r["ecosystem"], r["package"], r["version"]) for r in sure_nodup}
        pk_clean = {(r["ecosystem"], r["package"], r["version"]) for r in sure_nodup if r["osv_scanner_reports_package_clean"]}
        per_project[p] = {
            "commit": inv["projects"][p]["commit"], "packages": pk_total[p], "lockfiles": len(inv["projects"][p]["lockfiles"]),
            "limbo_findings_version_affected": len(sure), "limbo_findings_excluding_likely_duplicates": len(sure_nodup),
            "limbo_findings_needing_review": len(f) - len(sure),
            "limbo_advisories_affecting": len({r["ghsa_id"] for r in sure_nodup}),
            "affected_packages": len(pk), "affected_packages_osv_scanner_reports_clean": len(pk_clean),
            "high_or_critical": len({r["ghsa_id"] for r in sure_nodup if r["severity"] in ("high", "critical")}),
        }
    eval_reasons = Counter(("repo_only" if h["match"] == "repo_only" else "range_unparseable") for h in stt["hits"] if h["eval"] is None)
    proxy = stt["osv_proxy_sample"]
    nvd_groups = defaultdict(Counter)
    for c, v in stt["nvd"].items():
        s = v.get("status", "")
        key = "absent" if s == "absent" else ("error" if s.startswith("error") else
              ("enriched (NIST CVSS or CPE)" if v.get("nist_cvss") or v.get("cpe_configs") else f"not enriched: {s}"))
        nvd_groups[v["group"]][key] += 1
    summary = {
        "snapshot": SNAPSHOT, "osv_scanner": inv["osv_scanner"],
        "inventory": {"projects": len(inv["projects"]), "package_entries": sum(pk_total.values()),
                      "unique_package_versions": len(mp["mapping"]),
                      "mapped_to_github": sum(1 for m in mp["mapping"].values() if m["repo"]),
                      "map_methods": Counter(m["method"] for m in mp["mapping"].values()),
                      "unresolved_entries": len(unres)},
        "upstreams": {"repos_polled": len(ra["status"]), "poll_status": Counter(ra["status"].values()),
                      "repos_with_advisories": len(ra["advisories"]), "advisories": len(advs)},
        "classes": Counter(r["class"] for r in adv_rows),
        "limbo": {"count": len(limbo_rows), "share": round(len(limbo_rows) / len(adv_rows), 4),
                  "likely_duplicates": sum(1 for r in limbo_rows if r["likely_duplicate"]),
                  "possible_duplicates": sum(1 for r in limbo_rows if r["possible_duplicate"]),
                  "count_excluding_likely_duplicates": sum(1 for r in limbo_rows if not r["likely_duplicate"]),
                  "count_excluding_possible_duplicates": sum(1 for r in limbo_rows if not r["likely_duplicate"] and not r["possible_duplicate"]),
                  "unsupported_ecosystem_likely_permanent": sum(1 for r in limbo_rows if not r["supported_ecosystem"]),
                  "age_days": dist(limbo_ages), "age_buckets": buckets(limbo_ages),
                  "by_ecosystem": Counter(e for r in limbo_rows for e in r["ecosystems"].split(";")),
                  "by_severity": Counter(r["severity"] for r in limbo_rows),
                  "duplicate_signals": Counter(r["duplicate_signal"] or "not_checked" for r in limbo_rows)},
        "verification": {"checked_at": ver.get("checked_at"), "cve_list_release": ver.get("cve_list_release"),
                         "cve_records_scanned": ver.get("cve_records_scanned"), "verdicts": Counter(verdict.values())},
        "rbp": {"count": len(rbp), "age_days": dist([r["days_since_repo_publication"] for r in rbp]),
                "over_72h": sum(1 for r in rbp if r["days_since_repo_publication"] > 3)},
        "osv_proxy": {"limbo_confirmed_by_global_api": Counter(str((stt["global"].get(g) or {}).get("type") or (stt["global"].get(g) or {}).get("status")) for g in stt["in_limbo"]),
                      "osv_present_sample": len(proxy),
                      "osv_present_sample_reviewed": sum(1 for g in proxy if (stt["global"].get(g) or {}).get("type") == "reviewed")},
        "review_lag": {"sample_reviewed": lag["sample_size"], "from_repo_advisories": lag["from_repo"],
                       "reviewed_without_cve": lag["no_cve_reviewed"],
                       "reviewed_window": [min(r["github_reviewed_at"] for r in lag["rows"]), max(r["github_reviewed_at"] for r in lag["rows"])],
                       "repo_published_window": [min(r["repo_published_at"] for r in lag["rows"] if r["repo_published_at"]),
                                                 max(r["repo_published_at"] for r in lag["rows"] if r["repo_published_at"])],
                       "lag_days": dist(lags), "lag_buckets": buckets(lags),
                       "over_72h": round(sum(1 for x in lags if x > 3) / max(1, len(lags)), 4),
                       "over_30d": round(sum(1 for x in lags if x > 30) / max(1, len(lags)), 4),
                       "cve_published_before_review": sum(1 for x in cve_lead if x > 0), "cve_with_dates": len(cve_lead),
                       "cve_lead_days": dist(cve_lead),
                       "repo_to_cve_days": dist([x for x in (days(ts(r["repo_published_at"]), ts(r["cve_published_at"]))
                                                            for r in lag["rows"] if r.get("cve_published_at")) if x is not None])},
        "matching": {"hits": len(stt["hits"]), "eval": Counter(str(h["eval"]) for h in stt["hits"]), "eval_unknown_reasons": eval_reasons},
        "nvd": {k: dict(v) for k, v in nvd_groups.items()},
        "per_project": per_project,
    }
    save_json(d / "summary.json", summary)
    log(f"limbo {summary['limbo']['count']}/{len(adv_rows)} ({summary['limbo']['share']:.1%}); "
        f"excl. likely dups {summary['limbo']['count_excluding_likely_duplicates']}; RBP {len(rbp)}")
    log(f"review lag {summary['review_lag']['lag_days']}")
    for p, v in per_project.items():
        log(f"  {p}: {v}")


if __name__ == "__main__":
    main()
