"""Audit the live tracker, site and feed against primary sources (FINDINGS F-123). Run it before every release.

    uv run --with jsonschema python scripts/audit.py [--sample 300] [--out audit.md]

Read-only, and it needs the network: GitHub through `gh api` (about 2 requests per sampled advisory), OSV, CVE
Services and limbo.watch. It doesn't use the tracker's classification code: statuses, counts and metrics are
recomputed here from the raw `tracker-data` state the site was built from. Version ranges are the exception: feed
ranges are checked for consistency with `limbowatch.versions`, the parser the watcher uses.

Checks:
1. verdicts: a random sample of advisories in limbo, likely permanent, duplicates and reviewed, checked live;
2. reviewed sync: every repository advisory GitHub reviewed in the last 7 days is in the tracker's list;
3. metrics: every number in metrics.json, recomputed from the state;
4. feed: OSV-schema validation of every record, record fields against the state, index against the zip, and a
   package on every affected entry (older watchers need one);
5. ranges: each converted OSV range agrees with the parser at its boundary versions, and none covers every version
   from a range that doesn't say "all";
6. checker: /check/index.json covers the same advisories as the feed;
7. GIT ranges: for a sample of repos, the GIT entries of advisories without a package (C/C++ and the like), rebuilt
   from the repo's tags as `git ls-remote` lists them now, equal the feed's, and none is missing a range (F-138, F-142);
8. GIT packages: every entry has a package; GIT ones name their record's repo and keep the versions as entered;
9. old watchers: the oldest release and the newest on PyPI read the live feed (F-140).

Exit 1 if a check fails. The report is Markdown (stdout, or --out).
"""

from __future__ import annotations

import argparse
import io
import json
import random
import re
import statistics
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

SITE = "https://limbo.watch"
REVIEWABLE = {"npm", "pip", "go", "composer", "rust", "maven", "nuget", "rubygems", "erlang", "actions", "pub", "swift"}
CHECKER = {"npm", "PyPI", "crates.io", "Maven"}
AGE_BUCKETS = [("< 3 days", 0, 3), ("3–7 days", 3, 7), ("1–2 weeks", 7, 14), ("2–4 weeks", 14, 30),
               ("1–2 months", 30, 60), ("2–3 months", 60, 90), ("> 3 months", 90, 10**6)]  # fmt: skip
OSV_SCHEMA = "repos/ossf/osv-schema/contents/validation/schema.json"
http = httpx.Client(timeout=60, follow_redirects=True, headers={"User-Agent": "limbowatch-audit"})
# Every limbo.watch file is fetched past the CDN's cache, so metrics, feed and checker come from the same build: a
# cached all.zip from the build before made the 0.1.0a8 audit compare an old feed with new code (F-142).
NOCACHE = {"nocache": datetime.now(UTC).strftime("%Y%m%d%H%M%S")}


def at(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def gh(path: str) -> tuple[int, Any]:
    p = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if p.returncode == 0:
        return 200, json.loads(p.stdout)
    return (404 if "404" in p.stderr or "Not Found" in p.stderr else 0), None


def gh_pages(path: str) -> list[Any]:
    p = subprocess.run(["gh", "api", "--paginate", path, "--jq", ".[]"], capture_output=True, text=True, check=True)
    return [json.loads(line) for line in p.stdout.splitlines() if line.strip()]


class State:
    """The raw tracker state at the commit of tracker-data the site was built from."""

    def __init__(self, root: Path) -> None:
        def jl(name: str) -> list[dict[str, Any]]:
            return [json.loads(x) for x in (root / f"{name}.jsonl").read_text().splitlines() if x.strip()]

        self.adv = {a["ghsa_id"]: a for a in jl("advisories")}
        self.facts: dict[str, dict[str, Any]] = {}
        for r in jl("facts"):
            if r["ghsa_id"] not in self.facts or r["id"] > self.facts[r["ghsa_id"]]["id"]:
                self.facts[r["ghsa_id"]] = r
        self.reviewed = jl("reviewed")
        self.repos = jl("repos")
        self.events = jl("events")
        self.runs = sorted(jl("runs"), key=lambda r: r["started_at"])

    def items(self) -> list[dict[str, Any]]:
        out = []
        for g, r in self.facts.items():
            if g not in self.adv:
                continue
            f, a = r["facts"], self.adv[g]["data"]
            ecos = {p["ecosystem"] for p in a["packages"]} or {"other"}
            if f["reviewed"] or f["in_osv"]:
                st = "reviewed"
            elif f["repo_state"] == "withdrawn":
                st = "withdrawn"
            elif f["repo_state"] != "published":
                st = "not published"
            elif f["duplicate_of"]:
                st = "duplicate"
            else:
                st = "limbo"
            out.append({"g": g, "repo": self.adv[g]["repo"], "a": a, "f": f, "st": st, "ecos": ecos,
                        "perm": not ecos & REVIEWABLE})  # fmt: skip
        return out


def cve_label(f: dict[str, Any]) -> str:
    if f["cited_cve"]:
        return {"PUBLISHED": "CVE published, cited", "RESERVED": "CVE reserved (RBP)"}.get(
            f["cited_cve_state"], "CVE cited, other state"
        )
    return "CVE published by another CNA, not cited" if f["uncited_cves"] else "no CVE anywhere"


def load_state(metrics: dict[str, Any], tmp: Path) -> tuple[State, str]:
    """The tracker-data commit whose last run is the one metrics.json reports."""
    subprocess.run(["git", "fetch", "-q", "origin", "tracker-data"], check=True)
    want = (metrics.get("last_run") or {}).get("started_at")
    commits = subprocess.run(["git", "log", "origin/tracker-data", "--format=%H", "-n", "30"], capture_output=True,
                             text=True, check=True).stdout.split()  # fmt: skip
    for c in commits:
        runs = subprocess.run(["git", "show", f"{c}:state/runs.jsonl"], capture_output=True, text=True).stdout
        last = max((json.loads(x) for x in runs.splitlines() if x.strip()), key=lambda r: r["started_at"])
        if last["started_at"] == want:
            tar = subprocess.run(["git", "archive", c, "state"], capture_output=True, check=True).stdout
            with tarfile.open(fileobj=io.BytesIO(tar)) as t:
                t.extractall(tmp, filter="data")
            return State(tmp / "state"), c
    raise SystemExit(f"no tracker-data commit in the last 30 has the run metrics.json reports ({want})")


class Report:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.failed: list[str] = []

    def check(self, name: str, ok: bool, detail: str) -> None:
        self.lines.append(f"- {'PASS' if ok else '**FAIL**'} {name}: {detail}")
        if not ok:
            self.failed.append(name)

    def note(self, text: str) -> None:
        self.lines.append(f"  - {text}")


def check_verdicts(rep: Report, items: list[dict[str, Any]], n: int, seed: int) -> None:
    rnd = random.Random(seed)

    def pick(cond: Any, k: int) -> list[dict[str, Any]]:
        pool = [i for i in items if cond(i)]
        return rnd.sample(pool, min(k, len(pool)))

    sample = ([("limbo", i) for i in pick(lambda i: i["st"] == "limbo" and not i["perm"], n)]
              + [("permanent", i) for i in pick(lambda i: i["st"] == "limbo" and i["perm"], n // 3)]
              + [("duplicate", i) for i in pick(lambda i: i["st"] == "duplicate", n // 5)]
              + [("reviewed", i) for i in pick(lambda i: i["st"] == "reviewed", n // 5)])  # fmt: skip

    def cve(c: str) -> dict[str, Any]:
        r = http.get(f"https://cveawg.mitre.org/api/cve/{c}")
        if r.status_code == 200:
            return r.json()
        r = http.get(f"https://cveawg.mitre.org/api/cve-id/{c}")
        return {"_state": r.json().get("state") if r.status_code == 200 else f"http {r.status_code}"}

    def one(item: tuple[str, dict[str, Any]]) -> tuple[str, str, list[str]]:
        kind, i = item
        g, f, problems = i["g"], i["f"], []
        s1, ra = gh(f"/repos/{i['repo']}/security-advisories/{g}")
        s2, ga = gh(f"/advisories/{g}")
        s3 = http.get(f"https://api.osv.dev/v1/vulns/{g}").status_code
        reviewed = s2 == 200 and ga.get("type") == "reviewed"
        if kind == "reviewed":
            if not reviewed and s3 != 200:
                problems.append(f"not reviewed (global {s2}, OSV {s3})")
            return kind, g, problems
        if s1 != 200 or ra.get("state") != "published":
            problems.append(f"repository advisory now {s1 if s1 != 200 else ra.get('state')}")
        if reviewed:
            problems.append(f"reviewed at {ga.get('github_reviewed_at')}")
        if s3 == 200:
            problems.append("in OSV")
        if s1 == 200 and (ra.get("cve_id") or None) != f["cited_cve"]:
            problems.append(f"cites {ra.get('cve_id')} now, state says {f['cited_cve']}")
        if f["cited_cve"]:
            d = cve(f["cited_cve"])
            state = (d.get("cveMetadata") or {}).get("state") or d.get("_state")
            if state != f["cited_cve_state"]:
                problems.append(f"{f['cited_cve']} is {state}, state says {f['cited_cve_state']}")
        for c in f["uncited_cves"]:
            cna = ((cve(c).get("containers") or {}).get("cna")) or {}
            refs = [[x.get("url"), x.get("name")] for x in cna.get("references") or []]
            if g.upper() not in json.dumps([refs, cna.get("source")]).upper():
                problems.append(f"uncited {c} doesn't reference {g}")
        for dg in f["duplicate_of"]:
            s4, da = gh(f"/advisories/{dg}")
            shared = s4 == 200 and da.get("cve_id") in [f["cited_cve"], *f["uncited_cves"]]
            if not (shared and da.get("type") == "reviewed"):
                problems.append(f"duplicate_of {dg} isn't a reviewed advisory with a shared CVE")
        return kind, g, problems

    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(one, sample))
    by = Counter(k for k, _, _ in res)
    bad = [(k, g, p) for k, g, p in res if p]
    # A change since the run (reviewed or withdrawn after it) isn't a tracker error; anything else is.
    stale = [b for b in bad if all(x.startswith(("reviewed at", "in OSV", "repository advisory now")) for x in b[2])]
    wrong = [b for b in bad if b not in stale]
    rep.check("verdicts", not wrong, f"{len(res)} sampled live ({dict(by)}); {len(wrong)} wrong, "
              f"{len(stale)} changed since the run")  # fmt: skip
    for k, g, p in bad[:20]:
        rep.note(f"{k} {g}: {'; '.join(p)}")


def check_reviewed_sync(rep: Report, st: State, end: datetime) -> None:
    week = end - timedelta(days=7)
    day = lambda d: d.strftime("%Y-%m-%d")  # noqa: E731
    rows = {r["ghsa_id"]: r for q in (f"updated={day(week)}..{day(end + timedelta(days=1))}",)
            for r in gh_pages(f"/advisories?type=reviewed&per_page=100&{q}")}  # fmt: skip
    inw = [r for r in rows.values() if r.get("github_reviewed_at") and week <= at(r["github_reviewed_at"]) <= end]  # type: ignore[operator]
    repo_origin = [r for r in inw if r.get("repository_advisory_url")]
    known = {r["ghsa_id"] for r in st.reviewed}
    missing = [r["ghsa_id"] for r in repo_origin if r["ghsa_id"] not in known]
    rep.check("reviewed sync", not missing, f"GitHub reviewed {len(inw)} advisories in the 7 days to "
              f"{end:%Y-%m-%d %H:%M}, {len(repo_origin)} from repository advisories; {len(missing)} missing from the "
              f"tracker's list")  # fmt: skip
    if missing:
        rep.note(f"missing: {', '.join(missing[:10])}")


def check_metrics(rep: Report, st: State, items: list[dict[str, Any]], m: dict[str, Any]) -> None:
    now = at(m["generated_at"])
    assert now is not None
    limbo = [i for i in items if i["st"] == "limbo" and not i["perm"]]
    perm = [i for i in items if i["st"] == "limbo" and i["perm"]]

    def age(i: dict[str, Any]) -> float | None:
        p = at(i["a"]["published_at"])
        return (now - p).total_seconds() / 86400 if p else None

    ages = [x for i in limbo if (x := age(i)) is not None]
    sev = Counter(i["a"]["severity"] or "unknown" for i in limbo)
    rbp = [i for i in limbo if cve_label(i["f"]) == "CVE reserved (RBP)"]
    lag = [(at(i["f"]["reviewed_at"]) - at(i["a"]["published_at"])).total_seconds() / 86400  # type: ignore[operator]
           for i in items if i["f"]["reviewed_at"] and i["a"]["published_at"]]  # fmt: skip
    end = at(m["flow_7d"]["ends_at"])
    assert end is not None
    week = end - timedelta(days=7)
    reviewable_ids = {i["g"] for i in items if not i["perm"]}
    left = [e for e in st.events if e["event"].startswith("in limbo -> ") and e["ghsa_id"] in reviewable_ids
            and week <= at(e["at"]) <= end]  # type: ignore[operator]  # fmt: skip
    pub = lambda i: (p := at(i["a"]["published_at"])) is not None and week <= p <= end  # noqa: E731
    want = {
        "in_limbo.count": len(limbo),
        "in_limbo.by_cve": dict(Counter(cve_label(i["f"]) for i in limbo)),
        "in_limbo.by_severity": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low", "unknown")},
        "in_limbo.age_days_median": round(statistics.median(ages), 1) if ages else None,
        "in_limbo.age_buckets": {n: sum(1 for x in ages if lo <= max(x, 0) < hi) for n, lo, hi in AGE_BUCKETS},
        "in_limbo.rbp.count": len(rbp),
        "in_limbo.rbp.over_72h": sum(1 for i in rbp if (age(i) or 0) > 3),
        "likely_permanent.count": len(perm),
        "left_limbo.reviewed": sum(i["st"] == "reviewed" for i in items),
        "left_limbo.duplicates": sum(i["st"] == "duplicate" for i in items),
        "left_limbo.withdrawn_or_gone": sum(i["st"] in ("withdrawn", "not published") for i in items),
        "left_limbo.review_lag_days_median": round(statistics.median(lag), 1) if lag else None,
        "flow_7d.published": sum(1 for i in items if not i["perm"] and pub(i)),
        "flow_7d.published_all_ecosystems": sum(1 for i in items if pub(i)),
        "flow_7d.left": len(left),
        "flow_7d.reviewed": sum(e["event"] == "in limbo -> reviewed" for e in left),
        "coverage.watchlist_repos": len(st.repos),
        "coverage.repos_with_advisories": sum(1 for r in st.repos if r["advisory_count"]),
        "coverage.reviewed_advisories_known": len(st.reviewed),
    }

    def got(path: str) -> Any:
        v: Any = m
        for p in path.split("."):
            v = v.get(p) if isinstance(v, dict) else None
        return v

    diffs = [(k, v, got(k)) for k, v in want.items()
             if (v if not isinstance(v, dict) else {a: b for a, b in v.items() if b})
             != (got(k) if not isinstance(got(k), dict) else {a: b for a, b in got(k).items() if b})]  # fmt: skip
    rep.check(
        "metrics", not diffs, f"{len(want)} numbers in metrics.json recomputed from the state; {len(diffs)} differ"
    )
    for k, v, g in diffs:
        rep.note(f"{k}: recomputed {v}, site {g}")


def check_feed(rep: Report, st: State, items: list[dict[str, Any]], z: zipfile.ZipFile) -> dict[str, dict[str, Any]]:
    from jsonschema import validators

    schema = json.loads(__import__("base64").b64decode(gh(OSV_SCHEMA)[1]["content"]))
    validator = validators.validator_for(schema)(schema)
    recs = {n.removesuffix(".json"): json.loads(z.read(n)) for n in z.namelist() if n.endswith(".json")}
    invalid = [g for g, r in recs.items() if next(validator.iter_errors(r), None) is not None]
    want = {i["g"] for i in items if i["st"] == "limbo"}
    idx = http.get(f"{SITE}/feed/index.json", params=NOCACHE).json()
    by = {i["g"]: i for i in items}
    fields = []
    for g, r in recs.items():
        i, lw = by.get(g), r["database_specific"]["limbowatch"]
        if i is None:
            fields.append(f"{g}: not in the state")
            continue
        f = i["f"]
        same = {
            "status": lw["status"] == "in limbo",
            "likely_permanent": lw["likely_permanent"] == i["perm"],
            "cited_cve": lw["cited_cve"] == f["cited_cve"],
            "uncited": sorted(lw["uncited_cves"]) == sorted(f["uncited_cves"]),
            "repository": lw["repository"] == i["repo"],
            "published": r["published"][:19] == (i["a"]["published_at"] or "")[:19],
        }
        fields += [f"{g}: {name}" for name, ok in same.items() if not ok]
    # watchers before 0.1.0a7 read affected[].package of every entry, and fail without one (F-140)
    fields += [f"{g}: an affected entry without a package" for g, r in recs.items()
               if any("package" not in a for a in r["affected"])]  # fmt: skip
    index_ok = set(idx["ids"]) == set(recs)
    rep.check("feed", not invalid and not fields and set(recs) == want and index_ok,
              f"{len(recs):,} records ({len(want):,} in limbo in the state); {len(invalid)} invalid against the OSV "
              f"schema; {len(fields)} fields differ; index {'matches' if index_ok else 'differs'}")  # fmt: skip
    for x in invalid[:5] + fields[:10]:
        rep.note(x)
    return recs


def in_osv_ranges(cls: Any, v: Any, ranges: list[dict[str, Any]]) -> bool:
    """OSV semantics: affected if any range's events, in version order, leave `v` introduced and not fixed."""
    from limbowatch.versions import _mk

    def order(ev: dict[str, str]) -> tuple[bool, Any]:
        x = next(iter(ev.values()))
        return (x != "0", _mk(cls, x) if x != "0" else 0)

    for rg in ranges:
        hit = False
        for ev in sorted(rg["events"], key=order):
            ((k, x),) = ev.items()
            if k == "introduced" and (x == "0" or v >= _mk(cls, x)):
                hit = True
            elif (k == "fixed" and v >= _mk(cls, x)) or (k == "last_affected" and v > _mk(cls, x)):
                hit = False
        if hit:
            return True
    return False


ALL = re.compile(r"\s*(?:\*|all|any|all versions|>=?\s*v?0(?:\.0)*)\s*", re.I)


def check_ranges(rep: Report, recs: dict[str, dict[str, Any]]) -> None:
    from limbowatch.ecosystems import by_osv
    from limbowatch.versions import VERSION_CLASS, _mk, affected

    bad, checked = [], 0
    for g, r in recs.items():
        for e in r["affected"]:
            if "package" not in e or e["package"]["ecosystem"] == "GIT":
                continue  # GIT ranges, checked by check_git_ranges
            info = by_osv(e["package"]["ecosystem"])
            raw = e["database_specific"].get("vulnerable_version_range")
            if not e.get("ranges") or info is None or info.ghsa not in VERSION_CLASS or not raw:
                continue
            cls = VERSION_CLASS[info.ghsa]
            bounds = {v for rg in e["ranges"] for ev in rg["events"] for v in ev.values() if v != "0"}
            checked += 1
            for v in bounds:
                try:
                    mk = _mk(cls, v)
                except Exception:
                    continue
                osv = in_osv_ranges(cls, mk, e["ranges"])
                parsed = affected(info.ghsa, v, raw)
                fix_closed = parsed is True and not osv and e["database_specific"].get("patched_versions")
                if parsed is not None and parsed != osv and not fix_closed:
                    bad.append(f"{g} {e['package']['name']} `{raw}` at {v}: range {parsed}, feed {osv}")
                    break
            if all(rg["events"] == [{"introduced": "0"}] for rg in e["ranges"]) and not ALL.fullmatch(raw):
                bad.append(f"{g} {e['package']['name']} `{raw}`: the feed says every version")
    rep.check(
        "ranges", not bad, f"{checked:,} converted ranges checked at their boundary versions; {len(bad)} disagree"
    )
    for b in bad[:15]:
        rep.note(b)


def check_checker(rep: Report, recs: dict[str, dict[str, Any]]) -> None:
    ci = http.get(f"{SITE}/check/index.json", params=NOCACHE).json()
    got = {x["g"] for eco in ci["ecosystems"].values() for lst in eco.values() for x in lst}
    want = {g for g, r in recs.items() for e in r["affected"]
            if "package" in e and e["package"]["ecosystem"] in CHECKER
            and e["database_specific"].get("name_valid")}  # fmt: skip
    rep.check(
        "checker",
        got == want and ci["advisories"] == len(got),
        f"{len(got):,} advisories in /check/index.json, {len(want):,} expected from the feed",
    )


def check_git_ranges(rep: Report, recs: dict[str, dict[str, Any]], n: int, seed: int) -> None:
    """For a sample of repos, every GIT entry (with ranges or without) rebuilt from the repo's tags as they are now:
    ranges must be equal, and an entry without ranges must not have every version tagged by now (that range was missed,
    F-142). Tags made since the tracker's last run (it lists every repo daily) explain a few; more than 2% fails."""
    from limbowatch.models import AdvisoryPackage
    from limbowatch.publish.feed import git_ranges, git_versions
    from limbowatch.sources.gitrefs import parse
    from limbowatch.versions import tag_for

    by_repo: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for g, r in recs.items():
        for e in r["affected"]:
            if e.get("package", {}).get("ecosystem") == "GIT":
                by_repo.setdefault(r["database_specific"]["limbowatch"]["repository"], []).append((g, e))
    repos = sorted(r for r, es in by_repo.items() if any(e.get("ranges") for _, e in es))
    random.Random(seed).shuffle(repos)
    env = {"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}

    def listed(repo: str) -> dict[str, str] | None:
        try:
            p = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}.git"], capture_output=True,
                               text=True, timeout=120, env=env)  # fmt: skip
        except subprocess.TimeoutExpired:
            return None
        return parse(p.stdout) if p.returncode == 0 else None

    sample = repos[:n]
    with ThreadPoolExecutor(8) as ex:
        tags = dict(zip(sample, ex.map(listed, sample), strict=True))
    bad, missing, checked = [], [], 0
    for repo in sample:
        if tags[repo] is None:
            bad.append(f"{repo}: tags couldn't be listed")
            continue
        for g, e in by_repo[repo]:
            ds = e["database_specific"]
            p = AdvisoryPackage(ecosystem=ds["ecosystem_as_entered"], name=ds.get("name_as_entered"),
                                vulnerable_version_range=ds.get("vulnerable_version_range"),
                                patched_versions=ds.get("patched_versions"))  # fmt: skip
            git = {v: [t, tags[repo][t]] if (t := tag_for(v, tags[repo])) else None for v in git_versions(p)}
            want = git_ranges(repo, p, git)
            checked += 1
            if e.get("ranges") and want != e["ranges"]:
                bad.append(f"{g} ({repo}) `{ds.get('vulnerable_version_range')}`: GIT ranges differ from the tags now")
            elif not e.get("ranges") and want is not None:
                missing.append(f"{g} ({repo}) `{ds.get('vulnerable_version_range')}`: every version is tagged now, "
                               "but the feed has no GIT range")  # fmt: skip
    ok = not bad and len(missing) <= 0.02 * max(checked, 1)
    rep.check("git ranges", ok, f"{checked:,} GIT entries in {len(sample)} repos rebuilt from live tags "
                                f"({len(repos):,} repos have ranges); {len(bad)} differ, {len(missing)} missing a "
                                "range (at most 2% allowed: tags since the last run)")  # fmt: skip
    for b in (bad + missing)[:15]:
        rep.note(b)


def check_git_packages(rep: Report, recs: dict[str, dict[str, Any]]) -> None:
    """Every entry has a package (older watchers need one, F-140); a GIT package and its ranges name the record's own
    repo, and keep the versions as entered."""
    bad = []
    n = 0
    for g, r in recs.items():
        repo = f"https://github.com/{r['database_specific']['limbowatch']['repository']}"
        for e in r["affected"]:
            pkg = e.get("package") or {}
            if not pkg.get("ecosystem") or not pkg.get("name"):
                bad.append(f"{g}: an entry without a package ecosystem and name")
            if pkg.get("ecosystem") != "GIT":
                continue
            n += 1
            ds = e.get("database_specific") or {}
            if pkg["name"] != repo or any(rg.get("repo") != repo for rg in e.get("ranges") or []):
                bad.append(f"{g}: GIT package or range names another repo than {repo}")
            if "ecosystem_as_entered" not in ds or "vulnerable_version_range" not in ds:
                bad.append(f"{g}: GIT entry without the versions as entered")
    rep.check("git packages", not bad, f"{n:,} GIT entries name their record's repo and keep the versions as "
                                       f"entered; {len(bad)} don't")  # fmt: skip
    for b in bad[:10]:
        rep.note(b)


def check_old_watchers(rep: Report, z: zipfile.ZipFile) -> None:
    """The oldest release and the newest on PyPI read the live feed: every watcher users pin parses it with its own
    code, and a format change once made every release before 0.1.0a7 fail (F-140)."""
    latest = http.get("https://pypi.org/pypi/limbowatch-cli/json").json()["info"]["version"]
    n = sum(1 for x in z.namelist() if x.endswith(".json"))
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        feed = Path(tmp) / "all.zip"
        feed.write_bytes(Path(z.filename).read_bytes() if z.filename else b"")
        for v in dict.fromkeys(("0.1.0a1", latest)):
            code = ("import sys; from limbowatch.watch.candidates import from_feed_zip; "
                    "print(len(from_feed_zip(open(sys.argv[1], 'rb').read())))")  # fmt: skip
            p = subprocess.run(["uvx", "-q", "--from", f"limbowatch-cli=={v}", "python", "-c", code, str(feed)],
                               capture_output=True, text=True, timeout=600)  # fmt: skip
            got = p.stdout.strip()
            out.append((v, got == str(n), got or p.stderr.strip().splitlines()[-1:]))
    rep.check("old watchers", all(ok for _, ok, _ in out),
              "; ".join(f"{v} reads {got}" for v, _, got in out) + f" of {n:,} records")  # fmt: skip


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", type=int, default=300, help="advisories in limbo to verify live (others scale)")
    ap.add_argument("--seed", type=int, default=int(datetime.now(UTC).strftime("%Y%m%d")))
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    rep = Report()
    m = http.get(f"{SITE}/metrics.json", params=NOCACHE).json()
    with tempfile.TemporaryDirectory() as tmp:
        st, commit = load_state(m, Path(tmp))
        items = st.items()
        rep.lines.append(f"# Limbowatch audit, {datetime.now(UTC):%Y-%m-%d %H:%M} UTC\n")
        rep.lines.append(f"Site built {m['generated_at']} from `tracker-data` {commit[:7]} (run "
                         f"{m['last_run']['started_at']}). Sample seed {a.seed}.\n")  # fmt: skip
        feed_path = Path(tmp) / "all.zip"
        feed_path.write_bytes(http.get(f"{SITE}/feed/all.zip", params=NOCACHE).content)
        z = zipfile.ZipFile(feed_path)
        check_verdicts(rep, items, a.sample, a.seed)
        check_reviewed_sync(rep, st, at(m["flow_7d"]["ends_at"]))  # type: ignore[arg-type]
        check_metrics(rep, st, items, m)
        recs = check_feed(rep, st, items, z)
        check_ranges(rep, recs)
        check_checker(rep, recs)
        check_git_ranges(rep, recs, max(50, a.sample // 2), a.seed)
        check_git_packages(rep, recs)
        check_old_watchers(rep, z)
    rep.lines.append(f"\n{'All checks passed.' if not rep.failed else 'Failed: ' + ', '.join(rep.failed)}")
    text = "\n".join(rep.lines) + "\n"
    if a.out:
        a.out.write_text(text)
    print(text)
    sys.exit(1 if rep.failed else 0)


if __name__ == "__main__":
    main()
