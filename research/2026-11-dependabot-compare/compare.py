"""Dependabot vs Limbowatch on real projects (research/2026-11-dependabot-compare).

For each project of the October report (research/2026-10-state-of-the-gap), at its current HEAD:

  prepare  sparse, blob-less clone of only the dependency files (lockfiles, plus the manifests Dependabot reads),
           test fixtures and vendored copies left out; `limbowatch scan --scan-ignored` on exactly those files (the
           clones sit in a gitignored .cache/).
  push     for each project with findings: a PRIVATE repo limbowatch/dbcmp-<name> holding the same files, with
           Dependabot alerts turned on before the files are pushed (the dependency graph builds on a push, F-090).
  collect  Dependabot alerts (GET /repos/{r}/dependabot/alerts) and the dependency graph (GET /repos/{r}/dependency-
           graph/sbom) of each copy; every Limbowatch finding classified:
             alerted       Dependabot has an alert for the same advisory (GHSA or CVE) on that package
             not-alerted   the package and version are in GitHub's dependency graph, and there's no alert
             not-in-graph  GitHub's dependency graph doesn't list that package and version
           plus a live re-check of each advisory: still published and not withdrawn upstream (GET /repos/{repo}/security-
           advisories/{ghsa}), absent from the reviewed database (GET /advisories/{ghsa}) and from OSV (GET /v1/vulns/{ghsa}).

Writes data/<date>/{scans,alerts,sboms,compare}.json (gitignored: they hold dependency inventories and alert
metadata) and data/<date>/summary.json (counts only, committed; like the October report's summaries, no per-project advisory list). No advisory text is stored.
Needs git, gh (logged in, allowed to create repos in the limbowatch org), uv, OSV-Scanner 2.7.0 on PATH, network.

    uv run --no-project python research/2026-11-dependabot-compare/compare.py prepare|push|collect
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
CACHE = HERE / ".cache"
DATE = os.environ.get("SNAPSHOT_DATE", datetime.date.today().isoformat())
DATA = HERE / "data" / DATE
ORG = "limbowatch"
PREFIX = "dbcmp-"

PROJECTS = {  # the October report's 15 projects (research/2026-10-state-of-the-gap/scripts/s1_inventory.py)
    "gitea": "https://github.com/go-gitea/gitea.git",
    "kubernetes": "https://github.com/kubernetes/kubernetes.git",
    "n8n": "https://github.com/n8n-io/n8n.git",
    "open-webui": "https://github.com/open-webui/open-webui.git",
    "langchain": "https://github.com/langchain-ai/langchain.git",
    "gitlab": "https://gitlab.com/gitlab-org/gitlab.git",
    "gitlab-runner": "https://gitlab.com/gitlab-org/gitlab-runner.git",
    "gitaly": "https://gitlab.com/gitlab-org/gitaly.git",
    "forgejo": "https://codeberg.org/forgejo/forgejo.git",
    "gotosocial": "https://codeberg.org/superseriousbusiness/gotosocial.git",
    "arti": "https://gitlab.torproject.org/tpo/core/arti.git",
    "fractal": "https://gitlab.gnome.org/World/fractal.git",
    "fdroidserver": "https://gitlab.com/fdroid/fdroidserver.git",
    "mobilizon": "https://framagit.org/framasoft/mobilizon.git",
    "aerc": "https://git.sr.ht/~rjarry/aerc",
}
# The October report's lockfiles, plus the manifests next to them that GitHub's dependency graph reads.
LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "uv.lock", "poetry.lock",
             "Pipfile.lock", "pdm.lock", "pylock.toml", "requirements*.txt", "go.mod", "Cargo.lock", "composer.lock", "Gemfile.lock"]
MANIFESTS = ["package.json", "pyproject.toml", "Pipfile", "go.sum", "Cargo.toml", "composer.json", "Gemfile", "*.gemspec"]
EXCLUDE_DIRS = ["testdata", "fixtures", "__fixtures__", "test-fixtures", "node_modules", "vendor"]


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now():%H:%M:%S}] {msg}", file=sys.stderr, flush=True)


def run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def gh_json(path: str, paginate: bool = False) -> Any:
    cmd = ["gh", "api", "-X", "GET", path] + (["--paginate", "--slurp"] if paginate else [])
    r = run(cmd)
    if r.returncode != 0:
        return None
    out = json.loads(r.stdout)
    return [x for page in out for x in page] if paginate else out


def save(name: str, obj: Any) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / name).write_text(json.dumps(obj, indent=1, sort_keys=True) + "\n")


def load(name: str) -> Any:
    return json.loads((DATA / name).read_text())


# --- prepare ---------------------------------------------------------------------------------------------------

def sparse_clone(name: str, url: str) -> tuple[Path, str]:
    dest = CACHE / "repos" / name
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(3):
        r = run(["git", "clone", "--quiet", "--depth", "1", "--filter=blob:none", "--no-checkout", url, str(dest)])
        if r.returncode == 0:
            break
        log(f"  clone failed ({r.stderr.strip()[-200:]}), retrying")
        shutil.rmtree(dest, ignore_errors=True)
        time.sleep(20 * (attempt + 1))
    else:
        raise RuntimeError(f"clone of {url} failed")
    patterns = [f"**/{p}" for p in LOCKFILES + MANIFESTS] + [f"!**/{d}/**" for d in EXCLUDE_DIRS]
    run(["git", "-C", str(dest), "sparse-checkout", "set", "--no-cone", *patterns], check=True)
    for attempt in range(3):  # blobs are fetched lazily; busy hosts drop that fetch now and then
        if run(["git", "-C", str(dest), "checkout", "--quiet"]).returncode == 0:
            break
        time.sleep(20 * (attempt + 1))
    else:
        raise RuntimeError(f"checkout of {url} failed")
    sha = run(["git", "-C", str(dest), "rev-parse", "HEAD"], check=True).stdout.strip()
    return dest, sha


def dependency_files(tree: Path) -> list[str]:
    files = []
    for p in sorted(tree.rglob("*")):
        rel = p.relative_to(tree)
        if p.is_file() and ".git" not in rel.parts and not set(rel.parts) & set(EXCLUDE_DIRS):
            files.append(rel.as_posix())
    return files


def prepare(names: list[str]) -> None:
    scans = json.loads((DATA / "scans.json").read_text()) if (DATA / "scans.json").exists() else {}
    for name in names:
        log(f"{name}: cloning dependency files")
        try:
            tree, sha = sparse_clone(name, PROJECTS[name])
        except RuntimeError as e:
            scans[name] = {"url": PROJECTS[name], "error": str(e)}
            save("scans.json", scans)
            continue
        files = dependency_files(tree)
        out = CACHE / "scans" / f"{name}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        r = run(["uv", "run", "--project", str(REPO_ROOT), "limbowatch", "scan", str(tree), "--scan-ignored", "-o", f"json={out}"], cwd=REPO_ROOT)
        if r.returncode not in (0, 1):
            log(f"  scan couldn't run (exit {r.returncode}): {r.stderr.strip()[-300:]}")
            scans[name] = {"url": PROJECTS[name], "commit": sha, "files": files, "error": f"scan exit {r.returncode}"}
            save("scans.json", scans)
            continue
        s = json.loads(out.read_text())
        findings = [{"ghsa": f["ghsa_id"], "cves": f["cves"], "ecosystem": f["dependency"]["ecosystem"],
                     "package": f["dependency"]["name"], "version": f["dependency"]["version"], "path": os.path.relpath(REPO_ROOT / f["path"], tree),
                     "severity": f["severity"], "affected": f["affected"], "published_at": f["published_at"], "repo": f["repo"]}
                    for f in s["findings"]]
        scans[name] = {"url": PROJECTS[name], "commit": sha, "files": files, "summary": s["summary"],
                       "feed_generated_at": s["feed_generated_at"], "unresolved": len(s.get("unresolved") or []), "findings": findings}
        log(f"  {sha[:10]}: {len(files)} files, {s['summary']['dependencies']} dependencies, {len(findings)} findings")
        save("scans.json", scans)


# --- push ------------------------------------------------------------------------------------------------------

def push(names: list[str]) -> None:
    scans = load("scans.json")
    for name in names:
        s = scans.get(name)
        if not s or not s.get("findings"):
            log(f"{name}: no findings, not copied")
            continue
        repo = f"{ORG}/{PREFIX}{name}"
        if gh_json(f"repos/{repo}") is None:
            desc = f"Private research copy of {s['url']} dependency files at {s['commit'][:12]} (Dependabot vs Limbowatch)"
            r = run(["gh", "repo", "create", repo, "--private", "--disable-issues", "--disable-wiki", "--description", desc])
            if r.returncode != 0:
                raise SystemExit(f"creating {repo} failed: {r.stderr.strip()}")
            log(f"{name}: created private {repo}")
        r = run(["gh", "api", "-X", "PUT", f"repos/{repo}/vulnerability-alerts"])
        if r.returncode != 0:
            raise SystemExit(f"turning on Dependabot alerts for {repo} failed: {r.stderr.strip()}")
        src = CACHE / "repos" / name
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for rel in s["files"]:
                (work / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src / rel, work / rel)
            (work / "README.md").write_text(
                f"# {name}: dependency files only\n\nPrivate research copy of the dependency files of {s['url']} at commit "
                f"`{s['commit']}`, for comparing GitHub's Dependabot alerts with Limbowatch "
                f"(https://github.com/limbowatch/limbowatch/tree/main/research/2026-11-dependabot-compare). "
                f"No source code. Not maintained; deleted after the study.\n")
            g = ["git", "-C", str(work)]
            run([*g, "init", "-q", "-b", "main"], check=True)
            run([*g, "add", "-A"], check=True)
            run([*g, "-c", "commit.gpgsign=false", "commit", "-q", "-m", f"Dependency files of {s['url']} at {s['commit']}"], check=True)
            r = run([*g, "push", "-q", "--force", f"git@github.com:{repo}.git", "main"])
            if r.returncode != 0:
                raise SystemExit(f"push to {repo} failed: {r.stderr.strip()[-300:]}")
        log(f"{name}: pushed {len(s['files'])} files")


# --- collect ---------------------------------------------------------------------------------------------------

def osv_status(ghsa: str) -> int:
    try:
        with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{ghsa}", timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def norm(eco: str, name: str) -> str:
    n = name.lower()
    return n.replace("_", "-").replace(".", "-") if eco.lower() in ("pip", "pypi") else n


def collect(names: list[str]) -> None:
    scans = load("scans.json")
    alerts_all, sboms, compare, reviewed_cache, osv_cache, upstream_cache = {}, {}, {}, {}, {}, {}
    for name in names:
        s = scans.get(name)
        if not s or not s.get("findings"):
            continue
        repo = f"{ORG}/{PREFIX}{name}"
        alerts = gh_json(f"repos/{repo}/dependabot/alerts?per_page=100", paginate=True) or []
        sbom = gh_json(f"repos/{repo}/dependency-graph/sbom") or {}
        graph = set()
        for p in (sbom.get("sbom") or {}).get("packages", []):
            for ref in p.get("externalRefs", []):
                loc = ref.get("referenceLocator", "")
                if loc.startswith("pkg:"):  # pkg:<type>/<name>@<version>
                    body = loc[4:].split("?")[0]
                    typ, _, rest = body.partition("/")
                    pname, _, ver = rest.rpartition("@")
                    graph.add((typ, norm(typ, urllib.request.unquote(pname)), ver.lstrip("v")))
        alerts_all[name] = [{"number": a["number"], "state": a["state"], "ghsa": a["security_advisory"]["ghsa_id"],
                             "cve": a["security_advisory"].get("cve_id"), "ecosystem": a["dependency"]["package"]["ecosystem"],
                             "package": a["dependency"]["package"]["name"], "manifest": a["dependency"].get("manifest_path"),
                             "severity": a["security_advisory"]["severity"], "created_at": a["created_at"]} for a in alerts]
        sboms[name] = sorted("/".join(t) for t in graph)
        alert_ids = {(a["ghsa"]) for a in alerts_all[name]} | {a["cve"] for a in alerts_all[name] if a["cve"]}
        typ_of = {"npm": "npm", "pip": "pypi", "pypi": "pypi", "go": "golang", "rubygems": "gem", "cargo": "cargo", "rust": "cargo",
                  "crates.io": "cargo", "composer": "composer", "packagist": "composer", "maven": "maven", "nuget": "nuget"}
        rows = []
        for f in s["findings"]:
            typ = typ_of.get(f["ecosystem"].lower(), f["ecosystem"].lower())
            in_graph = any(t == typ and n == norm(typ, f["package"]) and v == f["version"].lstrip("v") for t, n, v in graph)
            alerted = f["ghsa"] in alert_ids or any(c in alert_ids for c in f["cves"])
            if f["ghsa"] not in reviewed_cache:
                reviewed_cache[f["ghsa"]] = gh_json(f"advisories/{f['ghsa']}") is not None
                osv_cache[f["ghsa"]] = osv_status(f["ghsa"])
                adv = gh_json(f"repos/{f['repo']}/security-advisories/{f['ghsa']}") or {}
                upstream_cache[f["ghsa"]] = adv.get("state") == "published" and not adv.get("withdrawn_at")
            rows.append({**f, "in_graph": in_graph, "dependabot": "alerted" if alerted else ("not-alerted" if in_graph else "not-in-graph"),
                         "reviewed_now": reviewed_cache[f["ghsa"]], "osv_now": osv_cache[f["ghsa"]],
                         "upstream_published_now": upstream_cache[f["ghsa"]]})
        compare[name] = {"repo": repo, "commit": s["commit"], "graph_packages": len(graph), "alerts": len(alerts), "findings": rows}
        c = {k: sum(r["dependabot"] == k for r in rows) for k in ("alerted", "not-alerted", "not-in-graph")}
        log(f"{name}: {len(alerts)} Dependabot alerts, graph {len(graph)} packages; Limbowatch {len(rows)} findings → {c}")
    save("alerts.json", alerts_all)
    save("sboms.json", sboms)
    save("compare.json", compare)
    summary: dict[str, Any] = {"date": DATE, "checked_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
                               "projects": {}, "attribution": "GitHub repository security advisories and the GitHub Advisory "
                               "Database (CC BY 4.0); OSV.dev"}
    for name, s in scans.items():
        entry: dict[str, Any] = {"url": s["url"], "commit": s.get("commit"), "error": s.get("error")}
        if "summary" in s:
            entry |= {"dependencies": s["summary"]["dependencies"], "unchecked": s["summary"]["unchecked"],
                      "limbowatch_findings": len(s["findings"]), "limbowatch_advisories": len({f["ghsa"] for f in s["findings"]})}
        if name in compare:
            rows = compare[name]["findings"]
            entry |= {"dependabot_alerts_total": compare[name]["alerts"],
                      "dependabot_open_alerts": sum(a["state"] == "open" for a in alerts_all[name]),
                      "graph_packages": compare[name]["graph_packages"],
                      "findings_by_dependabot_status": {k: sum(r["dependabot"] == k for r in rows) for k in ("alerted", "not-alerted", "not-in-graph")},
                      "findings_reviewed_now": sum(r["reviewed_now"] for r in rows),
                      "findings_in_osv_now": sum(r["osv_now"] == 200 for r in rows),
                      "findings_upstream_published_now": sum(r["upstream_published_now"] for r in rows)}
        summary["projects"][name] = entry
    save("summary.json", summary)


if __name__ == "__main__":
    stage, *only = sys.argv[1:] or ["?"]
    chosen = only or list(PROJECTS)
    {"prepare": prepare, "push": push, "collect": collect}.get(stage, lambda _: sys.exit(__doc__))(chosen)
