# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx", "univers"]
# ///
"""Stage 1: inventory. Sparse-clone lockfiles of each project, run OSV-Scanner --all-packages.

Output: data/<snapshot>/inventory.json with every package (ecosystem, name, version, lockfile)
and the vulnerability IDs OSV-Scanner reports for it (the "what a scanner sees" baseline).
"""

from __future__ import annotations

import json
import os
import fnmatch
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

from common import CACHE, DATA, ROOT, SNAPSHOT, UA, log, save_json

GITHUB = ["go-gitea/gitea", "kubernetes/kubernetes", "n8n-io/n8n", "open-webui/open-webui", "langchain-ai/langchain"]
# Popular projects hosted off GitHub (GitLab, Codeberg/Forgejo, GNOME, Tor, Framagit, SourceHut).
OFF_GITHUB = {
    "gitlab.com/gitlab-org/gitlab": "https://gitlab.com/gitlab-org/gitlab.git",
    "gitlab.com/gitlab-org/gitlab-runner": "https://gitlab.com/gitlab-org/gitlab-runner.git",
    "gitlab.com/gitlab-org/gitaly": "https://gitlab.com/gitlab-org/gitaly.git",
    "codeberg.org/forgejo/forgejo": "https://codeberg.org/forgejo/forgejo.git",
    "codeberg.org/superseriousbusiness/gotosocial": "https://codeberg.org/superseriousbusiness/gotosocial.git",
    "gitlab.torproject.org/tpo/core/arti": "https://gitlab.torproject.org/tpo/core/arti.git",
    "gitlab.gnome.org/World/fractal": "https://gitlab.gnome.org/World/fractal.git",
    "gitlab.com/fdroid/fdroidserver": "https://gitlab.com/fdroid/fdroidserver.git",
    "framagit.org/framasoft/mobilizon": "https://framagit.org/framasoft/mobilizon.git",
    "git.sr.ht/~rjarry/aerc": "https://git.sr.ht/~rjarry/aerc",
}
TOP100 = ROOT.parent.parent / "tracker" / "seeds" / "top100-projects.txt"  # tracker seed (make_seed.py select)
PROJECT_SETS = {
    "github": {s: f"https://github.com/{s}.git" for s in GITHUB},
    "offgithub": OFF_GITHUB,
    "top100": {s: f"https://github.com/{s}.git" for s in
               (ln.split("\t")[0] for ln in (TOP100.read_text().splitlines() if TOP100.exists() else []) if ln and not ln.startswith("#"))},
}
PROJECTS = PROJECT_SETS[os.environ.get("PROJECT_SET", "github")]
OSV_SCANNER_VERSION = "v2.7.0"
LOCKFILES = [
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock",
    "uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock", "pylock.toml", "requirements*.txt",
    "go.mod", "Cargo.lock", "composer.lock", "Gemfile.lock",
]
EXCLUDE_DIRS = {"testdata", "fixtures", "__fixtures__", "test-fixtures", "node_modules", "vendor"}


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def osv_scanner() -> Path:
    bindir = CACHE / "bin"
    exe = bindir / "osv-scanner"
    if not exe.exists():
        log(f"building osv-scanner {OSV_SCANNER_VERSION} into {bindir}")
        bindir.mkdir(parents=True, exist_ok=True)
        r = run(["go", "install", f"github.com/google/osv-scanner/v2/cmd/osv-scanner@{OSV_SCANNER_VERSION}"],
                env={**os.environ, "GOBIN": str(bindir)})
        if r.returncode != 0:
            raise SystemExit(f"go install failed: {r.stderr[-500:]}")
    return exe


def sparse_clone(slug: str, url: str) -> tuple[Path, str]:
    """Sparse, blob-less clone of only the lockfiles. Reuses an existing clone (hosts like gitlab.com
    shed load on repeated full-tree clones of large repos); retries with backoff when a host is busy."""
    dest = CACHE / "repos" / slug.replace("/", "__").replace("~", "")
    if not (dest / ".git").exists():
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        for attempt, wait in enumerate((60, 180, 300, None)):
            r = run(["git", "clone", "--quiet", "--depth", "1", "--filter=blob:none", "--no-checkout", url, str(dest)])
            if r.returncode == 0:
                break
            log(f"  clone attempt {attempt + 1} failed: {r.stderr.strip()[-160:]}")
            if wait is None:
                raise SystemExit(f"clone {slug} failed")
            shutil.rmtree(dest, ignore_errors=True)
            time.sleep(wait)
    else:
        log(f"  reusing existing clone {dest.name}")
    run(["git", "-C", str(dest), "sparse-checkout", "set", "--no-cone", *[f"**/{p}" for p in LOCKFILES]], check=True)
    sha = run(["git", "-C", str(dest), "rev-parse", "HEAD"], check=True).stdout.strip()
    marker = dest / ".raw-fetched"
    if marker.exists() and marker.read_text().strip() == sha:
        log(f"  lockfiles already fetched over HTTPS at {sha[:10]}")
        return dest, sha
    for attempt in range(3):  # partial clones fetch blobs lazily; hosts can drop that fetch
        r = run(["git", "-C", str(dest), "checkout", "--quiet"])
        if r.returncode == 0:
            break
        log(f"  checkout attempt {attempt + 1} failed: {r.stderr.strip()[-200:]}")
        time.sleep(30 * (attempt + 1))
    else:
        raw_fetch(slug, url, dest, sha)  # the tree is local; fetch only the lockfile blobs over HTTPS
    return dest, sha


def raw_url(url: str, sha: str, path: str) -> str:
    base = url.removesuffix(".git")
    q = urllib.parse.quote(path)
    if "git.sr.ht" in base:
        return f"{base}/blob/{sha}/{q}"
    if "codeberg.org" in base:  # Forgejo / Gitea
        return f"{base}/raw/commit/{sha}/{q}"
    return f"{base}/-/raw/{sha}/{q}"  # GitLab (gitlab.com, self-managed, framagit, gnome, torproject)


def raw_fetch(slug: str, url: str, dest: Path, sha: str) -> None:
    names = run(["git", "-C", str(dest), "ls-tree", "-r", "--name-only", sha], check=True).stdout.split()
    wanted = [n for n in names if any(fnmatch.fnmatch(n.rsplit("/", 1)[-1], pat) for pat in LOCKFILES)]
    log(f"  git checkout refused by host; fetching {len(wanted)} lockfiles over HTTPS at {sha[:10]}")
    for path in wanted:
        target = dest / path
        target.parent.mkdir(parents=True, exist_ok=True)
        for attempt, wait in enumerate((20, 60, 120, None)):
            try:
                req = urllib.request.Request(raw_url(url, sha, path), headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    target.write_bytes(resp.read())
                break
            except (urllib.error.URLError, TimeoutError) as e:
                if wait is None:
                    raise SystemExit(f"raw fetch of {slug}:{path} failed: {e}") from e
                time.sleep(wait)
        time.sleep(0.5)  # be polite to the host
    (dest / ".raw-fetched").write_text(sha)


def lockfiles_in(dest: Path) -> list[Path]:
    """Checked-out lockfiles, minus fixture/vendor copies (counted and logged)."""
    keep, removed = [], 0
    for f in sorted(p for p in dest.rglob("*") if p.is_file() and ".git" not in p.relative_to(dest).parts and p.name != ".raw-fetched"):
        if EXCLUDE_DIRS & set(f.relative_to(dest).parts[:-1]):
            removed += 1
        else:
            keep.append(f)
    log(f"  {len(keep)} lockfiles; excluded {removed} fixture/vendor lockfiles")
    return keep


def scan(exe: Path, src: Path, out: Path) -> dict:
    # Explicit -L per lockfile: `scan source --recursive DIR` silently finds nothing when DIR
    # sits under a hidden directory such as .cache (FINDINGS F-040).
    files = lockfiles_in(src)
    unreadable: list[str] = []
    for _ in range(len(files) + 1):  # a malformed lockfile fails the whole scan: drop it, record it, retry
        args: list[str] = []
        for f in files:
            is_req = f.name.startswith("requirements") and f.name.endswith(".txt")
            args += ["-L", f"requirements.txt:{f}" if is_req and f.name != "requirements.txt" else str(f)]
        if out.exists():
            out.unlink()
        r = run([str(exe), "scan", "source", "--all-packages", "--format", "json", "--output-file", str(out), *args])
        bad = [f for f in files if "extraction failed" in r.stderr and f"{str(f).lstrip('/')}: could not extract" in r.stderr]
        if r.returncode not in (0, 1) and bad:
            unreadable += [str(f.relative_to(src)) for f in bad]
            files = [f for f in files if f not in bad]
            log(f"  unreadable lockfile(s), recorded and skipped: {[str(f.relative_to(src)) for f in bad]}")
            if files:
                continue
            return {"results": [], "no_package_sources": True, "unreadable_lockfiles": unreadable}
        break
    if r.returncode == 128 and "No package sources found" in r.stderr:
        return {"results": [], "no_package_sources": True, "unreadable_lockfiles": unreadable}  # recorded by the caller
    if r.returncode not in (0, 1) or not out.exists():  # 1 = vulnerabilities found
        raise SystemExit(f"osv-scanner failed ({r.returncode}): {r.stderr[-800:]}")
    return {**json.loads(out.read_text()), "unreadable_lockfiles": unreadable}


def main() -> None:
    exe = osv_scanner()
    inventory: dict[str, dict] = {}
    failed: dict[str, str] = {}
    for slug, url in PROJECTS.items():
        log(f"inventory {slug}")
        try:
            src, sha = sparse_clone(slug, url)
        except SystemExit as e:  # record and continue: a project we couldn't read is reported, not dropped
            failed[slug] = str(e)
            log(f"  SKIPPED {slug}: {e}")
            continue
        try:
            res = scan(exe, src, CACHE / f"osv-{slug.replace('/', '__').replace('~', '')}.json")
        except SystemExit as e:  # same rule: record the project as unreadable, keep going
            failed[slug] = str(e)[:500]
            log(f"  SCAN FAILED {slug}: {str(e)[:200]}")
            continue
        if res.get("no_package_sources"):
            failed[slug] = "no package sources: OSV-Scanner found no readable lockfile (only fixtures / undeclared lockfile)"
            log(f"  NO PACKAGE SOURCES for {slug}; recorded as inventory gap")
        pkgs, lockfiles = [], Counter()
        for result in res.get("results", []):
            path = str(Path(result["source"]["path"]).relative_to(src))
            for p in result.get("packages", []):
                pk = p["package"]
                ids = sorted({v["id"] for v in p.get("vulnerabilities", [])} |
                             {a for v in p.get("vulnerabilities", []) for a in v.get("aliases", [])})
                pkgs.append({"ecosystem": pk.get("ecosystem", ""), "name": pk["name"], "version": pk.get("version", ""),
                             "lockfile": path, "osv_ids": ids})
                lockfiles[path] += 1
        inventory[slug] = {"commit": sha, "clone_url": url, "lockfiles": dict(lockfiles), "packages": pkgs,
                           "unreadable_lockfiles": res.get("unreadable_lockfiles", [])}
        eco = Counter(p["ecosystem"] for p in pkgs)
        nover = sum(1 for p in pkgs if not p["version"])
        log(f"  {len(lockfiles)} lockfiles, {len(pkgs)} package entries, {nover} without version, {dict(eco)}")
    save_json(DATA / SNAPSHOT / "inventory.json", {"snapshot": SNAPSHOT, "osv_scanner": OSV_SCANNER_VERSION, "projects": inventory,
                                                   "inventory_failed": failed})
    log("wrote inventory.json")


if __name__ == "__main__":
    main()
