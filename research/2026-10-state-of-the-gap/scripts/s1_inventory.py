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
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from common import CACHE, DATA, SNAPSHOT, log, save_json

PROJECTS = ["go-gitea/gitea", "kubernetes/kubernetes", "n8n-io/n8n", "open-webui/open-webui", "langchain-ai/langchain"]
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
                env={**__import__("os").environ, "GOBIN": str(bindir)})
        if r.returncode != 0:
            raise SystemExit(f"go install failed: {r.stderr[-500:]}")
    return exe


def sparse_clone(slug: str) -> tuple[Path, str]:
    dest = CACHE / "repos" / slug.replace("/", "__")
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = run(["git", "clone", "--quiet", "--depth", "1", "--filter=blob:none", "--no-checkout",
             f"https://github.com/{slug}.git", str(dest)])
    if r.returncode != 0:
        raise SystemExit(f"clone {slug} failed: {r.stderr[-300:]}")
    run(["git", "-C", str(dest), "sparse-checkout", "set", "--no-cone", *[f"**/{p}" for p in LOCKFILES]], check=True)
    run(["git", "-C", str(dest), "checkout", "--quiet"], check=True)
    sha = run(["git", "-C", str(dest), "rev-parse", "HEAD"], check=True).stdout.strip()
    removed = 0
    for f in list(dest.rglob("*")):
        if f.is_file() and ".git" not in f.parts and EXCLUDE_DIRS & set(f.relative_to(dest).parts[:-1]):
            f.unlink()
            removed += 1
    shutil.rmtree(dest / ".git")  # osv-scanner only needs the files; also avoids git-based scanning
    log(f"  {slug}@{sha[:10]}: excluded {removed} fixture/vendor lockfiles")
    return dest, sha


def scan(exe: Path, src: Path, out: Path) -> dict:
    # Explicit -L per lockfile: `scan source --recursive DIR` silently finds nothing when DIR
    # sits under a hidden directory such as .cache (FINDINGS F-040).
    args: list[str] = []
    for f in sorted(p for p in src.rglob("*") if p.is_file()):
        is_req = f.name.startswith("requirements") and f.name.endswith(".txt")
        args += ["-L", f"requirements.txt:{f}" if is_req and f.name != "requirements.txt" else str(f)]
    if out.exists():
        out.unlink()
    r = run([str(exe), "scan", "source", "--all-packages", "--format", "json", "--output-file", str(out), *args])
    if r.returncode not in (0, 1) or not out.exists():  # 1 = vulnerabilities found
        raise SystemExit(f"osv-scanner failed ({r.returncode}): {r.stderr[-800:]}")
    return json.loads(out.read_text())


def main() -> None:
    exe = osv_scanner()
    inventory: dict[str, dict] = {}
    for slug in PROJECTS:
        log(f"inventory {slug}")
        src, sha = sparse_clone(slug)
        res = scan(exe, src, CACHE / f"osv-{slug.replace('/', '__')}.json")
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
        inventory[slug] = {"commit": sha, "lockfiles": dict(lockfiles), "packages": pkgs}
        eco = Counter(p["ecosystem"] for p in pkgs)
        nover = sum(1 for p in pkgs if not p["version"])
        log(f"  {len(lockfiles)} lockfiles, {len(pkgs)} package entries, {nover} without version, {dict(eco)}")
    save_json(DATA / SNAPSHOT / "inventory.json", {"snapshot": SNAPSHOT, "osv_scanner": OSV_SCANNER_VERSION, "projects": inventory})
    log("wrote inventory.json")


if __name__ == "__main__":
    main()
