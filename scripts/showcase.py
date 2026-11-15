"""List the dependencies of the popular projects the home page counts (FINDINGS F-203).

    PATH=<dir with osv-scanner 2.7.1>:$PATH uv run --frozen --package limbowatch python scripts/showcase.py \
        --projects tracker/showcase/projects.txt --out showcase.json

For each project: a shallow, blob-less clone of only its dependency files (lockfiles and the manifests next to them;
test fixtures and vendored copies left out), then OSV-Scanner's inventory, as `limbowatch scan` reads it. The output
is the dependencies, not findings: the site build matches them against the feed it publishes, so the numbers agree
with that feed. Network: git clones from GitHub. A project that can't be cloned or read is recorded with its error,
never dropped.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from limbowatch.inventory import osv_scanner

LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "uv.lock",
             "poetry.lock", "Pipfile.lock", "pdm.lock", "pylock.toml", "requirements*.txt", "go.mod", "go.sum",
             "Cargo.lock", "composer.lock", "Gemfile.lock", "package.json", "pyproject.toml"]  # fmt: skip
EXCLUDE_DIRS = ["testdata", "fixtures", "__fixtures__", "test-fixtures", "node_modules", "vendor"]
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def projects(path: Path) -> list[str]:
    out = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if not REPO.fullmatch(line):
            raise ValueError(f"not owner/name: {line!r}")
        out.append(line)
    if len(set(out)) != len(out):
        raise ValueError("a project is listed twice")
    return out


def _git(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=600, check=False)


def clone(repo: str, dest: Path) -> str:
    """Only the dependency files, at the default branch's head. Returns the commit."""
    for attempt in range(3):
        shutil.rmtree(dest, ignore_errors=True)
        r = _git("clone", "--quiet", "--depth", "1", "--filter=blob:none", "--no-checkout",
                 f"https://github.com/{repo}.git", str(dest))  # fmt: skip
        if r.returncode == 0:
            patterns = [f"**/{p}" for p in LOCKFILES] + [f"!**/{d}/**" for d in EXCLUDE_DIRS]
            _git("sparse-checkout", "set", "--no-cone", *patterns, cwd=dest)
            if _git("checkout", "--quiet", cwd=dest).returncode == 0:
                return _git("rev-parse", "HEAD", cwd=dest).stdout.strip()
        time.sleep(15 * (attempt + 1))
    raise RuntimeError(f"clone failed: {r.stderr.strip()[-200:]}")


def one(repo: str, work: Path, binary: str) -> dict[str, Any]:
    dest = work / repo.replace("/", "__")
    try:
        sha = clone(repo, dest)
        inv = osv_scanner.run(dest, binary, resolve_maven=False)
    except Exception as e:  # recorded, not dropped: the page says which projects couldn't be read
        return {"repo": repo, "error": f"{type(e).__name__}: {e}"[:300]}
    finally:
        shutil.rmtree(dest, ignore_errors=True)
    seen: dict[tuple[str, str, str], str] = {}
    for d in inv.dependencies:
        seen.setdefault((d.ecosystem, d.name, d.version), d.source)
    return {
        "repo": repo,
        "commit": sha,
        "files": len(inv.sources),
        "unresolved": len(inv.unresolved),
        "dependencies": sorted([eco, name, ver, src] for (eco, name, ver), src in seen.items()),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--projects", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--osv-scanner", default="osv-scanner")
    ap.add_argument("--jobs", type=int, default=6)
    a = ap.parse_args(argv)
    version = osv_scanner.version(a.osv_scanner)
    if version is None:
        print(f"{a.osv_scanner} not found", file=sys.stderr)
        return 2
    names = projects(a.projects)
    started = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    # processes, not threads: reading a large lockfile's inventory is CPU-bound Python
    with tempfile.TemporaryDirectory(prefix="showcase-") as tmp, ProcessPoolExecutor(a.jobs) as pool:
        results = list(pool.map(partial(one, work=Path(tmp), binary=a.osv_scanner), names))
    failed = [r["repo"] for r in results if "error" in r]
    a.out.write_text(json.dumps({"scanned_at": started, "tool": f"osv-scanner {version}", "projects": results},
                                separators=(",", ":")))  # fmt: skip
    print(f"showcase: {len(names) - len(failed)} of {len(names)} projects read, "
          f"{sum(len(r.get('dependencies', [])) for r in results):,} dependencies"
          + (f"; failed: {', '.join(failed)}" if failed else ""))  # fmt: skip
    return 1 if len(failed) > len(names) // 5 else 0  # a few failures are reported; many mean something's broken


if __name__ == "__main__":
    sys.exit(main())
