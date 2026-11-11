# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Seed list of C/C++ upstreams: the GitHub repos that vcpkg ports, Bazel Central Registry modules and ConanCenter
recipes build from (PHASE0_PLAN §13.18 step 5, FINDINGS F-136).

Reads sparse, shallow clones of microsoft/vcpkg (MIT), bazelbuild/bazel-central-registry (Apache-2.0) and
conan-io/conan-center-index (MIT), made under .cache/ here, with the watcher's own parsers
(limbowatch.inventory.upstream), so the seed and the watcher map names the same way. Writes cpp-upstreams.txt.

Run from the repo root:  uv run python tracker/seeds/make_cpp_upstreams.py
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from limbowatch.inventory.upstream import locate, portfile_source

HERE = Path(__file__).parent
CACHE = HERE / ".cache"
NOT_UPSTREAM = {"microsoft/vcpkg", "conan-io/conan-center-index", "bazelbuild/bazel-central-registry"}


def clone(repo: str, d: str, *patterns: str) -> str:
    path = CACHE / d
    if not path.exists():
        subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout",
                        f"https://github.com/{repo}.git", str(path)], check=True)  # fmt: skip
        subprocess.run(["git", "-C", str(path), "sparse-checkout", "init", "--no-cone"], check=True)
        (path / ".git/info/sparse-checkout").write_text("\n".join(patterns) + "\n")
        subprocess.run(["git", "-C", str(path), "checkout", "-q"], check=True)
    else:
        subprocess.run(["git", "-C", str(path), "pull", "-q", "--depth", "1"], check=True)
    return subprocess.run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()  # fmt: skip


def github(url: str) -> str | None:
    loc = locate(url)
    return loc.repo if loc.host == "github.com" and loc.repo and loc.repo.count("/") == 1 else None


def vcpkg() -> set[str]:
    out = set()
    for pf in (CACHE / "vcpkg/ports").glob("*/portfile.cmake"):
        loc, _, _ = portfile_source(pf.read_text(errors="replace"), "0")
        if loc.host == "github.com" and loc.repo:
            out.add(loc.repo)
    return out


def bcr() -> set[str]:
    out = set()
    for mf in (CACHE / "bcr/modules").glob("*/metadata.json"):
        meta = json.loads(mf.read_text())
        for r in meta.get("repository") or []:
            if r.startswith("github:"):
                out.add(r.removeprefix("github:").lower())
                break
            if repo := github(r):
                out.add(repo)
                break
    return out


def conan() -> set[str]:
    out = set()
    for cd in (CACHE / "cci/recipes").glob("*/*/conandata.yml"):
        text = cd.read_text(errors="replace")
        block = text.split("\nsources:", 1)[-1] if "sources:" in text else ""
        repos = {r for u in re.findall(r"https?://[^\s\"']+", block) if (r := github(u))}
        if len(repos) == 1:  # one upstream for the recipe; several (vendored sub-sources) aren't guessed between
            out |= repos
    return out


def main() -> None:
    CACHE.mkdir(exist_ok=True)
    heads = {
        "vcpkg": clone("microsoft/vcpkg", "vcpkg", "/ports/*/portfile.cmake", "/ports/*/vcpkg.json"),
        "bcr": clone("bazelbuild/bazel-central-registry", "bcr", "/modules/*/metadata.json"),
        "cci": clone("conan-io/conan-center-index", "cci", "/recipes/*/*/conandata.yml"),
    }
    sets = {"vcpkg": vcpkg(), "bcr": bcr(), "conan": conan()}
    repos = sorted(set().union(*sets.values()) - NOT_UPSTREAM)
    header = (
        f"# C/C++ upstreams: GitHub repos that vcpkg ports ({len(sets['vcpkg'])}), Bazel Central Registry modules "
        f"({len(sets['bcr'])}) and ConanCenter recipes ({len(sets['conan'])}) build from.\n"
        f"# Generated {datetime.now(UTC):%Y-%m-%d} by make_cpp_upstreams.py from microsoft/vcpkg {heads['vcpkg']}, "
        f"bazelbuild/bazel-central-registry {heads['bcr']}, conan-io/conan-center-index {heads['cci']}.\n"
    )
    (HERE / "cpp-upstreams.txt").write_text(header + "\n".join(repos) + "\n")
    print(header + f"{len(repos)} repos")


if __name__ == "__main__":
    main()
