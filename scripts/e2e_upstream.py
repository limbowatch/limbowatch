"""End to end against the real world: `limbowatch scan` on a project that takes FreeRDP as a git submodule, ImageMagick
through CMake FetchContent and FreeRDP again as a vcpkg port, at old and at current releases (FINDINGS F-138 to F-142).

Not part of the test suite: it needs the network (GitHub for git and tags, limbo.watch, OSV, raw.githubusercontent.com)
and OSV-Scanner on PATH. Run it before a release that touches upstream sources:

    PATH=research/2026-10-state-of-the-gap/.cache/bin:$PATH uv run python scripts/e2e_upstream.py

Checks: the old pins are affected by many advisories in limbo (certain, not just possible); the current releases by
none for certain; the vcpkg port maps to FreeRDP's repo through the baseline; every report format is written.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_AUTHOR_NAME": "e2e", "GIT_AUTHOR_EMAIL": "e2e@example.com",
           "GIT_COMMITTER_NAME": "e2e", "GIT_COMMITTER_EMAIL": "e2e@example.com"}  # fmt: skip
VCPKG_BASELINE = "e54ef0fcc9a82033a61e51002552a910a5d57282"  # microsoft/vcpkg, 2026-11-10


def sh(*cmd: str, cwd: Path | None = None) -> str:
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True, env=GIT_ENV).stdout


def commit_of(repo: str, tag: str) -> str:
    out = sh("git", "ls-remote", f"https://github.com/{repo}.git", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
    lines = dict(reversed(ln.split("\t")) for ln in out.splitlines())
    return lines.get(f"refs/tags/{tag}^{{}}") or lines[f"refs/tags/{tag}"]


def project(root: Path, freerdp: str, imagemagick: str) -> Path:
    p = root / f"app-{freerdp}"
    p.mkdir()
    sh("git", "init", "-q", "-b", "main", cwd=p)
    (p / ".gitmodules").write_text('[submodule "freerdp"]\n\tpath = third_party/freerdp\n'
                                   "\turl = https://github.com/FreeRDP/FreeRDP.git\n")  # fmt: skip
    sh("git", "update-index", "--add", "--cacheinfo", f"160000,{commit_of('FreeRDP/FreeRDP', freerdp)},third_party/freerdp",
       cwd=p)  # fmt: skip
    (p / "CMakeLists.txt").write_text("include(FetchContent)\nFetchContent_Declare(im GIT_REPOSITORY "
                                      f"https://github.com/ImageMagick/ImageMagick.git GIT_TAG {imagemagick})\n")  # fmt: skip
    (p / "vcpkg.json").write_text(json.dumps({"name": "app", "builtin-baseline": VCPKG_BASELINE,
                                              "dependencies": ["freerdp"]}))  # fmt: skip
    sh("git", "add", ".gitmodules", "CMakeLists.txt", "vcpkg.json", cwd=p)  # not -A: it would stage the gitlink's removal
    sh("git", "commit", "-qm", "app", cwd=p)
    return p


def scan(p: Path, out: Path) -> dict:
    cmd = ["uv", "run", "limbowatch"]
    outputs = [x for f in ("json", "sarif", "markdown", "codequality", "junit", "csv", "cyclonedx", "html")
               for x in ("-o", f"{f}={out}/{p.name}.{f}")]  # fmt: skip
    r = subprocess.run([*cmd, "scan", str(p), "--fail-on", "none", "--cache", str(out / "cache"), *outputs],
                       cwd=ROOT, capture_output=True, text=True)  # fmt: skip
    if r.returncode != 0:
        sys.exit(f"scan failed ({r.returncode}):\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
    for f in ("sarif", "markdown", "codequality", "junit", "csv", "cyclonedx", "html"):
        if not (out / f"{p.name}.{f}").stat().st_size:
            sys.exit(f"empty {f} report")
    return json.loads((out / f"{p.name}.json").read_text())


def check(cond: bool, what: str, detail: object = "") -> None:
    print(("ok   " if cond else "FAIL ") + what + (f"  ({detail})" if detail != "" else ""))
    if not cond:
        raise SystemExit(1)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root, out = Path(tmp), Path(tmp) / "out"
        out.mkdir()
        old = scan(project(root, "3.10.0", "7.1.1-30"), out)
        tally = Counter((f["dependency"]["name"], f["affected"]) for f in old["findings"])
        print(dict(tally))
        check(tally[("github.com/freerdp/freerdp", True)] >= 200, "FreeRDP 3.10.0 is affected by 200+ advisories")
        check(tally[("github.com/imagemagick/imagemagick", True)] >= 100, "ImageMagick 7.1.1-30 by 100+")
        vcpkg = [u for u in old["unresolved"] if u["ecosystem"] == "vcpkg port"]
        check(old["summary"]["upstreams"] >= 3 and not vcpkg, "the vcpkg port maps to a repo and tag", vcpkg)
        check(not old["unresolved"], "every upstream source is checked", old["unresolved"])
        new = scan(project(root, latest("FreeRDP/FreeRDP", r"3\.\d+\.\d+"), latest("ImageMagick/ImageMagick",
                                                                                 r"7\.1\.\d+-\d+")), out)  # fmt: skip
        certain = [f for f in new["findings"] if f["affected"] is True
                   and f["dependency"]["note"].startswith(("git submodule", "CMake"))]  # fmt: skip
        check(not certain, "the current releases are certainly affected by none", [f["ghsa_id"] for f in certain])
    print("e2e upstream passed")


def latest(repo: str, pattern: str) -> str:
    import re

    tags = [ln.split("refs/tags/")[1] for ln in sh("git", "ls-remote", "--tags", "--refs",
                                                     f"https://github.com/{repo}.git").splitlines()]  # fmt: skip
    from limbowatch.versions import UpstreamVersion

    return max((t for t in tags if re.fullmatch(pattern, t)), key=UpstreamVersion)


if __name__ == "__main__":
    main()
