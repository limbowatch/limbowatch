# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Phase 6, step 0: how do real C/C++ projects take in their dependencies, and could the watcher name the upstream
and the version or commit of each?

Sample (GitHub search, 2026-11-10): the most-starred C and C++ repos, plus a seeded random sample of mid-sized ones
(200-2,000 stars, pushed in 2026). Each is cloned shallow and blob-less with a sparse checkout of only the files that
declare dependencies. Detected:
  - git submodules: .gitmodules URL + the gitlink commit from the tree (no submodule fetch)
  - CMake: FetchContent_Declare / ExternalProject_Add (GIT_REPOSITORY + GIT_TAG, or URL), CPMAddPackage
  - vcpkg.json, conanfile.txt / conanfile.py / conan.lock, MODULE.bazel (bazel_dep), WORKSPACE (http_archive,
    git_repository), meson subprojects/*.wrap
  - vendored copies: a directory under third_party/, 3rdparty/, thirdparty/, vendor/, external/, extern/, deps/ or
    contrib/ that holds a LICENSE or COPYING file
Each dependency is classed by what the watcher would know: upstream repo and ref (tag/commit/version), repo only,
a package name (resolvable through the vcpkg/BCR/conan indexes), or nothing.

Run from the repo root:  uv run research/2026-11-upstream-watch/survey.py [--top 25] [--mid 35]
Needs `gh` (authenticated; token never printed). Writes survey.json (counts and per-project summaries of public
build files, no advisory text); clones stay in .cache/projects/ (gitignored).
"""

from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).parent
CACHE = HERE / ".cache"
PROJ = CACHE / "projects"
SPARSE = [
    ".gitmodules", "CMakeLists.txt", "**/CMakeLists.txt", "*.cmake", "**/*.cmake", "vcpkg.json", "**/vcpkg.json",
    "vcpkg-configuration.json", "conanfile.txt", "**/conanfile.txt", "conanfile.py", "**/conanfile.py", "conan.lock",
    "**/conan.lock", "MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel", "*.bzl", "**/*.bzl", "subprojects/*.wrap",
]  # fmt: skip
VENDOR_DIRS = {"third_party", "third-party", "3rdparty", "thirdparty", "vendor", "external", "extern", "deps", "contrib"}
FORGE = re.compile(r"(?:https?://|git@|git://)(?:www\.)?(github\.com|gitlab\.com|codeberg\.org|bitbucket\.org)[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?=[/\"'\s#)]|$)", re.I)
SHA = re.compile(r"^[0-9a-f]{7,40}$")


def gh(*args: str) -> str:
    return subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True).stdout


def sample(top: int, mid: int) -> list[str]:
    f = CACHE / "sample.json"
    if f.exists():
        return json.loads(f.read_text())
    repos: list[str] = []
    for lang, n in (("C++", top), ("C", top)):
        q = f"language:{lang} stars:>1000 fork:false archived:false"
        repos += gh("-X", "GET", "search/repositories", "-f", f"q={q}", "-f", "sort=stars", "-f", f"per_page={n}",
                    "-q", ".items[].full_name").split()
    rnd = random.Random(20261110)
    pool: list[str] = []
    for lang in ("C++", "C"):
        q = f"language:{lang} stars:200..2000 pushed:>2026-01-01 fork:false archived:false"
        for page in rnd.sample(range(1, 11), 3):
            pool += gh("-X", "GET", "search/repositories", "-f", f"q={q}", "-f", "per_page=100", "-f", f"page={page}",
                       "-q", ".items[].full_name").split()
    repos += rnd.sample(sorted(set(pool) - set(repos)), mid)
    repos = list(dict.fromkeys(r.lower() for r in repos))
    f.write_text(json.dumps(repos, indent=1))
    return repos


def clone(repo: str) -> Path | None:
    d = PROJ / repo.replace("/", "__")
    if (d / ".git").exists():
        return d
    r = subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout",
                        f"https://github.com/{repo}.git", str(d)], capture_output=True, env={"GIT_TERMINAL_PROMPT": "0",
                        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"})  # fmt: skip
    if r.returncode:
        return None
    subprocess.run(["git", "-C", str(d), "sparse-checkout", "init", "--no-cone"], check=True, capture_output=True)
    (d / ".git/info/sparse-checkout").write_text("\n".join(SPARSE) + "\n")
    subprocess.run(["git", "-C", str(d), "checkout", "-q"], check=True, capture_output=True)
    return d


def forge(url: str) -> str | None:
    m = FORGE.search(url)
    return f"{m.group(1).lower()}/{m.group(2).lower()}/{m.group(3).lower().removesuffix('.git')}" if m else None


def dep(method: str, repo: str | None, ref: str | None, name: str | None = None, path: str = "") -> dict:
    if repo and ref:
        know = "repo+commit" if SHA.match(ref) else "repo+ref"
    elif repo:
        know = "repo only"
    elif name:
        know = "name (index)"
    else:
        know = "nothing"
    return {"method": method, "repo": repo, "ref": ref, "name": name, "know": know, "path": path}


def _blocks(text: str, fn: str) -> list[str]:
    out, i = [], 0
    while (m := re.compile(rf"(?<![\w.]){fn}\s*\(", re.I).search(text, i)) is not None:
        depth, j = 1, m.end()
        while j < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            j += 1
        out.append(text[m.end(): j - 1])
        i = j
    return out


def _kw(block: str, key: str) -> str | None:
    m = re.search(rf"\b{key}\s+(\"[^\"]*\"|[^\s)]+)", block)
    return m.group(1).strip('"') if m else None


def detect(d: Path) -> list[dict]:
    deps: list[dict] = []
    files = [p for p in d.rglob("*") if p.is_file() and ".git" not in p.parts]
    tree = subprocess.run(["git", "-C", str(d), "ls-tree", "-r", "-d", "HEAD"], capture_output=True, text=True).stdout
    gitlinks = {ln.split("\t")[1]: ln.split()[2] for ln in subprocess.run(
        ["git", "-C", str(d), "ls-tree", "-r", "HEAD"], capture_output=True, text=True).stdout.splitlines()
        if ln.startswith("160000")}  # fmt: skip
    gm = d / ".gitmodules"
    if gm.exists():
        cur: dict[str, str] = {}
        for ln in gm.read_text(errors="replace").splitlines() + ["[end]"]:
            if ln.strip().startswith("["):
                if cur.get("path"):
                    deps.append(dep("submodule", forge(cur.get("url", "")), gitlinks.get(cur["path"]),
                                    path=cur["path"]))  # fmt: skip
                cur = {}
            elif "=" in ln:
                k, v = ln.split("=", 1)
                cur[k.strip()] = v.strip()
    for p in files:
        rel = str(p.relative_to(d))
        if p.name == "CMakeLists.txt" or p.suffix == ".cmake":
            t = p.read_text(errors="replace")
            for fn in ("FetchContent_Declare", "ExternalProject_Add"):
                for b in _blocks(t, fn):
                    url = _kw(b, "GIT_REPOSITORY") or _kw(b, "URL") or ""
                    ref = _kw(b, "GIT_TAG")
                    if not ref and (m := re.search(r"/archive/(?:refs/tags/)?([^/\s\"]+?)\.(?:tar\.gz|zip)", url)):
                        ref = m.group(1)
                    if "${" in (ref or ""):
                        ref = None
                    deps.append(dep("cmake " + fn, forge(url), ref, path=rel))
            for b in _blocks(t, "CPMAddPackage"):
                if m := re.match(r'\s*"gh:([\w.-]+)/([\w.-]+)(?:@([^"#]+))?', b):
                    deps.append(dep("cmake CPM", f"github.com/{m[1].lower()}/{m[2].lower()}", m[3], path=rel))
                else:
                    url = _kw(b, "GITHUB_REPOSITORY")
                    repo = f"github.com/{url.lower()}" if url else forge(_kw(b, "GIT_REPOSITORY") or _kw(b, "URL") or "")
                    ref = _kw(b, "GIT_TAG") or _kw(b, "VERSION")
                    deps.append(dep("cmake CPM", repo, None if "${" in (ref or "") else ref, path=rel))
        elif p.name == "vcpkg.json":
            try:
                m = json.loads(p.read_text())
            except ValueError:
                continue
            base = m.get("builtin-baseline")
            for x in m.get("dependencies") or []:
                n = x if isinstance(x, str) else x.get("name")
                deps.append(dep("vcpkg.json", None, None, name=n, path=rel) | {"baseline": bool(base)})
        elif p.name == "conanfile.txt":
            sec = None
            for ln in p.read_text(errors="replace").splitlines():
                if ln.strip().startswith("["):
                    sec = ln.strip()
                elif sec in ("[requires]", "[tool_requires]", "[build_requires]") and "/" in ln:
                    n, v = ln.strip().split("/", 1)
                    deps.append(dep("conan", None, None, name=n, path=rel) | {"version": v.split("@")[0]})
        elif p.name == "conanfile.py":
            for m in re.finditer(r"""requires\(\s*["']([\w.+-]+)/([^"'@#\s]+)""", p.read_text(errors="replace")):
                deps.append(dep("conan", None, None, name=m[1], path=rel) | {"version": m[2]})
            for m in re.finditer(r"""requires\s*=\s*\(?([^)\n]+)""", p.read_text(errors="replace")):
                for n, v in re.findall(r"""["']([\w.+-]+)/([^"'@#\s]+)""", m[1]):
                    deps.append(dep("conan", None, None, name=n, path=rel) | {"version": v})
        elif p.name == "MODULE.bazel":
            for m in re.finditer(r"bazel_dep\(\s*name\s*=\s*\"([^\"]+)\"\s*,\s*version\s*=\s*\"([^\"]+)\"", p.read_text()):
                deps.append(dep("bazel_dep", None, None, name=m[1], path=rel) | {"version": m[2]})
        elif p.name.startswith("WORKSPACE") or p.suffix == ".bzl":
            t = p.read_text(errors="replace")
            for fn in (r"\w*http_archive", r"\w*git_repository"):  # also wrappers such as tf_http_archive
                for b in _blocks(t, fn):
                    urls = re.findall(r"\"((?:https?|git)://[^\"]+)\"", b)
                    url = next((u for u in urls if forge(u)), urls[0] if urls else "")
                    ref = (re.search(r"(?:commit|tag)\s*=\s*\"([^\"]+)\"", b) or [None, None])[1]
                    if not ref and (m := re.search(r"/archive/(?:refs/tags/)?([^/\"]+?)\.(?:tar\.gz|zip)", url)):
                        ref = m.group(1)
                    deps.append(dep("bazel " + fn.removeprefix(r"\w*"), forge(url), ref, path=rel))
        elif p.suffix == ".wrap" and p.parent.name == "subprojects":
            t = p.read_text(errors="replace")
            url = (re.search(r"^(?:url|source_url)\s*=\s*(\S+)", t, re.M) or [None, ""])[1]
            ref = (re.search(r"^revision\s*=\s*(\S+)", t, re.M) or [None, None])[1]
            if ref == "HEAD":
                ref = None
            deps.append(dep("meson wrap", forge(url), ref, name=p.stem, path=str(p.relative_to(d))))
    # vendored: a dir under a vendor root that has a license file, from the full tree (no blobs needed)
    names = subprocess.run(["git", "-C", str(d), "ls-tree", "-r", "--name-only", "HEAD"], capture_output=True,
                           text=True).stdout.splitlines()  # fmt: skip
    seen = set()
    sub_paths = {x["path"] for x in deps if x["method"] == "submodule"}
    for n in names:
        parts = n.split("/")
        for i, part in enumerate(parts[:-2]):
            if part.lower() in VENDOR_DIRS and re.match(r"(?i)(licen[cs]e|copying)", parts[-1]) and len(parts) == i + 3:
                lib = "/".join(parts[: i + 2])
                if lib not in seen and lib not in sub_paths:
                    seen.add(lib)
                    deps.append(dep("vendored", None, None, name=parts[i + 1], path=lib))
    del tree
    return deps


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--mid", type=int, default=35)
    a = ap.parse_args()
    PROJ.mkdir(parents=True, exist_ok=True)
    repos = sample(a.top, a.mid)
    with ThreadPoolExecutor(8) as ex:
        dirs = dict(zip(repos, ex.map(clone, repos)))
    idx = json.loads((CACHE / "indexes.json").read_text())
    limbo: Counter[str] = Counter()
    with zipfile.ZipFile(CACHE / "feed-all.zip") as z:
        for n in z.namelist():
            limbo["github.com/" + json.loads(z.read(n))["database_specific"]["limbowatch"]["repository"].lower()] += 1
    per_project, methods, know, by_method_know = [], Counter(), Counter(), defaultdict(Counter)
    projects_with = Counter()
    hits: Counter[str] = Counter()
    for repo, d in dirs.items():
        if d is None:
            per_project.append({"repo": repo, "error": "clone failed"})
            continue
        deps = detect(d)
        for x in deps:  # name → upstream through the indexes
            if x["repo"] is None and x["name"]:
                src = {"vcpkg.json": "vcpkg", "conan": "conan", "bazel_dep": "bcr", "meson wrap": None}.get(x["method"])
                e = idx.get(src, {}).get(x["name"]) if src else None
                if e and e["repo"]:
                    x["repo_via_index"] = e["repo"]
            up = x.get("repo") or x.get("repo_via_index")
            x["in_limbo_feed"] = bool(up and limbo.get(up))
            methods[x["method"]] += 1
            know[x["know"]] += 1
            by_method_know[x["method"]][x["know"] + (" → repo via index" if x.get("repo_via_index") else "")] += 1
            if x["in_limbo_feed"]:
                hits[up] += 1
        for m in {x["method"] for x in deps}:
            projects_with[m] += 1
        if not deps:
            projects_with["none detected"] += 1
        per_project.append({"repo": repo, "deps": len(deps), "methods": dict(Counter(x["method"] for x in deps)),
                            "with_limbo_upstream": sorted({x.get("repo") or x.get("repo_via_index") for x in deps
                                                           if x["in_limbo_feed"]})})  # fmt: skip
    summary = {
        "projects": len(repos), "cloned": sum(1 for d in dirs.values() if d),
        "projects_by_method": dict(projects_with.most_common()),
        "dependencies_by_method": dict(methods.most_common()),
        "dependencies_by_what_is_known": dict(know.most_common()),
        "by_method_and_known": {m: dict(c.most_common()) for m, c in by_method_know.items()},
        "projects_with_an_upstream_in_the_limbo_feed": sum(1 for p in per_project if p.get("with_limbo_upstream")),
        "upstreams_in_the_limbo_feed": dict(hits.most_common()),
        "per_project": per_project,
    }
    (HERE / "survey.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "per_project"}, indent=1))


if __name__ == "__main__":
    main()
