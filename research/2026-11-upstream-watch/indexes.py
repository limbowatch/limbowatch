# /// script
# requires-python = ">=3.12"
# dependencies = ["pyyaml>=6"]
# ///
"""Phase 6, step 0: which upstream repo does each vcpkg port, Bazel Central Registry module and conan-center recipe
build from?

Reads sparse, shallow clones in .cache/ (made by `clone.sh`): microsoft/vcpkg (ports/*/portfile.cmake and
vcpkg.json), bazelbuild/bazel-central-registry (modules/*/metadata.json, */source.json), conan-io/conan-center-index
(recipes/*/*/conandata.yml). Writes .cache/indexes.json: {index: {name: {"repo": "host/owner/repo" | None,
"how": ..., "versions": [...], "ref": tag template}}}. Run: uv run research/2026-11-upstream-watch/indexes.py
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import yaml

HERE = Path(__file__).parent
CACHE = HERE / ".cache"

# github.com/o/r, gitlab.com/o/r(/sub), codeberg, bitbucket, sourceforge are kept with their host
_URL = re.compile(r"https?://(?:www\.)?(github\.com|gitlab\.com|codeberg\.org|bitbucket\.org)/([\w.-]+)/([\w.-]+)", re.I)
_VAR = re.compile(r"\$\{[^}]+\}")


def norm(host: str, owner: str, repo: str) -> str:
    repo = re.sub(r"\.git$", "", repo)
    return f"{host.lower()}/{owner.lower()}/{repo.lower()}"


def _arg(block: str, key: str) -> str | None:
    m = re.search(rf"\b{key}\s+(\"[^\"]*\"|\S+)", block)
    return m.group(1).strip('"') if m else None


def vcpkg() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for port in sorted((CACHE / "vcpkg/ports").iterdir()):
        pf, man = port / "portfile.cmake", port / "vcpkg.json"
        if not pf.exists():
            continue
        text = pf.read_text(errors="replace")
        meta = json.loads(man.read_text()) if man.exists() else {}
        version = next((meta[k] for k in ("version", "version-semver", "version-date", "version-string") if k in meta), None)
        entry: dict = {"repo": None, "how": None, "versions": [version] if version else [], "ref": None}
        if m := re.search(r"vcpkg_from_github\s*\((.*?)\n\s*\)", text, re.S):
            repo, ref = _arg(m.group(1), "REPO"), _arg(m.group(1), "REF")
            if repo and not _VAR.search(repo) and "/" in repo:
                o, r = repo.split("/", 1)
                entry |= {"repo": norm("github.com", o, r), "how": "vcpkg_from_github", "ref": ref}
        elif m := re.search(r"vcpkg_from_gitlab\s*\((.*?)\n\s*\)", text, re.S):
            base, repo = _arg(m.group(1), "GITLAB_URL") or "", _arg(m.group(1), "REPO") or ""
            if "gitlab.com" in base and "/" in repo and not _VAR.search(repo):
                o, r = repo.split("/", 1)
                entry |= {"repo": norm("gitlab.com", o, r), "how": "vcpkg_from_gitlab", "ref": _arg(m.group(1), "REF")}
        elif m := re.search(r"vcpkg_from_git\s*\((.*?)\n\s*\)", text, re.S):
            url = _arg(m.group(1), "URL") or ""
            if u := _URL.search(url):
                entry |= {"repo": norm(*u.groups()), "how": "vcpkg_from_git", "ref": _arg(m.group(1), "REF")}
        if entry["repo"] is None:
            if u := _URL.search(text):  # vcpkg_download_distfile from a GitHub release or archive
                entry |= {"repo": norm(*u.groups()), "how": "download url"}
            elif "set(VCPKG_POLICY_EMPTY_PACKAGE enabled)" in text or not re.search(r"vcpkg_(from|download)", text):
                entry["how"] = "no source (meta-port)"
            else:
                entry["how"] = "other host"
        out[port.name] = entry
    return out


def bcr() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for mod in sorted((CACHE / "bcr/modules").iterdir()):
        mf = mod / "metadata.json"
        if not mf.exists():
            continue
        meta = json.loads(mf.read_text())
        repo, how = None, "no repository field"
        for r in meta.get("repository") or []:
            if r.startswith("github:"):
                o, n = r[len("github:"):].split("/", 1)
                repo, how = norm("github.com", o, n), "repository github:"
                break
            if r.startswith("gitlab:"):
                o, n = r[len("gitlab:"):].split("/", 1)
                repo, how = norm("gitlab.com", o, n), "repository gitlab:"
                break
            if u := _URL.search(r):
                repo, how = norm(*u.groups()), "repository url"
                break
        else:
            if meta.get("repository"):
                how = "repository elsewhere"
        if repo is None:  # fall back to the newest version's source.json archive url
            for v in reversed(meta.get("versions") or []):
                sj = mod / v / "source.json"
                if sj.exists() and (u := _URL.search(json.loads(sj.read_text()).get("url", "") or "")):
                    repo, how = norm(*u.groups()), "source.json url"
                    break
        out[mod.name] = {"repo": repo, "how": how, "versions": meta.get("versions") or [], "ref": None}
    return out


def conan() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for rec in sorted((CACHE / "cci/recipes").iterdir()):
        repos: Counter[str] = Counter()
        versions: list[str] = []
        for cd in rec.glob("*/conandata.yml"):
            try:
                data = yaml.safe_load(cd.read_text()) or {}
            except yaml.YAMLError:
                continue
            for ver, src in (data.get("sources") or {}).items():
                versions.append(str(ver))
                for u in _URL.finditer(json.dumps(src)):
                    if u.group(2).lower() != "conan-io":
                        repos[norm(*u.groups())] += 1
        repo = repos.most_common(1)[0][0] if repos else None
        out[rec.name] = {"repo": repo, "how": "conandata url" if repo else "no forge url", "versions": versions, "ref": None}
    return out


def main() -> None:
    idx = {"vcpkg": vcpkg(), "bcr": bcr(), "conan": conan()}
    (CACHE / "indexes.json").write_text(json.dumps(idx, indent=1, sort_keys=True))
    for name, d in idx.items():
        hows = Counter(e["how"] for e in d.values())
        repos = {e["repo"] for e in d.values() if e["repo"]}
        print(f"{name}: {len(d)} entries, {sum(1 for e in d.values() if e['repo'])} mapped to {len(repos)} repos;",
              dict(hows.most_common()))
    allr = {e["repo"] for d in idx.values() for e in d.values() if e["repo"]}
    print("union of repos:", len(allr), "github:", sum(r.startswith("github.com/") for r in allr))


if __name__ == "__main__":
    main()
