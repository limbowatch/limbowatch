"""Upstream source dependencies: code a project takes in by git or archive instead of from a package registry
(PHASE0_PLAN §6 Tier 3, §13.18; FINDINGS F-135, F-136).

OSV-Scanner, run offline, reads none of these (F-135). Detected here, from the project's own files:

- git submodules: `.gitmodules`, with each submodule's commit from the git index (the submodule needn't be fetched)
- CMake: `FetchContent_Declare`, `ExternalProject_Add`, `CPMAddPackage` (and `CPMFindPackage`, `CPMDeclarePackage`),
  with variables from the project's own `set()` calls substituted
- Bazel: `bazel_dep` in MODULE.bazel (and its overrides), `http_archive` / `git_repository` and wrappers of them
  (`tf_http_archive`, `maybe(http_archive, ...)`) in MODULE.bazel, WORKSPACE and .bzl files
- vcpkg: `vcpkg.json` dependencies, overrides and baseline; Conan: `conan.lock`, else `conanfile.txt` / `.py`
- meson: `subprojects/*.wrap`
- vendored copies: a directory with a license file under `third_party/`, `3rdparty/`, `vendor/`, `external/`, ...;
  reported, since nothing says which version was copied

What each names is kept as declared; registry names (Bazel modules, vcpkg ports, Conan packages) are mapped to a repo
and tag later, at scan time (`limbowatch.watch.registries`). Whatever can't be pinned down is still listed, with why.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from limbowatch.models import Inventory, Unchecked, UnresolvedDependency, Upstream, UpstreamKind

MAX_BYTES = 2_000_000  # build files larger than this aren't read
NOT_WALKED = {".git", ".gradle", "node_modules", "build", "target", ".idea", "bazel-out", ".cache"}
VENDOR_ROOTS = {"third_party", "third-party", "thirdparty", "3rdparty", "vendor", "vendored", "external", "extern",
                "deps", "contrib"}  # fmt: skip
# A vendor/ next to one of these is a package manager's (Go, Composer, Bundler, npm), already read from its lockfile.
MANAGED_VENDOR = {"go.mod", "composer.json", "Gemfile", "package.json", "Cargo.toml"}
LICENSE = re.compile(r"(?i)^(licen[cs]e|copying)([.-].*)?$")
CPP_BUILD_FILES = {"CMakeLists.txt", "meson.build", "configure.ac", "configure.in", "Makefile", "makefile",
                   "GNUmakefile", "BUILD", "BUILD.bazel", "SConstruct", "premake5.lua", "xmake.lua"}  # fmt: skip

_FORGES = ("github.com", "gitlab.com", "codeberg.org", "bitbucket.org")
_COMMIT = re.compile(r"[0-9a-f]{7,40}")
_ARCHIVE = re.compile(r"\.(?:tar\.gz|tgz|tar\.bz2|tar\.xz|zip)$")


# --- URLs ---------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Located:
    host: str | None = None
    repo: str | None = None
    ref: str | None = None


def is_commit(ref: str | None) -> bool:
    return bool(ref) and _COMMIT.fullmatch(ref or "") is not None and not (ref or "").isdigit()


def locate(url: str) -> Located:
    """The host, repo and (for archive URLs) ref a git or archive URL points at.

    `git@github.com:o/r.git`, `https://github.com/o/r/archive/refs/tags/v1.tar.gz`, a mirror's copy of one
    (`https://mirror.bazel.build/github.com/o/r/...`), `codeload.github.com/o/r/tar.gz/REF`, GitLab's
    `/-/archive/REF/...`, or any other git URL (host and path, no ref).
    """
    url = url.strip()
    if m := re.match(r"^[\w.-]+@([\w.-]+):(?!//)(.+)$", url):  # scp-like
        url = f"ssh://{m.group(1)}/{m.group(2)}"
    if url.startswith("git+"):
        url = url[4:]
    s = urlsplit(url)
    host, path = (s.hostname or "").lower().removeprefix("www."), s.path
    if not host:
        return Located()
    for forge in _FORGES:  # a mirror's copy: .../github.com/o/r/...
        if host != forge and f"/{forge}/" in path:
            host, path = forge, path.split(f"/{forge}/", 1)[1]
            break
    if host == "codeload.github.com":
        host = "github.com"
    parts = [p for p in path.split("/") if p]
    if host == "github.com":
        if len(parts) < 2:
            return Located(host)
        repo = f"{parts[0]}/{parts[1].removesuffix('.git')}".lower()
        rest = parts[2:]
        ref = None
        if rest[:3] == ["archive", "refs", "tags"] and len(rest) == 4:
            ref = _ARCHIVE.sub("", rest[3])
        elif rest[:1] == ["archive"] and len(rest) == 2:
            ref = _ARCHIVE.sub("", rest[1])
        elif rest[:2] == ["releases", "download"] and len(rest) >= 3:
            ref = rest[2]
        elif rest[:1] in (["tarball"], ["zipball"], ["tar.gz"], ["zip"]) and len(rest) >= 2:
            ref = rest[1]
        return Located(host, repo, ref)
    if "-" in parts:  # GitLab and Gitea-style: owner/group/repo/-/archive/REF/name.tar.gz
        i = parts.index("-")
        ref = parts[i + 2] if parts[i + 1 : i + 2] == ["archive"] and len(parts) > i + 2 else None
        return Located(host, "/".join(parts[:i]).removesuffix(".git"), ref)
    if parts and _ARCHIVE.search(parts[-1]):
        return Located(host)  # an archive on a project's own site: no repo
    return Located(host, "/".join(parts).removesuffix(".git") or None)


def pick_url(urls: list[str]) -> tuple[str, Located]:
    """The URL that names a repository, preferring GitHub; else the first."""
    located = [(u, locate(u)) for u in urls]
    for u, loc in sorted(located, key=lambda x: (x[1].host != "github.com", x[1].repo is None)):
        if loc.repo:
            return u, loc
    return (urls[0], Located()) if urls else ("", Located())


# --- vcpkg portfiles ---------------------------------------------------------------------------------------------


def ref_template(portfile: str) -> str:
    for _, args, _ in calls(strip_cmake_comments(portfile), r"vcpkg_from_(?:github|gitlab|git)"):
        a = cmake_args(args)
        if "REF" in a and a.index("REF") + 1 < len(a):
            return a[a.index("REF") + 1]
    return ""


def portfile_source(portfile: str, version: str) -> tuple[Located, str | None, str]:
    """(repo, ref, url) a portfile builds from, with ${VERSION} and the portfile's own set() variables filled in."""
    text = strip_cmake_comments(portfile)
    var = cmake_variables([text]) | {"VERSION": version}
    for fn, args, _ in calls(text, r"vcpkg_from_(?:github|gitlab|git|bitbucket|sourceforge)"):
        a = [subst(x, var) for x in cmake_args(args)]
        get = {k: a[a.index(k) + 1] for k in ("REPO", "REF", "URL", "GITLAB_URL") if k in a and a.index(k) + 1 < len(a)}
        ref = get.get("REF")
        ref = None if ref is None or "${" in ref else ref
        kind = fn.lower().removeprefix("vcpkg_from_")
        if kind == "github" and "REPO" in get and "/" in get["REPO"]:
            url = f"https://github.com/{get['REPO']}"
            return locate(url), ref, url
        if kind == "gitlab" and "REPO" in get:
            url = f"{get.get('GITLAB_URL', 'https://gitlab.com').rstrip('/')}/{get['REPO']}"
            return locate(url), ref, url
        if kind == "git" and "URL" in get:
            return locate(get["URL"]), ref, get["URL"]
        if kind == "bitbucket" and "REPO" in get:
            url = f"https://bitbucket.org/{get['REPO']}"
            return locate(url), ref, url
    urls = [subst(u, var) for u in re.findall(r"(?:https?|ftp)://[^\s\"'\]]+", text)]
    url, loc = pick_url([u for u in urls if "${" not in u])
    return loc, loc.ref, url


# --- CMake ----------------------------------------------------------------------------------------------------------

_CMAKE_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\[(=*)\[.*?\]\1\]|[^\s()"]+', re.S)


def strip_cmake_comments(text: str) -> str:
    text = re.sub(r"#\[(=*)\[.*?\]\1\]", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    out = []
    for line in text.split("\n"):
        q = False
        for i, ch in enumerate(line):
            if ch == '"' and (i == 0 or line[i - 1] != "\\"):
                q = not q
            elif ch == "#" and not q:
                line = line[:i]
                break
        out.append(line)
    return "\n".join(out)


def calls(text: str, names: str) -> Iterator[tuple[str, str, int]]:
    """(name, argument text, line) of every call to a function matching `names` (a regex, case-insensitive)."""
    for m in re.finditer(rf"(?<![\w.]){names}\s*\(", text, re.I):
        depth, j, q = 1, m.end(), False
        while j < len(text) and depth:
            ch = text[j]
            if ch == '"' and text[j - 1] != "\\":
                q = not q
            elif not q:
                depth += {"(": 1, ")": -1}.get(ch, 0)
            j += 1
        yield m.group(0).rstrip("( \t\n"), text[m.end() : j - 1], text.count("\n", 0, m.start()) + 1


def cmake_args(s: str) -> list[str]:
    out = []
    for m in _CMAKE_TOKEN.finditer(s):
        t = m.group(0)
        if t.startswith('"'):
            t = t[1:-1].replace('\\"', '"')
        elif t.startswith("["):
            t = re.sub(r"^\[(=*)\[|\](=*)\]$", "", t)
        out.append(t)
    return out


def cmake_variables(texts: list[str]) -> dict[str, str | None]:
    """`set(NAME value)` across the project's CMake files; None when a name is set to different values."""
    out: dict[str, str | None] = {}
    for text in texts:
        for _, args, _ in calls(strip_cmake_comments(text), "set"):
            a = cmake_args(args)
            if len(a) < 2:
                continue
            vals = a[1 : a.index("CACHE")] if "CACHE" in a else [x for x in a[1:] if x != "PARENT_SCOPE"]
            v = ";".join(vals)
            out[a[0]] = v if a[0] not in out or out[a[0]] == v else None
    return out


def subst(s: str, var: dict[str, str | None]) -> str:
    for _ in range(5):
        new = re.sub(r"\$\{(\w+)\}", lambda m: var.get(m.group(1)) or m.group(0), s)
        if new == s:
            break
        s = new
    return s


_CMAKE_KEYWORDS = set(
    [
        "GIT_REPOSITORY",
        "GIT_TAG",
        "URL",
        "URL_HASH",
        "URL_MD5",
        "SOURCE_DIR",
        "GIT_SHALLOW",
        "PREFIX",
        "BINARY_DIR",
        "CMAKE_ARGS",
        "PATCH_COMMAND",
        "UPDATE_COMMAND",
        "BUILD_COMMAND",
        "INSTALL_COMMAND",
        "CONFIGURE_COMMAND",
        "SOURCE_SUBDIR",
        "FIND_PACKAGE_ARGS",
        "OVERRIDE_FIND_PACKAGE",
        "EXCLUDE_FROM_ALL",
        "SYSTEM",
        "GIT_PROGRESS",
        "GIT_SUBMODULES",
        "DOWNLOAD_EXTRACT_TIMESTAMP",
        "NAME",
        "VERSION",
        "GITHUB_REPOSITORY",
        "GITLAB_REPOSITORY",
        "BITBUCKET_REPOSITORY",
        "OPTIONS",
        "DOWNLOAD_ONLY",
        "DEPENDS",
        "LOG_DOWNLOAD",
        "TIMEOUT",
        "TEST_COMMAND",
        "STEP_TARGETS",
        "BUILD_IN_SOURCE",
        "INSTALL_DIR",
        "DOWNLOAD_COMMAND",
        "DOWNLOAD_DIR",
        "TLS_VERIFY",
        "GIT_REMOTE_NAME",
        "GIT_CONFIG",
        "BUILD_BYPRODUCTS",
        "USES_TERMINAL_DOWNLOAD",
        "LIST_SEPARATOR",
    ]
)


def _kw(args: list[str], key: str) -> list[str]:
    """The values after keyword `key`, up to the next keyword."""
    if key not in args:
        return []
    out = []
    for a in args[args.index(key) + 1 :]:
        if a in _CMAKE_KEYWORDS:
            break
        out.append(a)
    return out


def _first(xs: list[str]) -> str | None:
    return xs[0] if xs else None


def _from_url(kind: UpstreamKind, name: str, src: str, line: int, url: str, tag: str | None,
              version: str | None = None) -> Upstream:  # fmt: skip
    local = re.match(r"^\$\{(CMAKE_CURRENT_SOURCE_DIR|CMAKE_CURRENT_LIST_DIR|CMAKE_SOURCE_DIR|PROJECT_SOURCE_DIR)\}"
                     r"|^file://|^\.{0,2}/", url)  # fmt: skip
    if local:
        return Upstream(kind=kind, name=name, source=src, line=line, url=url, version=version,
                        detail="an archive in this tree: its version is unknown")  # fmt: skip
    unresolved = "${" in url or "$<" in url
    loc = Located() if unresolved or not url else locate(url)
    ref = tag if tag and "${" not in tag else loc.ref
    detail = ""
    if unresolved:
        detail = f"the URL comes from a variable this project doesn't set: {url}"
    elif not url:
        detail = "no download URL"
    elif loc.repo is None:
        detail = f"{loc.host or url} isn't a git repository"
    elif ref is None:
        detail = (f"the tag comes from a variable this project doesn't set: {tag}" if tag
                  else "no tag or commit: it follows a branch")  # fmt: skip
    return Upstream(kind=kind, name=name, source=src, line=line, url=url or None, host=loc.host, repo=loc.repo,
                    ref=ref, ref_is_commit=is_commit(ref), version=version, detail=detail)  # fmt: skip


_CPM_SCHEMES = {"gh": "github.com", "gl": "gitlab.com", "bb": "bitbucket.org"}


def _cpm(args: list[str], src: str, line: int) -> Upstream | None:
    if len(args) == 1:  # shorthand: "gh:owner/name@1.2.3#tag", or "https://host/o/r.git@1.2.3"
        s = args[0]
        tag = s.split("#", 1)[1] if "#" in s else None
        s = s.split("#", 1)[0]
        version = None
        if m := re.match(r"^(.*?)@([^@/]+)$", s):
            s, version = m.group(1), m.group(2)
        if m := re.match(r"^(gh|gl|bb):(.+)$", s):
            s = f"https://{_CPM_SCHEMES[m.group(1)]}/{m.group(2)}"
        name = s.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        return _from_url(UpstreamKind.CPM, name, src, line, s, tag or (f"v{version}" if version else None), version)
    name = (_kw(args, "NAME") or [""])[0]
    version = _first(_kw(args, "VERSION"))
    tag = _first(_kw(args, "GIT_TAG")) or (f"v{version}" if version else None)  # CPM's default tag
    for key, host in (("GITHUB_REPOSITORY", "github.com"), ("GITLAB_REPOSITORY", "gitlab.com"),
                      ("BITBUCKET_REPOSITORY", "bitbucket.org")):  # fmt: skip
        if v := _kw(args, key):
            return _from_url(UpstreamKind.CPM, name or v[0], src, line, f"https://{host}/{v[0]}", tag, version)
    url = (_kw(args, "GIT_REPOSITORY") or _kw(args, "URL") or [""])[0]
    if not url and _kw(args, "SOURCE_DIR"):
        return None  # a local copy, not downloaded
    return _from_url(UpstreamKind.CPM, name, src, line, url, tag, version)


def cmake(text: str, src: str, var: dict[str, str | None]) -> list[Upstream]:
    text = strip_cmake_comments(text)
    out: list[Upstream] = []
    for fn, raw, line in calls(
        text, r"(FetchContent_Declare|ExternalProject_Add|CPMAddPackage|CPMFindPackage|CPMDeclarePackage)"
    ):
        args = [subst(a, var) for a in cmake_args(raw)]
        if not args:
            continue
        if fn.lower().startswith("cpm"):
            if (u := _cpm(args, src, line)) is not None:
                out.append(u)
            continue
        kind = UpstreamKind.FETCHCONTENT if fn.lower() == "fetchcontent_declare" else UpstreamKind.EXTERNALPROJECT
        git, urls = _kw(args, "GIT_REPOSITORY"), _kw(args, "URL")
        if not git and not urls:
            continue  # SOURCE_DIR (a local copy), or a custom DOWNLOAD_COMMAND: nothing is fetched by URL here
        url = git[0] if git else next((u for u in urls if locate(u).repo), urls[0])
        tag = _first(_kw(args, "GIT_TAG")) if git else None
        out.append(_from_url(kind, args[0], src, line, url, tag))
    return out


# --- git submodules -------------------------------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> str | None:
    try:
        # core.fsmonitor in a repo's config would run a command; safe.directory=* (needed for checkouts owned by
        # another user, as in CI containers) would otherwise let it (F-141)
        r = subprocess.run(["git", "-c", "safe.directory=*", "-c", "core.fsmonitor=false", *args], cwd=cwd,
                           capture_output=True, text=True,
                           timeout=120, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def gitmodules(text: str) -> list[tuple[str, str, int]]:
    """(path, url, line) of each submodule in a .gitmodules file."""
    out: list[tuple[str, str, int]] = []
    cur: dict[str, str] = {}
    at = 1
    for n, ln in enumerate([*text.splitlines(), "[end]"], 1):
        s = ln.strip()
        if s.startswith("["):
            if cur.get("path"):
                out.append((cur["path"], cur.get("url", ""), at))
            cur, at = {}, n
        elif "=" in s and not s.startswith(("#", ";")):
            k, v = s.split("=", 1)
            cur[k.strip().lower()] = v.strip().strip('"')
    return out


def _relative_url(url: str, base: str | None) -> str:
    """A submodule URL like ../lib.git is relative to the superproject's remote."""
    if not url.startswith(("./", "../")) or not base:
        return url
    if m := re.match(r"^[\w.-]+@([\w.-]+):(?!//)(.+)$", base):  # git@github.com:o/super.git (F-141)
        base = f"ssh://{m.group(1)}/{m.group(2)}"
    b = base.rstrip("/").removesuffix(".git")
    for part in url.split("/"):
        if part == "..":
            b = b.rsplit("/", 1)[0] if "/" in b.split("://", 1)[-1] else b
        elif part not in (".", ""):
            b = f"{b}/{part}"
    return b


def submodules(root: Path, rel: str, text: str) -> list[Upstream]:
    d = root / rel
    entries = gitmodules(text)
    if not entries:
        return []
    links: dict[str, str] = {}
    listed = _git(d, "ls-files", "-s", "-z", "--", *[p for p, _, _ in entries])
    for rec in (listed or "").split("\0"):
        if rec.startswith("160000 "):
            meta, path = rec.split("\t", 1)
            links[path] = meta.split()[1]
    base = (_git(d, "remote", "get-url", "origin") or "").strip() or None
    src = (PurePosixPath(rel) / ".gitmodules").as_posix() if rel not in ("", ".") else ".gitmodules"
    out = []
    for path, url, line in entries:
        url = _relative_url(url, base)
        loc = locate(url) if url else Located()
        commit = links.get(path)
        if commit is None and (d / path / ".git").exists():
            commit = (_git(d / path, "rev-parse", "HEAD") or "").strip() or None
        detail = ""
        if loc.repo is None:
            detail = f"submodule URL “{url}” isn't a repository URL" if url else "no submodule URL"
        elif commit is None:
            detail = ("not in the git index" if listed is not None
                      else "not a git checkout, and the submodule isn't checked out")  # fmt: skip
        out.append(Upstream(kind=UpstreamKind.SUBMODULE, name=path, source=src, line=line, url=url or None,
                            host=loc.host, repo=loc.repo, ref=commit, ref_is_commit=commit is not None,
                            detail=detail))  # fmt: skip
    return out


# --- Bazel ----------------------------------------------------------------------------------------------------------

_STR = re.compile(r'"((?:\\.|[^"\\])*)"|\'((?:\\.|[^\'\\])*)\'')


def _kwarg(args: str, key: str) -> str | None:
    m = re.search(rf"(?<![\w.]){key}\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", args)
    return (m.group(1) if m.group(1) is not None else m.group(2)) if m else None


def _urls(args: str) -> list[str]:
    return [a or b for a, b in _STR.findall(args) if re.match(r"^(?:https?|git|ssh)://|^git@", a or b)]


def bazel(text: str, src: str, module_file: bool) -> list[Upstream]:
    text = "\n".join(re.sub(r"(^|\s)#.*$", r"\1", ln) for ln in text.split("\n"))
    out: list[Upstream] = []
    overrides: dict[str, tuple[str, str]] = {}  # module -> (kind, args)
    if module_file:
        for fn, args, _ in calls(text, r"(git_override|archive_override|single_version_override|local_path_override)"):
            if mod := _kwarg(args, "module_name"):
                overrides[mod] = (fn, args)
        for _, args, line in calls(text, "bazel_dep"):
            name, version = _kwarg(args, "name"), _kwarg(args, "version") or ""
            if not name:
                continue
            ov = overrides.get(name)
            if ov and ov[0] == "local_path_override":
                continue  # the module's source is in this tree
            if ov and ov[0] in ("git_override", "archive_override"):
                urls = [_kwarg(ov[1], "remote") or ""] if ov[0] == "git_override" else _urls(ov[1])
                url = next((u for u in urls if locate(u).repo), urls[0] if urls else "")
                tag = _kwarg(ov[1], "commit") or _kwarg(ov[1], "tag") if ov[0] == "git_override" else None
                u = _from_url(UpstreamKind.BAZEL_MODULE, name, src, line, url, tag, version or None)
                out.append(u.model_copy(update={"via": ov[0]}))
                continue
            if ov and ov[0] == "single_version_override":
                version = _kwarg(ov[1], "version") or version
            why = "" if version else "no version: Bazel picks it from the dependency graph"
            out.append(Upstream(kind=UpstreamKind.BAZEL_MODULE, name=name, source=src, line=line,
                                version=version or None, detail=why))  # fmt: skip
    rules = r"(?:\w*http_archive|\w*git_repository|maybe)"
    for fn, args, line in calls(text, rules):
        if fn == "maybe":  # maybe(http_archive, name = ..., ...)
            m = re.match(r"\s*(\w*(?:http_archive|git_repository))\s*,", args)
            if not m:
                continue
            fn = m.group(1)
        name = _kwarg(args, "name")
        if not name:
            continue  # a macro passing its own parameters through, not a declaration
        if fn.endswith("git_repository"):
            url = _kwarg(args, "remote") or ""
            tag = _kwarg(args, "commit") or _kwarg(args, "tag")
            out.append(_from_url(UpstreamKind.BAZEL_GIT, name, src, line, url, tag))
        else:
            urls = _urls(args)
            url = next((u for u in urls if locate(u).repo), urls[0] if urls else "")
            u = _from_url(UpstreamKind.BAZEL_ARCHIVE, name, src, line, url, None)
            if u.repo and u.ref is None and (sp := _kwarg(args, "strip_prefix")):
                u = u.model_copy(update={"detail": f"{u.detail}; strip_prefix “{sp}”"})
            out.append(u)
    return out


# --- vcpkg, Conan, meson --------------------------------------------------------------------------------------------


def _obj(x: Any) -> dict[str, Any]:
    return x if isinstance(x, dict) else {}


def _objs(x: Any) -> list[dict[str, Any]]:
    return [o for o in x if isinstance(o, dict)] if isinstance(x, list) else []


def _strs(x: Any) -> list[str]:
    return [s for s in x if isinstance(s, str)] if isinstance(x, list) else []


def _line_of(text: str, needle: str, start: int = 0) -> int:
    i = text.find(needle, start)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def vcpkg(
    text: str,
    src: str,
    config: str | None,
    *,
    overlays: frozenset[str] = frozenset(),
    project_baseline: str | None = None,
) -> tuple[list[Upstream], list[UnresolvedDependency]]:
    """A vcpkg manifest's dependencies. Ports the project defines itself (`overlays`) aren't looked up in vcpkg's
    registry: each is listed from its own portfile (`overlay_port`). An overlay port's manifest has no baseline of its
    own; its dependencies take the project's (`project_baseline`)."""
    try:
        m = json.loads(text)
    except ValueError as e:
        return [], [UnresolvedDependency(reason=Unchecked.LOCKFILE_UNREADABLE, source=src, detail=str(e))]
    if not isinstance(m, dict) or not isinstance(m.get("dependencies", []), list):
        why = "not a vcpkg manifest: expected an object with a list of dependencies"
        return [], [UnresolvedDependency(reason=Unchecked.LOCKFILE_UNREADABLE, source=src, detail=why)]
    cfg = _obj(m.get("vcpkg-configuration"))
    if config:
        try:
            cfg = _obj(json.loads(config))
        except ValueError:
            cfg = {}
    default = _obj(cfg.get("default-registry"))
    official = default.get("kind") in ("builtin", "git") and "microsoft/vcpkg" in (
        default.get("repository") or "microsoft/vcpkg"
    )
    baseline = m.get("builtin-baseline") or project_baseline or (default.get("baseline") if official else None)
    custom = {p: r.get("repository") or r.get("path") or r.get("kind") for r in _objs(cfg.get("registries"))
              for p in _strs(r.get("packages"))}  # fmt: skip
    overrides = {o["name"]: o.get("version") or o.get("version-string") or o.get("version-semver")
                 or o.get("version-date")
                 for o in _objs(m.get("overrides")) if isinstance(o.get("name"), str)}  # fmt: skip
    start = text.find('"dependencies"')
    out: list[Upstream] = []
    out_bad: list[UnresolvedDependency] = []
    for d in m.get("dependencies") or []:
        name = d if isinstance(d, str) else d.get("name") if isinstance(d, dict) else None
        if not isinstance(name, str):
            why = f"a dependency that isn't a port name: {d!r}"[:200]
            out_bad.append(UnresolvedDependency(reason=Unchecked.LOCKFILE_UNREADABLE, source=src, detail=why))
            continue
        if not name or name.startswith("vcpkg-") or name in overlays:
            continue  # vcpkg's own CMake helper ports, not code the project ships; or a port the project defines
        minimum = d.get("version>=") if isinstance(d, dict) else None
        version = overrides.get(name) or (f">={minimum}" if minimum else None)
        detail = ""
        if name in custom:
            detail = f"from the registry {custom[name]}, not vcpkg's own"
        elif not baseline and not overrides.get(name):
            detail = "no builtin-baseline: the version depends on the vcpkg checkout used to build"
        pin = baseline if baseline and name not in custom else None
        out.append(Upstream(kind=UpstreamKind.VCPKG, name=name, source=src, line=_line_of(text, f'"{name}"', start),
                            version=version, baseline=pin, detail=detail))  # fmt: skip
    return out, out_bad


def overlay_port(manifest: str, portfile: str, src: str) -> Upstream | None:
    """A port the project defines itself (an overlay port): the repo and tag its portfile builds from."""
    try:
        m = json.loads(manifest)
    except ValueError:
        return None
    if not isinstance(m, dict):
        return None
    name = m.get("name")
    if not isinstance(name, str):
        return None
    version = next((str(m[k]) for k in ("version", "version-semver", "version-date", "version-string") if k in m), "")
    loc, ref, url = portfile_source(portfile, version)
    detail = "" if loc.repo and ref else (
        "the port's tag couldn't be worked out" if loc.repo else "the port downloads from a site, not a repository"
        if url else "the port builds from no download")  # fmt: skip
    return Upstream(kind=UpstreamKind.VCPKG, name=name, source=src, line=1, url=url or None, host=loc.host,
                    repo=loc.repo, ref=ref, ref_is_commit=is_commit(ref), version=version or None,
                    via="the project's own port", detail=detail)  # fmt: skip


_CONAN_REF = re.compile(r"^([\w.+-]+)/([^@#\s]+)(?:@([\w.+-]+)/([\w.+-]+))?")


def _conan_entry(ref: str, src: str, line: int) -> Upstream:
    m = _CONAN_REF.match(ref.strip())
    if not m:
        return Upstream(kind=UpstreamKind.CONAN, name=ref.strip(), source=src, line=line,
                        detail="not a Conan reference")  # fmt: skip
    name, version, user = m.group(1), m.group(2), m.group(3)
    detail = ""
    if version.startswith("["):
        detail, version = f"only a version range is given: {version}", ""
    elif user and user != "_":
        detail = f"from @{user}/{m.group(4)}, not ConanCenter"
    return Upstream(kind=UpstreamKind.CONAN, name=name, source=src, line=line, version=version or None,
                    detail=detail)  # fmt: skip


def conan_lock(text: str, src: str) -> list[Upstream]:
    m = json.loads(text)  # a malformed lock raises; detect() reports it as unreadable
    if not isinstance(m, dict):
        raise ValueError("not a Conan lockfile: expected an object")
    refs: list[str] = []
    for key in ("requires", "build_requires", "python_requires"):
        refs += _strs(m.get(key))
    nodes = _obj(_obj(m.get("graph_lock")).get("nodes"))
    for node in nodes.values():  # Conan 1 lockfiles
        if isinstance(node, dict) and node.get("ref"):
            refs.append(node["ref"])
    return [_conan_entry(r, src, _line_of(text, r)) for r in dict.fromkeys(refs)]


def _conan_strings(s: str) -> list[str]:
    return re.findall(r"""["']([\w.+-]+/[^"'\s]+)["']""", s)


def conanfile(text: str, src: str) -> list[Upstream]:
    out = []
    if src.endswith(".txt"):
        sec = None
        for n, ln in enumerate(text.splitlines(), 1):
            s = ln.split("#", 1)[0].strip()
            if s.startswith("["):
                sec = s
            elif s and sec in ("[requires]", "[tool_requires]", "[build_requires]", "[test_requires]"):
                out.append(_conan_entry(s, src, n))
        return out
    for m in re.finditer(r"(?<!\w)(?:tool_|build_|test_)?requires\s*(\+?=|\()", text):
        j, opener = m.end(), m.group(1)
        if opener != "(":  # an assignment: to the end of the line, or of the bracket it opens
            k = len(text) - len(text[j:].lstrip(" \t"))
            if text[k : k + 1] not in ("(", "["):
                end = text.find("\n", j)
                body = text[j : end if end >= 0 else len(text)]
                out += [_conan_entry(r, src, text.count("\n", 0, m.start()) + 1) for r in _conan_strings(body)]
                continue
            j, opener = k + 1, text[k]
        close = {"(": ")", "[": "]"}[opener]
        depth, e = 1, j
        while e < len(text) and depth:
            depth += 1 if text[e] == opener else -1 if text[e] == close else 0
            e += 1
        out += [_conan_entry(r, src, text.count("\n", 0, m.start()) + 1) for r in _conan_strings(text[j:e])]
    return out


def meson_wrap(text: str, src: str, name: str) -> Upstream | None:
    sec = (re.search(r"^\[(wrap-\w+)\]", text, re.M) or [None, ""])[1]
    kv = dict(re.findall(r"^\s*([\w-]+)\s*=\s*(.*?)\s*$", text, re.M))
    if sec == "wrap-git":
        rev = kv.get("revision")
        rev = None if rev in (None, "HEAD", "head", "master", "main") else rev
        return _from_url(UpstreamKind.MESON_WRAP, name, src, 1, kv.get("url", ""), rev)
    if sec == "wrap-file":
        u = _from_url(UpstreamKind.MESON_WRAP, name, src, 1, kv.get("source_url", ""), None,
                      kv.get("wrapdb_version"))  # fmt: skip
        return u
    return None  # wrap-redirect and friends point at another wrap


# --- the whole tree -------------------------------------------------------------------------------------------------


@dataclass
class Detected:
    upstreams: list[Upstream] = field(default_factory=list)
    unresolved: list[UnresolvedDependency] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    conan_locks: set[str] = field(default_factory=set)
    build_files: list[str] = field(default_factory=list)  # C/C++ build files seen, for a better "nothing found"


def files(root: Path, include_ignored: bool = False) -> list[str]:
    """The project's files, relative and POSIX: from git (tracked, in checked-out submodules too, plus untracked
    files not ignored), or by walking the tree when it isn't a git checkout or ignored files are wanted."""
    if not include_ignored:
        tracked = _git(root, "ls-files", "-z", "--recurse-submodules")
        if tracked is not None:
            others = _git(root, "ls-files", "-z", "--others", "--exclude-standard") or ""
            return sorted({f for f in (tracked + "\0" + others).split("\0") if f})
    out = []
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x not in NOT_WALKED]
        rel = Path(d).relative_to(root)
        out += [(rel / n).as_posix() for n in names]
    return sorted(out)


def _wanted(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return (name in (".gitmodules", "CMakeLists.txt", "MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel",
                     "WORKSPACE.bzlmod", "vcpkg.json", "conan.lock", "conanfile.txt", "conanfile.py")
            or name.endswith((".cmake", ".bzl", ".MODULE.bazel"))
            or (name.endswith(".wrap") and path.rsplit("/", 2)[-2:-1] == ["subprojects"]))  # fmt: skip


def detect(root: Path, include_ignored: bool = False) -> Detected:
    det = Detected()
    all_files = files(root, include_ignored)
    wanted = [f for f in all_files if _wanted(f) and not any(p in NOT_WALKED for p in f.split("/")[:-1])]
    det.build_files = [f for f in all_files if f.rsplit("/", 1)[-1] in CPP_BUILD_FILES][:5]

    def read(rel: str) -> str | None:
        p = root / rel
        try:
            return p.read_text(errors="replace") if p.stat().st_size <= MAX_BYTES else None
        except OSError:
            return None

    texts = {f: t for f in wanted if (t := read(f)) is not None}
    var = cmake_variables([t for f, t in texts.items() if f.endswith(("CMakeLists.txt", ".cmake"))])
    lock_dirs = {f.rsplit("/", 1)[0] if "/" in f else "" for f in texts if f.endswith("conan.lock")}
    present = set(all_files)
    # vcpkg overlay ports: a vcpkg.json beside a portfile.cmake is a port the project defines, not a project manifest
    overlay_dirs = {
        f: f.removesuffix("vcpkg.json") + "portfile.cmake"
        for f in texts
        if f.rsplit("/", 1)[-1] == "vcpkg.json" and f.removesuffix("vcpkg.json") + "portfile.cmake" in present
    }
    overlays = frozenset(n for f in overlay_dirs if isinstance(n := _json_name(texts[f]), str))
    baselines = {
        b
        for f, x in texts.items()
        if f.rsplit("/", 1)[-1] == "vcpkg.json"
        and f not in overlay_dirs
        and isinstance(b := _json_get(x, "builtin-baseline"), str)
    }
    baseline = baselines.pop() if len(baselines) == 1 else None  # fmt: skip
    for f, t in texts.items():
        name = f.rsplit("/", 1)[-1]
        d = f.rsplit("/", 1)[0] if "/" in f else ""
        found: list[Upstream] = []
        try:
            if name == ".gitmodules":
                found = submodules(root, d or ".", t)
            elif name == "CMakeLists.txt" or name.endswith(".cmake"):
                found = cmake(t, f, var)
            elif name in ("MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel", "WORKSPACE.bzlmod") or name.endswith(
                (".bzl", ".MODULE.bazel")
            ):  # *.MODULE.bazel: files MODULE.bazel include()s (Bazel 7.2+)
                found = bazel(t, f, module_file=name.endswith("MODULE.bazel"))
            elif name == "vcpkg.json":
                cfg_path = f"{d}/vcpkg-configuration.json" if d else "vcpkg-configuration.json"
                cfg = texts.get(cfg_path) or read(cfg_path)
                if f in overlay_dirs:  # a port the project defines: itself from its portfile, its dependencies
                    port = read(overlay_dirs[f])
                    own = overlay_port(t, port, overlay_dirs[f]) if port is not None else None
                    deps, bad = vcpkg(t, f, cfg, overlays=overlays, project_baseline=baseline)
                    found = ([own] if own else []) + deps
                else:
                    found, bad = vcpkg(t, f, cfg, overlays=overlays)
                det.unresolved += bad
            elif name == "conan.lock":
                found = conan_lock(t, f)
                det.conan_locks.add(f)
            elif name.startswith("conanfile.") and d not in lock_dirs:
                found = conanfile(t, f)
            elif name.endswith(".wrap"):
                found = [u] if (u := meson_wrap(t, f, name.removesuffix(".wrap"))) else []
        except Exception as e:  # one malformed file is reported, never the end of the scan
            why = f"couldn't be read: {type(e).__name__}: {e}"[:200]
            det.unresolved.append(UnresolvedDependency(reason=Unchecked.LOCKFILE_UNREADABLE, source=f, detail=why))
            continue
        if found:
            det.sources.append(f)
            det.upstreams += found
    taken = {u.name.rstrip("/") for u in det.upstreams if u.kind is UpstreamKind.SUBMODULE}
    det.unresolved += vendored(all_files, taken)
    return det


def _json_get(text: str, key: str) -> Any:
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    return doc.get(key) if isinstance(doc, dict) else None


def _json_name(text: str) -> Any:
    return _json_get(text, "name")


def vendored(all_files: list[str], submodule_paths: set[str]) -> list[UnresolvedDependency]:
    """Directories copied in under a vendor root, recognised by their license file."""
    present = set(all_files)
    seen: set[str] = set()
    out = []
    for f in all_files:
        parts = f.split("/")
        if len(parts) < 3 or not LICENSE.match(parts[-1]) or parts[-3].lower() not in VENDOR_ROOTS:
            continue
        lib = "/".join(parts[:-1])
        parent = "/".join(parts[:-3])
        if lib in seen or any(lib == s or lib.startswith(s + "/") for s in submodule_paths):
            continue
        if parts[-3].lower() == "vendor" and any(f"{parent}/{m}".lstrip("/") in present for m in MANAGED_VENDOR):
            continue  # a package manager's vendor directory
        seen.add(lib)
        why = "copied into the tree; list it in an SBOM (--sbom) to check it"
        out.append(UnresolvedDependency(reason=Unchecked.VENDORED, source=lib, name=parts[-2], detail=why))
    return out


def combine(inv: Inventory, det: Detected) -> Inventory:
    """OSV-Scanner's inventory plus the upstream sources. Conan locks OSV-Scanner read as an unsupported ecosystem
    are replaced by the detectors' reading; "no supported lockfile" goes when anything was found, and names the
    C/C++ build files when nothing was."""
    unresolved = [u for u in inv.unresolved
                  if not (u.reason is Unchecked.UNKNOWN_ECOSYSTEM and u.source in det.conan_locks)]  # fmt: skip
    found = bool(inv.dependencies or det.upstreams or det.unresolved)
    keep = []
    for u in unresolved:
        if u.reason is Unchecked.NO_LOCKFILES:
            if found:
                continue
            if det.build_files:
                u = u.model_copy(update={"detail": (
                    f"C/C++ build files ({', '.join(det.build_files)}) declare no dependency by repository or "
                    "version: libraries from the system (find_package, pkg-config) can't be checked; pass an SBOM "
                    "with --sbom")})  # fmt: skip
        keep.append(u)
    return inv.model_copy(update={
        "upstreams": tuple(det.upstreams),
        "unresolved": tuple(keep + det.unresolved),
        "sources": tuple(sorted(set(inv.sources) | set(det.sources))),
    })  # fmt: skip
