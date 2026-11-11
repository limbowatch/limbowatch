"""Upstream source dependencies (Phase 6 step 1, PHASE0_PLAN §13.18, FINDINGS F-136, F-137): detection from a
project's own files, and registry names (Bazel modules, vcpkg ports, Conan packages) mapped to repos and tags, from
recorded responses."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from conftest import FIXTURES
from limbowatch.http import HttpClient
from limbowatch.inventory import osv_scanner
from limbowatch.inventory import upstream as up
from limbowatch.models import Inventory, Unchecked, UnresolvedDependency, Upstream, UpstreamKind
from limbowatch.watch import registries as reg
from limbowatch.watch.scan import upstream_unchecked

UP = FIXTURES / "upstream"
BASELINE = "e54ef0fcc9a82033a61e51002552a910a5d57282"
GIT_ENV = {
    **os.environ,
    **dict.fromkeys(("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"), "t"),
    **dict.fromkeys(("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"), "t@example.com"),
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


@pytest.mark.parametrize(
    ("url", "host", "repo", "ref"),
    [
        ("https://github.com/madler/zlib.git", "github.com", "madler/zlib", None),
        ("git@github.com:FmtLib/fmt.git", "github.com", "fmtlib/fmt", None),
        ("https://github.com/google/highway/archive/refs/tags/1.4.0.tar.gz", "github.com", "google/highway", "1.4.0"),
        ("https://github.com/intel/ARM_NEON_2_x86_SSE/archive/a15b489e1222b2087007546b4912e21293ea86ff.tar.gz",
         "github.com", "intel/arm_neon_2_x86_sse", "a15b489e1222b2087007546b4912e21293ea86ff"),
        ("https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz", "github.com", "madler/zlib",
         "v1.3.1"),
        ("https://mirror.bazel.build/github.com/bazelbuild/rules_cc/archive/0.1.1.tar.gz", "github.com",
         "bazelbuild/rules_cc", "0.1.1"),
        ("https://codeload.github.com/o/r/tar.gz/v2", "github.com", "o/r", "v2"),
        ("https://gitlab.com/libeigen/eigen/-/archive/3.4.0/eigen-3.4.0.tar.gz", "gitlab.com", "libeigen/eigen",
         "3.4.0"),
        ("https://chromium.googlesource.com/webm/libvpx", "chromium.googlesource.com", "webm/libvpx", None),
        ("https://zlib.net/fossils/zlib-1.3.1.tar.gz", "zlib.net", None, None),
    ],
)  # fmt: skip
def test_locate(url: str, host: str, repo: str | None, ref: str | None) -> None:
    assert up.locate(url) == up.Located(host, repo, ref)


def test_is_commit() -> None:
    assert up.is_commit("a15b489e1222b2087007546b4912e21293ea86ff") and up.is_commit("abc1234")
    assert not up.is_commit("v1.2.3") and not up.is_commit("20250127") and not up.is_commit(None)


CMAKE = """
set(FMT_TAG 10.2.1)
set(JSON_URL "https://github.com/nlohmann/json/archive/refs/tags/v3.11.3.tar.gz")
include(FetchContent)
FetchContent_Declare(fmt GIT_REPOSITORY https://github.com/fmtlib/fmt.git GIT_TAG ${FMT_TAG})
FetchContent_Declare(json URL ${JSON_URL} URL_HASH SHA256=abc)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        b514bdc898e2951020cbdca1304b75f5950d1f59 # v1.15.2
)
# FetchContent_Declare(old GIT_REPOSITORY https://github.com/old/old.git GIT_TAG v1)
#[[ FetchContent_Declare(older GIT_REPOSITORY https://github.com/old/older.git GIT_TAG v1) ]]
FetchContent_Declare(local SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/local)
ExternalProject_Add(boost URL ${BOOST_URL})
ExternalProject_Add(angel URL ${CMAKE_CURRENT_SOURCE_DIR}/angelscript.zip)
ExternalProject_Add(head GIT_REPOSITORY https://github.com/o/head.git)
CPMAddPackage("gh:nlohmann/json@3.11.3")
CPMAddPackage("gh:fmtlib/fmt#10.0.0")
CPMAddPackage(NAME spdlog GITHUB_REPOSITORY gabime/spdlog VERSION 1.14.1)
"""


def test_cmake() -> None:
    got = {(u.kind.value, u.name): u for u in up.cmake(CMAKE, "CMakeLists.txt", up.cmake_variables([CMAKE]))}
    fmt = got[("CMake FetchContent", "fmt")]
    assert (fmt.repo, fmt.ref, fmt.ref_is_commit, fmt.line) == ("fmtlib/fmt", "10.2.1", False, 5)
    assert got[("CMake FetchContent", "json")].ref == "v3.11.3"  # from the archive URL, after variable substitution
    gt = got[("CMake FetchContent", "googletest")]
    assert gt.ref_is_commit and gt.ref == "b514bdc898e2951020cbdca1304b75f5950d1f59"
    assert not any(n in ("old", "older", "local") for _, n in got)  # comments, and a local SOURCE_DIR
    assert "variable this project doesn't set" in got[("CMake ExternalProject", "boost")].detail
    assert got[("CMake ExternalProject", "angel")].detail == "an archive in this tree: its version is unknown"
    assert got[("CMake ExternalProject", "head")].detail == "no tag or commit: it follows a branch"
    cpm = {u.name: u for u in got.values() if u.kind is UpstreamKind.CPM}
    assert (cpm["json"].repo, cpm["json"].ref, cpm["json"].version) == ("nlohmann/json", "v3.11.3", "3.11.3")
    assert (cpm["fmt"].ref, cpm["spdlog"].repo, cpm["spdlog"].ref) == ("10.0.0", "gabime/spdlog", "v1.14.1")


def test_cmake_variables_set_twice_differently_are_not_guessed() -> None:
    var = up.cmake_variables(["set(TAG v1)", "set(TAG v2)", "set(X a CACHE STRING doc)"])
    assert var == {"TAG": None, "X": "a"}


MODULE = """
bazel_dep(name = "zlib", version = "1.3.1.bcr.3")
bazel_dep(name = "rules_cc", version = "0.1.1", dev_dependency = True)
bazel_dep(name = "abseil-cpp", version = "20240116.0")
single_version_override(module_name = "abseil-cpp", version = "20250127.1")
bazel_dep(name = "mylib", version = "1.0")
git_override(
    module_name = "mylib",
    remote = "https://github.com/me/mylib.git",
    commit = "0123456789abcdef0123456789abcdef01234567",
)
bazel_dep(name = "inhouse", version = "")
local_path_override(module_name = "inhouse", path = "../inhouse")
"""
WORKSPACE = """
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
http_archive(
    name = "com_google_protobuf",  # protobuf
    urls = [
        "https://storage.googleapis.com/grpc-bazel-mirror/github.com/protocolbuffers/protobuf/archive/v29.0.tar.gz",
        "https://github.com/protocolbuffers/protobuf/archive/v29.0.tar.gz",
    ],
)
maybe(
    http_archive,
    name = "boringssl",
    urls = ["https://github.com/google/boringssl/archive/c63fadbde60a2224c22189d14c4001bbd2a3a629.tar.gz"],
)
def repo():
    tf_http_archive(
        name = "highway",
        urls = tf_mirror_urls("https://github.com/google/highway/archive/refs/tags/1.4.0.tar.gz"),
    )
def tf_http_archive(name, urls, **kwargs):
    http_archive(name = name, urls = urls)
git_repository(name = "re2", remote = "https://github.com/google/re2.git", tag = "2024-07-02")
http_archive(name = "site", urls = ["https://example.org/dl/thing-1.0.tar.gz"])
"""


def test_bazel() -> None:
    mods = {u.name: u for u in up.bazel(MODULE, "MODULE.bazel", module_file=True)}
    assert set(mods) == {"zlib", "rules_cc", "abseil-cpp", "mylib"}  # a local_path_override is in the tree
    assert (mods["zlib"].version, mods["zlib"].repo) == ("1.3.1.bcr.3", None)  # mapped through BCR at scan time
    assert mods["abseil-cpp"].version == "20250127.1"
    assert (mods["mylib"].repo, mods["mylib"].ref_is_commit, mods["mylib"].via) == ("me/mylib", True, "git_override")
    ws = {u.name: u for u in up.bazel(WORKSPACE, "WORKSPACE", module_file=False)}
    assert set(ws) == {"com_google_protobuf", "boringssl", "highway", "re2", "site"}  # not the macro's own call
    assert (ws["com_google_protobuf"].repo, ws["com_google_protobuf"].ref) == ("protocolbuffers/protobuf", "v29.0")
    assert ws["boringssl"].ref_is_commit and ws["highway"].ref == "1.4.0"
    assert (ws["re2"].kind, ws["re2"].ref) == (UpstreamKind.BAZEL_GIT, "2024-07-02")
    assert ws["site"].repo is None and "isn't a git repository" in ws["site"].detail


def test_vcpkg() -> None:
    manifest = json.dumps({
        "name": "app",
        "builtin-baseline": BASELINE,
        "dependencies": ["fmt", {"name": "vcpkg-cmake", "host": True}, {"name": "curl", "version>=": "8.0.0"},
                         "inhouse", "zlib"],
        "overrides": [{"name": "zlib", "version": "1.2.13"}],
    })  # fmt: skip
    config = '{"registries": [{"kind": "git", "repository": "https://example.org/reg.git", "packages": ["inhouse"]}]}'
    got, bad = up.vcpkg(manifest, "vcpkg.json", config)
    by = {u.name: u for u in got}
    assert not bad and set(by) == {"fmt", "curl", "inhouse", "zlib"}  # vcpkg's helper ports aren't upstreams
    assert (by["fmt"].baseline, by["curl"].version, by["zlib"].version) == (BASELINE, ">=8.0.0", "1.2.13")
    assert by["inhouse"].baseline is None and "example.org/reg.git" in by["inhouse"].detail
    nobase, _ = up.vcpkg('{"dependencies": ["fmt"]}', "vcpkg.json", None)
    assert "no builtin-baseline" in nobase[0].detail


def test_conan() -> None:
    lock2 = '{"version": "0.5", "requires": ["zlib/1.3.1#b8bc2603263cf7eccbd6e17e66b0ed76%1707212342.069"]}'
    lock1 = '{"graph_lock": {"nodes": {"0": {"ref": "app/1.0@me/stable"}, "1": {"ref": "bzip2/1.0.8#abc"}}}}'
    assert [(u.name, u.version) for u in up.conan_lock(lock2, "conan.lock")] == [("zlib", "1.3.1")]
    one = {u.name: u for u in up.conan_lock(lock1, "conan.lock")}
    assert one["bzip2"].version == "1.0.8" and "not ConanCenter" in one["app"].detail
    txt = up.conanfile("[requires]\nzlib/1.3.1\nboost/[>=1.80 <2]\n[generators]\nCMakeDeps\n", "conanfile.txt")
    assert [(u.name, u.version, u.line) for u in txt] == [("zlib", "1.3.1", 2), ("boost", None, 3)]
    assert "version range" in txt[1].detail
    py = up.conanfile(
        'class App(ConanFile):\n    requires = (\n        "fmt/10.2.1",\n        "spdlog/1.14.1",\n    )\n'
        '    def requirements(self):\n        self.requires("openssl/3.2.1")\n'
        '        self.tool_requires("cmake/3.30.0")\n',
        "conanfile.py",
    )
    assert [u.name for u in py] == ["fmt", "spdlog", "openssl", "cmake"]


def test_meson_wrap() -> None:
    g = up.meson_wrap("[wrap-git]\nurl = https://github.com/google/googletest.git\nrevision = v1.14.0\n", "s.wrap", "g")
    assert g is not None and (g.repo, g.ref) == ("google/googletest", "v1.14.0")
    head = up.meson_wrap("[wrap-git]\nurl = https://github.com/o/r.git\nrevision = HEAD\n", "s.wrap", "r")
    assert head is not None and head.ref is None
    assert up.meson_wrap("[wrap-redirect]\nfilename = a/b.wrap\n", "s.wrap", "x") is None


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, env=GIT_ENV).stdout


def _repo(tmp: Path) -> Path:
    p = tmp / "proj"
    p.mkdir()
    _git(p, "init", "-q")
    return p


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_submodules_get_their_commit_from_the_index_without_being_fetched(tmp_path: Path) -> None:
    p = _repo(tmp_path)
    sha = "cacf7f1d4e3d44d871b605da3b647f07d718623f"
    (p / ".gitmodules").write_text(
        '[submodule "zlib"]\n\tpath = third_party/zlib\n\turl = https://github.com/madler/zlib.git\n'
        '[submodule "gone"]\n\tpath = third_party/gone\n\turl = ../gone.git\n'
    )
    _git(p, "update-index", "--add", "--cacheinfo", f"160000,{sha},third_party/zlib")
    _git(p, "add", ".gitmodules")
    _git(p, "remote", "add", "origin", "https://github.com/acme/app.git")
    det = up.detect(p)
    subs = {u.name: u for u in det.upstreams}
    z = subs["third_party/zlib"]
    assert (z.repo, z.ref, z.ref_is_commit, z.source, z.line) == ("madler/zlib", sha, True, ".gitmodules", 1)
    gone = subs["third_party/gone"]
    assert (gone.repo, gone.ref, gone.detail) == ("acme/gone", None, "not in the git index")  # relative URL resolved


def test_a_submodule_outside_git_says_so(tmp_path: Path) -> None:
    (tmp_path / ".gitmodules").write_text('[submodule "x"]\n\tpath = x\n\turl = https://github.com/o/x.git\n')
    (u,) = up.detect(tmp_path).upstreams
    assert u.ref is None and "isn't checked out" in u.detail


def test_vendored_copies_are_reported_but_not_package_managers_vendor_dirs(tmp_path: Path) -> None:
    for f in ("third_party/stb/LICENSE", "src/3rdparty/zlib/COPYING", "vendor/github.com/x/LICENSE", "go.mod",
              "third_party/sub/LICENSE", "deps/README"):  # fmt: skip
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text("x")
    got = up.vendored(up.files(tmp_path, include_ignored=True), {"third_party/sub"})
    assert [(u.source, u.name, u.reason) for u in got] == [
        ("src/3rdparty/zlib", "zlib", Unchecked.VENDORED), ("third_party/stb", "stb", Unchecked.VENDORED)]  # fmt: skip


def test_combine_drops_no_lockfiles_when_upstreams_are_found_and_replaces_osv_scanners_conan_reading(
    tmp_path: Path,
) -> None:
    (tmp_path / "conan.lock").write_text('{"version": "0.5", "requires": ["zlib/1.3.1"]}')
    det = up.detect(tmp_path, include_ignored=True)
    inv = Inventory(unresolved=(
        UnresolvedDependency(reason=Unchecked.UNKNOWN_ECOSYSTEM, source="conan.lock", name="zlib", version="1.3.1",
                             ecosystem="ConanCenter"),
        UnresolvedDependency(reason=Unchecked.NO_LOCKFILES, source=".", detail="no supported lockfile")))  # fmt: skip
    out = up.combine(inv, det)
    assert out.unresolved == () and [u.name for u in out.upstreams] == ["zlib"] and out.sources == ("conan.lock",)


def test_combine_names_cpp_build_files_when_nothing_is_declared(tmp_path: Path) -> None:
    (tmp_path / "CMakeLists.txt").write_text("find_package(ZLIB REQUIRED)\n")
    out = up.combine(Inventory(unresolved=(UnresolvedDependency(reason=Unchecked.NO_LOCKFILES, source="."),)),
                     up.detect(tmp_path, include_ignored=True))  # fmt: skip
    (u,) = out.unresolved
    assert u.reason is Unchecked.NO_LOCKFILES and "CMakeLists.txt" in u.detail and "find_package" in u.detail


@pytest.mark.skipif(shutil.which("osv-scanner") is None, reason="osv-scanner not installed")
def test_osv_scanner_reads_conan_lock_offline(tmp_path: Path) -> None:
    """Without an empty ConanCenter database, offline OSV-Scanner fails the whole scan on a conan.lock (F-137)."""
    (tmp_path / "conan.lock").write_text('{"version": "0.5", "requires": ["zlib/1.3.1#abc%1"]}')
    inv = osv_scanner.run(tmp_path, resolve_maven=False)
    assert not any(u.reason is Unchecked.LOCKFILE_UNREADABLE for u in inv.unresolved)
    assert [(u.ecosystem, u.name) for u in inv.unresolved] == [("ConanCenter", "zlib")]


# --- registries, from recorded responses ----------------------------------------------------------------------------


def _u(kind: UpstreamKind, name: str, **kw: Any) -> Upstream:
    return Upstream(kind=kind, name=name, source="f", **kw)


async def test_bazel_module_from_its_source_archive(no_sleep: Any) -> None:
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{reg.BCR}/zlib/1.3.1.bcr.3/source.json").mock(
            return_value=httpx.Response(200, content=(UP / "bcr-zlib-1.3.1.bcr.3-source.json").read_bytes())
        )
        router.get(f"{reg.BCR}/nope/1.0/source.json").mock(return_value=httpx.Response(404))
        async with HttpClient(sleep=no_sleep) as http:
            r = reg.Registries(http)
            got = await r.resolve([_u(UpstreamKind.BAZEL_MODULE, "zlib", version="1.3.1.bcr.3"),
                                   _u(UpstreamKind.BAZEL_MODULE, "nope", version="1.0")])  # fmt: skip
    (z,), (n,) = got.values()
    assert (z.host, z.repo, z.ref, z.via) == ("github.com", "madler/zlib", "v1.3.1", "Bazel Central Registry")
    assert n.repo is None and "isn't in the Bazel Central Registry" in n.detail


async def test_vcpkg_ports_and_their_dependencies(no_sleep: Any) -> None:
    raw = f"{reg.RAW}/{reg.VCPKG}/{BASELINE}"
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{raw}/versions/baseline.json").mock(
            return_value=httpx.Response(200, content=(UP / "vcpkg-baseline-excerpt.json").read_bytes()))  # fmt: skip
        for p in ("zlib", "fmt", "curl"):
            router.get(f"{raw}/ports/{p}/portfile.cmake").mock(
                return_value=httpx.Response(200, content=(UP / f"vcpkg-{p}-portfile.cmake").read_bytes()))  # fmt: skip
            router.get(f"{raw}/ports/{p}/vcpkg.json").mock(
                return_value=httpx.Response(200, content=(UP / f"vcpkg-{p}.json").read_bytes()))  # fmt: skip
        async with HttpClient(sleep=no_sleep) as http:
            got = await reg.Registries(http).resolve([
                _u(UpstreamKind.VCPKG, "curl", baseline=BASELINE),
                _u(UpstreamKind.VCPKG, "fmt", baseline=BASELINE, version="10.2.1"),  # an override
                _u(UpstreamKind.VCPKG, "zlib", baseline=BASELINE, version=">=1.2.0"),  # below the baseline's
            ])  # fmt: skip
    curl_graph, (fmt,), zlib_graph = got.values()
    curl, *deps = curl_graph
    assert (curl.repo, curl.version, curl.ref) == ("curl/curl", "8.23.0", None)  # REF built by string(REPLACE)
    assert "couldn't be worked out" in curl.detail
    assert [(d.name, d.repo, d.ref, d.via.split(";")[0]) for d in deps] == [
        ("zlib", "madler/zlib", "v1.3.2", "a dependency of curl")
    ]  # host tools and helper ports left out
    assert (fmt.repo, fmt.version, fmt.ref) == ("fmtlib/fmt", "10.2.1", "10.2.1")  # REF "${VERSION}"
    assert (zlib_graph[0].version, zlib_graph[0].ref) == ("1.3.2", "v1.3.2")


async def test_conan_from_the_conancenter_remote(no_sleep: Any) -> None:
    base = f"{reg.CONAN_REMOTE}/zlib/1.3.1/_/_"
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{base}/latest").mock(
            return_value=httpx.Response(200, content=(UP / "conan-zlib-1.3.1-latest.json").read_bytes()))  # fmt: skip
        router.get(f"{base}/revisions/cac0f6daea041b0ccf42934163defb20/files/conan_export.tgz").mock(
            return_value=httpx.Response(200, content=(UP / "conan-zlib-1.3.1-export.tgz").read_bytes()))  # fmt: skip
        router.get(f"{reg.CONAN_REMOTE}/inhouse/2.0/_/_/latest").mock(return_value=httpx.Response(404))
        async with HttpClient(sleep=no_sleep) as http:
            got = await reg.Registries(http).resolve([_u(UpstreamKind.CONAN, "zlib", version="1.3.1"),
                                                      _u(UpstreamKind.CONAN, "inhouse", version="2.0")])  # fmt: skip
    (z,), (i,) = got.values()
    assert (z.repo, z.ref, z.via) == ("madler/zlib", "v1.3.1", "ConanCenter recipe")
    assert i.repo is None and "isn't on ConanCenter" in i.detail


def test_yaml_block() -> None:
    text = (
        'sources:\n  "1.3":\n    url: "https://a/1.3"\n  1.3.1:\n    url:\n      - "https://b/1.3.1"\n'
        "patches:\n  1.3.1: []\n"
    )
    assert reg.yaml_block(text, "sources", "1.3.1") == '    url:\n      - "https://b/1.3.1"'
    assert reg.yaml_block(text, "sources", "9") is None


def test_upstream_unchecked_says_how_far_it_got() -> None:
    known = upstream_unchecked(_u(UpstreamKind.SUBMODULE, "z", host="github.com", repo="madler/zlib", ref="abc1234"))
    assert known.reason is Unchecked.UPSTREAM_NO_CHECK and known.detail == "github.com/madler/zlib at abc1234"
    noref = upstream_unchecked(_u(UpstreamKind.VCPKG, "curl", host="github.com", repo="curl/curl", version="8.23.0",
                                  via="vcpkg port", detail="the port's tag couldn't be worked out"))  # fmt: skip
    assert noref.reason is Unchecked.UPSTREAM_NO_REF
    assert noref.detail == "github.com/curl/curl at version 8.23.0; the port's tag couldn't be worked out (vcpkg port)"
    unknown = upstream_unchecked(_u(UpstreamKind.CONAN, "x", version="1", detail="x 1 isn't on ConanCenter"))
    assert (unknown.reason, unknown.version, unknown.ecosystem) == (Unchecked.UPSTREAM_UNKNOWN, "1", "Conan package")


def test_vcpkg_overlay_ports_come_from_their_own_portfile(tmp_path: Path) -> None:
    files = {
        "vcpkg.json": json.dumps({"name": "app", "builtin-baseline": BASELINE, "dependencies": ["mylib", "fmt"]}),
        "ports/mylib/vcpkg.json": json.dumps({"name": "mylib", "version": "2.1.0", "dependencies": ["zlib"]}),
        "ports/mylib/portfile.cmake": "vcpkg_from_github(\n  OUT_SOURCE_PATH SOURCE_PATH\n  REPO Acme/MyLib\n"
        "  REF v${VERSION}\n)\n",
    }
    for f, text in files.items():
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text(text)
    got = {(u.name, u.source): u for u in up.detect(tmp_path, include_ignored=True).upstreams}
    assert set(got) == {
        ("fmt", "vcpkg.json"),
        ("mylib", "ports/mylib/portfile.cmake"),
        ("zlib", "ports/mylib/vcpkg.json"),
    }
    own = got[("mylib", "ports/mylib/portfile.cmake")]
    assert (own.repo, own.ref, own.version, own.via) == ("acme/mylib", "v2.1.0", "2.1.0", "the project's own port")
    assert got[("zlib", "ports/mylib/vcpkg.json")].baseline == BASELINE  # the project's baseline


@pytest.mark.parametrize(
    ("name", "text"),
    [("vcpkg.json", "[]"), ("vcpkg.json", '{"dependencies": [1]}'), ("vcpkg.json", '{"dependencies": "zlib"}'),
     ("conan.lock", "[1]"), ("conan.lock", "{not json")],
)  # fmt: skip
def test_malformed_manifests_are_reported_not_a_crash(tmp_path: Path, name: str, text: str) -> None:
    (tmp_path / name).write_text(text)
    det = up.detect(tmp_path, include_ignored=True)
    assert not det.upstreams and [(u.reason, u.source) for u in det.unresolved] == [
        (Unchecked.LOCKFILE_UNREADABLE, name)]  # fmt: skip


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_a_repos_config_cant_run_commands(tmp_path: Path) -> None:
    p = _repo(tmp_path)
    marker = tmp_path / "PWNED"
    _git(p, "config", "core.fsmonitor", f"touch {marker}")
    (p / "CMakeLists.txt").write_text("project(x)\n")
    up.detect(p)
    assert not marker.exists()


def test_two_sources_with_one_name_are_both_reported() -> None:
    from limbowatch.models import Inventory as Inv
    from limbowatch.watch.candidates import Index
    from limbowatch.watch.scan import Shared, assess

    a = Upstream(
        kind=UpstreamKind.EXTERNALPROJECT, name="zlib", source="a/CMakeLists.txt", url="https://zlib.net/a.tgz"
    )
    b = a.model_copy(update={"source": "b/CMakeLists.txt", "url": "https://zlib.net/b.tgz"})
    res = assess(Inv(upstreams=(a, b)), Shared(Index(), upstream_check=False))
    assert sorted(u.source for u in res.unresolved) == ["a/CMakeLists.txt", "b/CMakeLists.txt"]


def test_bazel_module_includes_and_scp_relative_submodules() -> None:
    assert up._wanted("deps.MODULE.bazel")
    assert up._relative_url("../../other/lib.git", "git@github.com:o/super.git") == "ssh://github.com/other/lib.git"
    assert up.locate("https://www.github.com/O/R") == up.Located("github.com", "o/r", None)


async def test_registry_edges(no_sleep: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """What each registry says when it can't name a repo and tag: always a reason, never a silent drop."""
    raw = f"{reg.RAW}/{reg.VCPKG}/{BASELINE}"
    base = {"default": {"site": {"baseline": "1.0"}, "pinned": {"baseline": "2.0"}, "graph": {"baseline": "1.0"},
                        "dep": {"baseline": "1.0"}, "gone": {"baseline": "1.0"}}}  # fmt: skip
    with respx.mock(assert_all_called=False) as router:
        gitsrc = {"type": "git_repository", "remote": "https://github.com/o/git.git", "commit": "a" * 40}
        router.get(f"{reg.BCR}/git/1.0/source.json").mock(return_value=httpx.Response(200, json=gitsrc))
        router.get(f"{reg.BCR}/meta/1.0/source.json").mock(return_value=httpx.Response(
            200, json={"url": "https://example.org/meta-1.0.tar.gz"}))  # fmt: skip
        router.get(f"{reg.BCR}/meta/metadata.json").mock(return_value=httpx.Response(
            200, json={"repository": ["github:O/Meta"]}))  # fmt: skip
        router.get(f"{reg.BCR}/site/1.0/source.json").mock(return_value=httpx.Response(
            200, json={"url": "https://example.org/site-1.0.tar.gz"}))  # fmt: skip
        router.get(f"{reg.BCR}/site/metadata.json").mock(return_value=httpx.Response(404))
        router.get(f"{reg.RAW}/{reg.VCPKG}/bad/versions/baseline.json").mock(return_value=httpx.Response(404))
        router.get(f"{raw}/versions/baseline.json").mock(return_value=httpx.Response(200, json=base))
        dl = 'vcpkg_download_distfile(A URLS "https://example.org/site-${VERSION}.tgz" FILENAME x)'
        router.get(f"{raw}/ports/site/portfile.cmake").mock(return_value=httpx.Response(200, text=dl))
        router.get(f"{raw}/ports/pinned/portfile.cmake").mock(return_value=httpx.Response(
            200, text=f"vcpkg_from_github(OUT_SOURCE_PATH S REPO o/pinned REF {'b' * 40})"))  # fmt: skip
        router.get(f"{raw}/ports/gone/portfile.cmake").mock(return_value=httpx.Response(404))
        router.get(f"{raw}/ports/graph/portfile.cmake").mock(return_value=httpx.Response(
            200, text="vcpkg_from_github(OUT_SOURCE_PATH S REPO o/graph REF v${VERSION})"))  # fmt: skip
        router.get(f"{raw}/ports/graph/vcpkg.json").mock(return_value=httpx.Response(
            200, json={"dependencies": ["dep", {"name": "tool", "host": True}]}))  # fmt: skip
        router.get(f"{raw}/ports/dep/portfile.cmake").mock(return_value=httpx.Response(
            200, text="vcpkg_from_github(OUT_SOURCE_PATH S REPO o/dep REF v${VERSION})"))  # fmt: skip
        router.get(f"{raw}/ports/dep/vcpkg.json").mock(
            return_value=httpx.Response(200, json={"dependencies": ["more"]})
        )
        router.get(url__startswith=f"{reg.CONAN_REMOTE}/web/").mock(side_effect=[
            httpx.Response(200, json={"revision": "r1"}), httpx.Response(200, content=b"not a tarball")])  # fmt: skip
        router.get(url__regex=r".*/ports/[^/]+/vcpkg\.json$").mock(return_value=httpx.Response(404))  # the rest
        monkeypatch.setattr(reg, "MAX_VCPKG_PORTS", 1)
        async with HttpClient(sleep=no_sleep) as http:
            got = await reg.Registries(http).resolve([
                _u(UpstreamKind.BAZEL_MODULE, "git", version="1.0"),
                _u(UpstreamKind.BAZEL_MODULE, "meta", version="1.0"),
                _u(UpstreamKind.BAZEL_MODULE, "site", version="1.0"),
                _u(UpstreamKind.VCPKG, "x", baseline="bad"),
                _u(UpstreamKind.VCPKG, "site", baseline=BASELINE),
                _u(UpstreamKind.VCPKG, "pinned", baseline=BASELINE, version="2.0.0"),  # 2.0.0 is the baseline's 2.0
                _u(UpstreamKind.VCPKG, "missing", baseline=BASELINE),
                _u(UpstreamKind.VCPKG, "gone", baseline=BASELINE),
                _u(UpstreamKind.VCPKG, "graph", baseline=BASELINE),
                _u(UpstreamKind.CONAN, "web", version="1.0"),
                _u(UpstreamKind.BAZEL_MODULE, "nover"),  # nothing to look up
            ])  # fmt: skip
    r = {u.name: rs for u, rs in got.items() if not (u.kind is UpstreamKind.VCPKG and u.name == "site")}
    assert (r["git"][0].repo, r["git"][0].ref_is_commit) == ("o/git", True)
    assert (r["meta"][0].repo, r["meta"][0].ref, r["meta"][0].via) == (
        "o/meta",
        None,
        "Bazel Central Registry metadata",
    )
    assert "isn't on a forge" in r["site"][0].detail and r["site"][0].repo is None
    assert "couldn't be read" in r["x"][0].detail
    vsite = next(us for u, us in got.items() if u.kind is UpstreamKind.VCPKG and u.name == "site")[0]
    assert vsite.detail == "the port downloads from a site, not a repository"  # no deps: not truncated
    assert r["pinned"][0].ref == "b" * 40  # 2.0.0 is the same version as the baseline's 2.0 (F-142)
    assert "no port missing" in r["missing"][0].detail and "couldn't be read" in r["gone"][0].detail
    graph = r["graph"]
    assert [g.name for g in graph] == ["graph"] and "more than 1 ports" in graph[0].detail  # dep left out, said
    assert r["web"][0].repo is None and "names no source URL" in r["web"][0].detail
    assert r["nover"] == [_u(UpstreamKind.BAZEL_MODULE, "nover")]


def test_installed_packages_and_caches_arent_walked(tmp_path: Path) -> None:
    for f in (".venv/lib/site-packages/x/catch2/CMakeLists.txt", "venv/x/third_party/jq/LICENSE",
              "third_party/real/LICENSE"):  # fmt: skip
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text("FetchContent_Declare(c GIT_REPOSITORY https://github.com/o/c GIT_TAG v1)\n")
    det = up.detect(tmp_path, include_ignored=True)
    assert det.upstreams == [] and [u.source for u in det.unresolved] == ["third_party/real"]


def test_line_numbers_stay_fast_on_huge_cmake_files() -> None:
    import time

    text = "set(X 1)\n" * 70_000 + "FetchContent_Declare(z GIT_REPOSITORY https://github.com/o/z GIT_TAG v1)\n"
    t0 = time.monotonic()
    (u,) = up.cmake(text, "big.cmake", up.cmake_variables([text]))
    assert u.line == 70_001 and time.monotonic() - t0 < 5


async def test_vcpkg_overrides_apply_to_the_ports_pulled_in(no_sleep: Any) -> None:
    raw = f"{reg.RAW}/{reg.VCPKG}/{BASELINE}"
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{raw}/versions/baseline.json").mock(return_value=httpx.Response(
            200, json={"default": {"curl": {"baseline": "8.0"}, "zlib": {"baseline": "1.3.2"}}}))  # fmt: skip
        for port, deps in (("curl", ["zlib"]), ("zlib", [])):
            router.get(f"{raw}/ports/{port}/vcpkg.json").mock(return_value=httpx.Response(
                200, json={"dependencies": deps}))  # fmt: skip
            router.get(f"{raw}/ports/{port}/portfile.cmake").mock(return_value=httpx.Response(
                200, text=f"vcpkg_from_github(OUT_SOURCE_PATH S REPO o/{port} REF v${{VERSION}})"))  # fmt: skip
        root = _u(UpstreamKind.VCPKG, "curl", baseline=BASELINE, overrides=(("zlib", "1.2.13"),))
        async with HttpClient(sleep=no_sleep) as http:
            (graph,) = (await reg.Registries(http).resolve([root])).values()
    assert [(g.name, g.version, g.ref) for g in graph] == [("curl", "8.0", "v8.0"), ("zlib", "1.2.13", "v1.2.13")]
