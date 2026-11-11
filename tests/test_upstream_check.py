"""Phase 6 steps 2-4 (PHASE0_PLAN §13.18, FINDINGS F-138): upstream versions and tags, the feed's GIT ranges for
advisories without a package, the tracker's tag lookup, and whether a pinned upstream source is affected."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from conftest import FIXTURES, load
from limbowatch.classify import assess
from limbowatch.models import AdvisoryPackage, CveLabel, Facts, MatchKind, RepoAdvisory, Upstream, UpstreamKind
from limbowatch.normalize import repo_advisory
from limbowatch.publish import Item
from limbowatch.publish.feed import by_ecosystem, git_ranges, git_versions, record
from limbowatch.sources.gitrefs import parse
from limbowatch.versions import UPSTREAM, UpstreamVersion, affected, tag_for, version_of_tag
from limbowatch.watch import upstream_check as uc
from limbowatch.watch.candidates import Candidate, Index, from_feed_record
from limbowatch.watch.gitgraph import GitGraph, _clone

C = {n: f"{n:x}" * 40 for n in range(1, 10)}  # fake full commit hashes
C = {k: v[:40] for k, v in C.items()}


@pytest.mark.parametrize(
    ("a", "b"),
    [("1.2.9", "1.2.10"), ("7.1.1", "7.1.1-38"), ("7.1.1-38", "7.1.1-40"), ("1.0.0-rc1", "1.0.0"),
     ("0.27.5-RC1", "0.27.5"), ("3.0.0-beta.2", "3.0.0-beta.10"), ("2024-07-02", "2024-11-01"), ("v1.2.3", "1.2.4")],
)  # fmt: skip
def test_upstream_versions_order(a: str, b: str) -> None:
    assert UpstreamVersion(a) < UpstreamVersion(b)
    assert UpstreamVersion("1.0") == UpstreamVersion("1.0.0") == UpstreamVersion("v1.0")


def test_upstream_ranges() -> None:
    spans = "10.6.1-10.6.27, 10.11.1-10.11.18"  # MariaDB's: spans, not pre-releases
    assert affected(UPSTREAM, "10.6.5", spans) is True and affected(UPSTREAM, "10.7.0", spans) is False
    assert (
        affected(UPSTREAM, "7.1.1-37", "< 7.1.1-38") is True and affected(UPSTREAM, "7.1.1-38", "< 7.1.1-38") is False
    )


def test_tags_and_versions() -> None:
    assert [version_of_tag(t) for t in ("v1.2.3", "curl-8_10_0", "release-22.1.8", "openssl-3.0.15", "nightly")] == [
        "1.2.3", "8.10.0", "22.1.8", "3.0.15", None]  # fmt: skip
    tags = {"v1.3.1": C[1], "bacnet-stack-1.6.0": C[2], "curl-8_10_0": C[3], "a-2.0": C[4], "b-2.0": C[5]}
    assert [tag_for(v, tags) for v in ("1.3.1", "1.6.0", "8.10.0", "2.0", "9")] == [
        "v1.3.1", "bacnet-stack-1.6.0", "curl-8_10_0", None, None]  # two tags, two commits: not guessed  # fmt: skip


def test_ls_remote_tags_are_peeled() -> None:
    listing = f"{C[1]}\trefs/tags/v1.0\n{C[2]}\trefs/tags/v1.0^{{}}\n{C[3]}\trefs/tags/light\n{C[4]}\tHEAD\n"
    assert parse(listing) == {"v1.0": C[2], "light": C[3]}


# --- the feed -------------------------------------------------------------------------------------------------------


def _item(pkgs: tuple[AdvisoryPackage, ...], git: dict[str, Any]) -> Item:
    adv = repo_advisory(load("repo_advisories_regexp2.json")[0], "dlclark/regexp2")
    adv = adv.model_copy(update={"repo": "madler/zlib", "packages": pkgs})
    f = Facts(ghsa_id=adv.ghsa_id, repo="madler/zlib", repo_state="published", reviewed=False)
    return Item(adv, f, assess(adv, f), "2026-11-11T00:00:00Z", git)


def test_unpackaged_advisories_get_git_ranges_where_every_version_has_a_tag() -> None:
    schema = json.loads((FIXTURES / "osv_schema.json").read_text())
    tagged = AdvisoryPackage(ecosystem="c", name="zlib", vulnerable_version_range=">= 1.2.0, < 1.3.1",
                             patched_versions="1.3.1")  # fmt: skip
    untagged = AdvisoryPackage(ecosystem="other", name="zlib", vulnerable_version_range="<= 0.9")
    assert git_versions(tagged) == {"1.2.0", "1.3.1"}
    git = {"1.2.0": ["v1.2.0", C[1]], "1.3.1": ["v1.3.1", C[2]], "0.9": None}
    rec = record(_item((tagged, untagged), git), "2026-11-11T00:00:00Z")
    jsonschema.validate(rec, schema)
    a, b = rec["affected"]
    assert "package" not in a and a["ranges"] == [{"type": "GIT", "repo": "https://github.com/madler/zlib",
                                                   "events": [{"introduced": C[1]}, {"fixed": C[2]}]}]  # fmt: skip
    assert a["database_specific"]["tags"] == {"1.2.0": "v1.2.0", "1.3.1": "v1.3.1"}
    assert a["database_specific"]["range_converted"] and a["database_specific"]["ecosystem_as_entered"] == "c"
    assert "ranges" not in b and b["database_specific"]["vulnerable_version_range"] == "<= 0.9"
    assert rec["database_specific"]["limbowatch"]["quality"] == {"names": "none", "ranges": "partly converted"}
    # the watcher reads the versions back, to match by repository
    back = from_feed_record(rec).adv.packages
    assert [(p.ecosystem, p.name, p.vulnerable_version_range) for p in back] == [
        ("c", "zlib", ">= 1.2.0, < 1.3.1"), ("other", "zlib", "<= 0.9")]  # fmt: skip
    zips = by_ecosystem([rec])
    assert zipfile.ZipFile(io.BytesIO(zips["GIT"])).namelist() == [f"{rec['id']}.json"]


def test_git_ranges_need_every_tag() -> None:
    p = AdvisoryPackage(ecosystem="c", name="x", vulnerable_version_range="< 2.0", patched_versions="2.0")
    assert git_ranges("o/x", p, {}) is None
    assert git_ranges("o/x", p, {"2.0": ["v2.0", "short"]}) is None  # not a full hash


# --- the tracker ----------------------------------------------------------------------------------------------------


async def test_tracker_resolves_tags_for_unpackaged_advisories(monkeypatch: pytest.MonkeyPatch, no_sleep: Any) -> None:
    from limbowatch import tracker as tr
    from limbowatch.http import HttpClient
    from limbowatch.store import Advisory, FactSnapshot, GitTag, Store

    store = Store()
    pkg = AdvisoryPackage(ecosystem="c", name="zlib", vulnerable_version_range="< 1.3.1", patched_versions="1.3.1")
    adv = RepoAdvisory(ghsa_id="GHSA-aaaa-bbbb-cccc", repo="madler/zlib", state="published", packages=(pkg,),
                       html_url="https://github.com/madler/zlib/security/advisories/GHSA-aaaa-bbbb-cccc")  # fmt: skip
    facts = Facts(ghsa_id=adv.ghsa_id, repo=adv.repo, repo_state="published", reviewed=False, in_osv=False)
    with store.session() as s:
        s.add(Advisory(ghsa_id=adv.ghsa_id, repo=adv.repo, data=adv.model_dump(mode="json"), first_seen="x",
                       last_seen="x"))  # fmt: skip
        s.add(FactSnapshot(ghsa_id=adv.ghsa_id, facts=facts.model_dump(mode="json"), facts_hash="h", observed_at="x"))
    asked: list[str] = []

    async def tags(url: str, timeout: float = 60) -> dict[str, str]:
        asked.append(url)
        return {"v1.3.1": C[2], "v1.3": C[1]}

    monkeypatch.setattr(tr.gitrefs, "tags", tags)
    async with HttpClient(sleep=no_sleep) as http:
        report = tr.RunReport(started_at="x")
        await tr.Tracker(store, http, tr.TrackerConfig()).resolve_git_tags(report)
        await tr.Tracker(store, http, tr.TrackerConfig()).resolve_git_tags(tr.RunReport(started_at="y"))
    assert asked == ["https://github.com/madler/zlib.git"]  # the second run has nothing left to look up
    with store.session() as s:
        (g,) = s.query(GitTag).all()
    assert g.versions == {"1.3.1": ["v1.3.1", C[2]]}
    assert report.git_tags == {"repos": 1, "listed": 1, "failed": 0, "versions": 1, "tagged": 1}


# --- the watcher ----------------------------------------------------------------------------------------------------


class FakeGraph:
    """main: C1 (v1.0) → C2 → C3 (v1.1) → C4 → C5 (v2.0); a branch off C3: C6 (v1.1.1) → C7."""

    def __init__(self) -> None:
        self.parents = {C[2]: C[1], C[3]: C[2], C[4]: C[3], C[5]: C[4], C[6]: C[3], C[7]: C[6]}
        self.tags = {"v1.0": C[1], "v1.1": C[3], "v2.0": C[5], "v1.1.1": C[6]}

    def commit(self, ref: str) -> str | None:
        return self.tags.get(ref) or (ref if ref in C.values() else None)

    def _ancestors(self, c: str) -> set[str]:
        out = {c}
        while c in self.parents:
            c = self.parents[c]
            out.add(c)
        return out

    def contains(self, ancestor: str, descendant: str) -> bool | None:
        return ancestor in self._ancestors(descendant)

    def describe(self, commit: str) -> str | None:
        anc = self._ancestors(commit)
        return next((t for t, c in sorted(self.tags.items(), key=lambda x: x[0], reverse=True) if c in anc), None)


def _u(**kw: Any) -> Upstream:
    return Upstream(kind=UpstreamKind.SUBMODULE, name="third_party/x", source=".gitmodules", host="github.com",
                    repo="o/x", **kw)  # fmt: skip


def _pkg(rng: str | None = None, fix: str | None = None) -> AdvisoryPackage:
    return AdvisoryPackage(ecosystem="c", name="x", vulnerable_version_range=rng, patched_versions=fix)


@pytest.mark.parametrize(
    ("commit", "rng", "fix", "want"),
    [
        (C[4], "< 2.0", "2.0", True),  # on main, before v2.0
        (C[5], "< 2.0", "2.0", False),  # the fix release itself
        (C[2], ">= 1.1, < 2.0", "2.0", False),  # older than the affected range
        (C[7], "< 2.0", "2.0", None),  # a branch without v2.0: possibly
        (C[7], "< 1.1.1", "1.1.1", False),  # contains the branch's fix
        (C[4], None, None, None),  # the advisory gives no versions
    ],
)  # fmt: skip
def test_verdict_from_the_commit_graph(commit: str, rng: str | None, fix: str | None, want: bool | None) -> None:
    g = FakeGraph()
    pn = uc.pin(_u(ref=commit, ref_is_commit=True), g)
    assert uc.verdict(pn, _pkg(rng, fix), g)[0] is want


def test_pin_by_tag_and_version() -> None:
    g = FakeGraph()
    assert uc.pin(_u(ref="v1.1", version=None), g) == uc.Pin(C[3], "1.1", "v1.1")
    bazel = _u(version="2.0").model_copy(update={"kind": UpstreamKind.BAZEL_MODULE})
    assert uc.pin(bazel, g) == uc.Pin(C[5], "2.0", "2.0")  # the version found among the tags
    assert uc.pin(_u(ref=C[4], ref_is_commit=True), g).version == "1.1"  # the nearest tag
    no_graph = uc.pin(_u(ref="curl-8_10_0"), None)
    assert (no_graph.commit, no_graph.version) == (None, "8.10.0")
    assert uc.by_version("8.10.0", _pkg("< 8.11.0", "8.11.0"))[0] is True


def _cand(gid: str, *pkgs: AdvisoryPackage, cves: tuple[str, ...] = ()) -> Candidate:
    adv = RepoAdvisory(ghsa_id=gid, repo="o/x", state="published", packages=pkgs, html_url=f"https://x/{gid}")
    return Candidate(adv, CveLabel.NONE, cves, "feed")


def test_findings_match_unpackaged_advisories_only_and_take_osv_by_commit() -> None:
    index = Index()
    for c in (
        _cand("GHSA-0001", _pkg("< 2.0", "2.0")),
        _cand("GHSA-0002", AdvisoryPackage(ecosystem="npm", name="x-bindings", vulnerable_version_range="< 9")),
        _cand("GHSA-0003", _pkg(">= 2.0", "3.0"), cves=("CVE-2026-1",)),
        _cand("GHSA-0004", _pkg("< 1.0", "1.0")),
    ):
        index.add(c)
    u = _u(ref=C[4], ref_is_commit=True)
    cands = uc.candidates(u, index)
    assert [c.adv.ghsa_id for c in cands] == ["GHSA-0001", "GHSA-0003", "GHSA-0004"]  # not the npm package's
    g = FakeGraph()
    got = {f.ghsa_id: f for f in uc.findings(u, uc.pin(u, g), cands, g, {"CVE-2026-1"})}
    assert set(got) == {"GHSA-0001", "GHSA-0003"}
    one = got["GHSA-0001"]
    assert (one.affected, one.match, one.dependency.name, one.dependency.version) == (
        True, MatchKind.UPSTREAM, "github.com/o/x", C[4][:12])  # fmt: skip
    assert one.dependency.purl == f"pkg:github/o/x@{C[4][:12]}" and one.dependency.note == "git submodule third_party/x"
    assert "older than v2.0" in one.evidence
    # out of its range by version, but OSV lists the commit under the CVE the advisory cites
    assert got["GHSA-0003"].affected is True and "OSV lists" in got["GHSA-0003"].evidence


async def test_check_reports_what_it_couldnt_check(no_sleep: Any) -> None:
    from limbowatch.http import HttpClient
    from limbowatch.models import Unchecked

    index = Index()
    index.add(_cand("GHSA-0001", _pkg("< 2.0", "2.0")))
    ups = [
        Upstream(kind=UpstreamKind.CONAN, name="y", source="conan.lock", detail="y 1 isn't on ConanCenter"),
        _u(ref="v1", ref_is_commit=False).model_copy(update={"host": "gitlab.com"}),
        _u(ref="v1").model_copy(update={"repo": "o/quiet"}),
        _u(),  # no ref or version, with an advisory in limbo
        _u(ref="v1").model_copy(update={"repo": "o/rate-limited"}),
    ]
    async with HttpClient(sleep=no_sleep) as http:
        got = await uc.check(http, ups, index, not_polled={"o/rate-limited"})
    reasons = [got[u].unchecked.reason if got[u].unchecked else None for u in ups]
    assert reasons == [Unchecked.UPSTREAM_UNKNOWN, Unchecked.UPSTREAM_OFF_GITHUB, None, Unchecked.UPSTREAM_NO_REF,
                       Unchecked.REPO_NOT_POLLED]  # fmt: skip
    assert "has 1 advisory in limbo" in (got[ups[3]].unchecked.detail if got[ups[3]].unchecked else "")


GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           **dict.fromkeys(("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"), "t"),
           **dict.fromkeys(("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"), "t@example.com")}  # fmt: skip


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_graph_from_a_commits_only_clone(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()

    def git(*a: str) -> str:
        return subprocess.run(["git", *a], cwd=src, check=True, capture_output=True, text=True, env=GIT_ENV).stdout

    git("init", "-q", "-b", "main")
    shas = []
    for i, tag in enumerate(("v1.0", None, "v1.1")):
        (src / "f").write_text(str(i))
        git("add", "f")
        git("commit", "-qm", str(i))
        shas.append(git("rev-parse", "HEAD").strip())
        if tag:
            git("tag", "-a", tag, "-m", tag)  # annotated, as zlib's are: peeled to the commit
    g = _clone(f"file://{src}", tmp_path / "x.git")
    assert isinstance(g, GitGraph)
    assert g.tags == {"v1.0": shas[0], "v1.1": shas[2]}
    assert g.commit(shas[1][:10]) == shas[1] and g.commit("nope") is None
    assert g.contains(shas[0], shas[1]) is True and g.contains(shas[2], shas[1]) is False
    assert g.describe(shas[1]) == "v1.0"
    assert _clone(f"file://{src}", tmp_path / "x.git") is not None  # an existing clone is fetched, not re-cloned
