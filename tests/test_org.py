"""Org-wide mode (`limbowatch watch`): listing groups and orgs, cloning safely, one poll per upstream repo.

Listings are recorded from gitlab.com (gitlab-org/cluster-integration) and codeberg.org (forgejo), trimmed to
the fields used, on 2026-11-10 (FINDINGS F-129).
"""

from __future__ import annotations

import base64
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from conftest import load
from limbowatch.hosts import HostKind, Listing, Project, Skip, SourceError, excluded, git_project, safe_path, split_url
from limbowatch.hosts import git as git_host
from limbowatch.hosts.gitea import list_org
from limbowatch.hosts.gitlab import list_group
from limbowatch.http import HttpClient
from limbowatch.models import Dependency, Inventory
from limbowatch.watch import org, org_output, output
from test_match import _zip, rec

NOW = datetime(2026, 11, 10, tzinfo=UTC)
GL = "https://gitlab.com"


async def test_gitlab_group_pages_and_skips(no_sleep: Any) -> None:
    rows = load("hosts/gitlab_group_projects.json")
    nxt = f"{GL}/api/v4/groups/gitlab-org%2Fcluster-integration/projects?page=2&per_page=4"
    with respx.mock(assert_all_mocked=True) as router:
        first = router.get(url__startswith=f"{GL}/api/v4/groups/gitlab-org%2Fcluster-integration/projects")
        first.mock(side_effect=[httpx.Response(200, json=rows[:4], headers={"link": f'<{nxt}>; rel="next"'}),
                                httpx.Response(200, json=rows[4:])])  # fmt: skip
        async with HttpClient(sleep=no_sleep) as http:
            ls = await list_group(http, GL, "gitlab-org/cluster-integration", "tok")
    assert str(first.calls[1].request.url) == nxt  # the next link as given, every parameter in it
    q = first.calls[0].request.url.params
    assert q["include_subgroups"] == "true" and q["with_shared"] == "false"  # not projects shared in (F-129)
    assert first.calls[0].request.headers["authorization"] == "Bearer tok"
    assert ls.error is None
    assert [p.path.rsplit("/", 1)[-1] for p in ls.projects] == [
        "helm-install-image", "auto-build-image", "auto-deploy-image", "k3s-gitlab-ci",
        "cluster-applications"]  # fmt: skip
    assert [(p.path.rsplit("/", 1)[-1], why) for p, why in ls.skipped] == [
        ("example-cluster-applications", Skip.ARCHIVED), ("helm-stable-archive", Skip.ARCHIVED)]  # fmt: skip
    p = ls.projects[3]
    assert p.name == "gitlab.com/gitlab-org/cluster-integration/test-utils/k3s-gitlab-ci" and p.public is True
    assert p.clone_url.endswith("/test-utils/k3s-gitlab-ci.git")


async def test_gitlab_listing_errors_are_never_an_empty_group(no_sleep: Any) -> None:
    with respx.mock(assert_all_mocked=True) as router:
        router.get(url__startswith=f"{GL}/api/v4/groups/").mock(
            return_value=httpx.Response(404, json={"message": "404 Group Not Found"}))  # fmt: skip
        async with HttpClient(sleep=no_sleep) as http:
            ls = await list_group(http, GL, "private-group", None)
    assert ls.projects == [] and ls.error and "404 Group Not Found" in ls.error and "read_api" in ls.error


async def test_pagination_never_leaves_the_host(no_sleep: Any) -> None:
    with respx.mock(assert_all_mocked=True) as router:
        away = {"link": '<https://evil.example/x>; rel="next"'}
        router.get(url__startswith=f"{GL}/api/v4/groups/").mock(return_value=httpx.Response(200, json=[], headers=away))
        async with HttpClient(sleep=no_sleep) as http:
            ls = await list_group(http, GL, "g", "tok")
    assert ls.error and "pagination left" in ls.error  # this source fails; the run goes on


async def test_gitea_org_or_user(no_sleep: Any) -> None:
    rows = load("hosts/forgejo_org_repos.json")
    cb = "https://codeberg.org"
    with respx.mock(assert_all_mocked=True) as router:
        org_route = router.get(f"{cb}/api/v1/orgs/forgejo/repos").mock(return_value=httpx.Response(200, json=rows))
        router.get(f"{cb}/api/v1/orgs/someone/repos").mock(return_value=httpx.Response(404, json={}))
        user = router.get(f"{cb}/api/v1/users/someone/repos").mock(return_value=httpx.Response(200, json=rows[2:]))
        async with HttpClient(sleep=no_sleep) as http:
            ls = await list_org(http, cb, "forgejo", "tok")
            as_user = await list_org(http, cb, "someone", None)
    assert org_route.calls[0].request.headers["authorization"] == "token tok"
    assert [p.path for p in ls.projects] == ["forgejo/forgejo", "forgejo/website"]
    assert [(p.path, why) for p, why in ls.skipped] == [("forgejo/gitea-open-letter", Skip.ARCHIVED),
                                                        ("forgejo/discussions", Skip.EMPTY)]  # fmt: skip
    assert user.called and [p.path for p in as_user.projects] == ["forgejo/forgejo", "forgejo/website"]
    assert "authorization" not in user.calls[0].request.headers


def test_source_urls_and_paths() -> None:
    assert split_url("https://gitlab.example.com/acme/backend") == ("https://gitlab.example.com", "acme/backend")
    assert split_url("https://gitlab.com/groups/acme") == ("https://gitlab.com", "acme")  # the group page's URL
    assert split_url("acme/backend", "https://gitlab.com/") == ("https://gitlab.com", "acme/backend")
    for bad in ("acme/../etc", "https://u:secret@gitlab.com/acme", "acme"):
        with pytest.raises(SourceError) as e:
            split_url(bad) if bad != "acme" else split_url(bad, None)
        assert "secret" not in str(e.value)
    assert safe_path("/a/b.c/d-e_f/") == "a/b.c/d-e_f"
    with pytest.raises(SourceError):
        safe_path("a/./b")
    p = git_project("https://git.example.org/team/tool.git")
    assert (p.kind, p.path, p.name, p.public) == (HostKind.GIT, "team/tool", "git.example.org/team/tool", None)
    with pytest.raises(SourceError):
        git_project("git@github.com:team/tool.git")  # ssh: no way to scope a token header
    assert excluded(p, ["team/*"]) and excluded(p, ["git.example.org/*"]) and not excluded(p, ["other/*"])


def test_clone_keeps_the_token_off_the_command_line() -> None:
    p = Project(HostKind.GITLAB, "https://gitlab.example.com", "a/b", "https://gitlab.example.com/a/b.git", "")
    cmd = git_host.command(p, Path("/tmp/x"))
    env = git_host.environment(p, "glpat-secret", base={"GIT_CONFIG_COUNT": "1"})
    assert not any("secret" in c for c in cmd)
    assert "core.symlinks=false" in cmd and "--depth" in cmd and "--no-recurse-submodules" in cmd
    assert env["GIT_CONFIG_COUNT"] == "2"  # appended after the caller's own
    assert env["GIT_CONFIG_KEY_1"] == "http.https://gitlab.example.com/.extraHeader"
    value = env["GIT_CONFIG_VALUE_1"].removeprefix("Authorization: Basic ")
    assert base64.b64decode(value).decode() == "oauth2:glpat-secret"  # GitLab's form (F-130)
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert "GIT_CONFIG_KEY_0" not in git_host.environment(p, None, base={})


def test_clone_of_a_local_repo(tmp_path: Path) -> None:
    """The real git command, on a local repo: a symlink comes out as a plain file holding its target."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "go.mod").write_text("module example.com/x\n")
    (src / "package-lock.json").symlink_to("/etc/passwd")

    def git(*a: str) -> None:
        subprocess.run(["git", "-C", str(src), *a], check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    git("add", ".")
    git("-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-qm", "x")
    p = Project(HostKind.GIT, "file://", "src", f"file://{src}", "")
    commit = git_host.clone(p, tmp_path / "out", None)
    assert len(commit) == 40 and (tmp_path / "out/go.mod").exists()
    link = tmp_path / "out/package-lock.json"
    assert not link.is_symlink() and link.read_text() == "/etc/passwd"
    with pytest.raises(git_host.CloneError):
        git_host.clone(Project(HostKind.GIT, "file://", "x", f"file://{tmp_path}/nope", ""), tmp_path / "o2", None)


def _proj(path: str) -> Project:
    return Project(HostKind.GITLAB, GL, path, f"{GL}/{path}.git", f"{GL}/{path}", public=False)


def _dep(eco: str, name: str, version: str, source: str = "package-lock.json") -> Dependency:
    return Dependency(ecosystem=eco, name=name, version=version, source=source, line=3)


async def test_one_poll_per_upstream_repo_for_all_projects(no_sleep: Any) -> None:
    feed = _zip(rec("GHSA-10", "lodash/lodash", ("npm", "lodash", "< 4.17.21", "4.17.21")))
    a, b, broken, old = _proj("acme/a"), _proj("acme/b"), _proj("acme/broken"), _proj("acme/old")
    listings = [Listing(f"{GL}/acme", HostKind.GITLAB, [a, b, broken, a], [(old, Skip.ARCHIVED)])]
    invs = {
        "acme/a": Inventory(dependencies=(_dep("npm", "lodash", "4.17.20"), _dep("npm", "left-pad", "1.0.0"))),
        "acme/b": Inventory(dependencies=(_dep("npm", "left-pad", "1.0.0"), _dep("npm", "lodash", "4.17.21"))),
    }
    cloned: list[str] = []

    def clone(p: Project, dest: Path, token: str | None) -> str:
        if p.path == "acme/broken":
            raise git_host.CloneError("fatal: repository not found")
        cloned.append(p.path)
        dest.mkdir(parents=True)
        (dest / "marker").write_text(p.path)
        return "c0ffee"

    def inventory(path: Path) -> Inventory:
        return invs[(path / "marker").read_text()]

    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:

        def deps_dev(name: str, repo: str) -> None:
            src = {"projectKey": {"id": f"github.com/{repo}"}, "relationProvenance": "UNVERIFIED_METADATA",
                   "relationType": "SOURCE_REPO"}  # fmt: skip
            router.get(url__startswith=f"https://api.deps.dev/v3/systems/npm/packages/{name}/").mock(
                return_value=httpx.Response(200, json={"relatedProjects": [src]}))  # fmt: skip

        deps_dev("lodash", "lodash/lodash")
        deps_dev("left-pad", "left-pad/left-pad")
        poll = router.get(url__startswith="https://api.github.com/repos/left-pad/left-pad/security-advisories")
        poll.mock(return_value=httpx.Response(200, json=[]))
        async with HttpClient(sleep=no_sleep) as http:
            w = await org.run(listings, http, feed_zip=feed, watchlist={"lodash/lodash": "2026-11-09T00:00:00Z"},
                              now=NOW, inventory=inventory, token=None, clone=clone)  # fmt: skip
    assert sorted(cloned) == ["acme/a", "acme/b"]  # listed twice, cloned once
    assert poll.call_count == 1  # left-pad's repo serves both projects
    by = {c.project.path: c for c in w.checked}
    assert by["acme/broken"].error == "clone failed: fatal: repository not found" and by["acme/broken"].result is None
    assert [f.ghsa_id for f in by["acme/a"].result.findings] == ["GHSA-10"]  # type: ignore[union-attr]
    assert by["acme/b"].result.findings == []  # type: ignore[union-attr]
    assert by["acme/a"].result.stats["repos"] == 2  # type: ignore[union-attr]
    assert w.skipped == [(old, Skip.ARCHIVED)]
    assert w.stats["repos"] == 2 and w.stats["repos_polled"] == 1 and w.stats["unique_dependencies"] == 3

    # The org report: exit 1 for a project's findings; the broken project and the archived one are listed
    def rep(c: org.Checked) -> output.Report | None:
        r = c.result
        return output.Report(r.findings, r.unresolved, r.stats, "test", fail_on="high") if r else None

    entries = [org_output.Entry(c.project, rep(c), c.commit, c.error) for c in w.checked]
    o = org_output.OrgReport(entries, listings, w.skipped, w.stats, fail_on="high")
    assert o.exit_code == 1 and org_output.verdict(o)[0] == "FAILED"
    text = org_output.table(o)
    assert "Couldn't be checked (1):" in text and "acme/broken" in text and "archived" in text
    assert "━━ gitlab.com/acme/a" in text and "GHSA-10" in text
    assert text.count("GitHub repository security advisories") == 1  # the attribution, once
    doc = json.loads(org_output.as_json(o))
    assert doc["summary"]["with_findings"] == 1 and doc["summary"]["couldnt_be_checked"] == 1
    assert doc["projects"][0]["report"]["findings"][0]["ghsa_id"] == "GHSA-10"
    md = org_output.markdown(o)
    assert "### [gitlab.com/acme/a]" in md and "#### To fix" in md and "_Advisory data:" in md
    assert md.count("_Advisory data:") == 1

    # A source that lists nothing is an error: Gitea shows a private org as empty without a token (F-129)
    async with HttpClient(sleep=no_sleep) as http:
        empty = Listing("https://codeberg.org/private-org", HostKind.GITEA)
        w2 = await org.run([empty], http, feed_zip=feed, watchlist={}, now=NOW, inventory=inventory, token=None,
                           upstream_check=False, clone=clone)  # fmt: skip
    assert w2.errors and "private" in w2.errors[0]

    # A source that couldn't be listed makes the run an error, whatever was found
    o.listings = [*listings, Listing("https://gitlab.com/gone", HostKind.GITLAB, error="listing: HTTP 404")]
    assert o.exit_code == 2 and org_output.verdict(o)[0] == "ERROR"
