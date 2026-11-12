"""GitHub as a host (Phase 7): the issue tracker, rate limits on writes, org and user listings, empty clones.

Responses are trimmed to the fields used, in the shapes observed on 2026-11-12 in limbowatch/limbowatch-e2e and
the limbowatch org (FINDINGS F-145 to F-147).
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from limbowatch.hosts import HostKind, Listing, Project, Skip
from limbowatch.hosts import git as git_host
from limbowatch.hosts import github as gh
from limbowatch.http import BudgetExhausted, HttpClient
from limbowatch.models import Inventory
from limbowatch.watch import issues, org, org_output, state, trackers
from limbowatch_cli import main as cli
from test_match import _zip
from test_output import finding

API = "https://api.github.com"
REPO = f"{API}/repos/acme/app"


def _body(f: Any = None) -> str:
    f = f or finding()
    return issues.body(state.entries([f], "t")[f.key] | {"key": f.key}, f.model_dump(mode="json"))


def _issue(n: int, body: str, state_: str = "open", labels: tuple[str, ...] = ("limbowatch",), **kw: Any) -> dict:
    return {"number": n, "state": state_, "labels": [{"name": x} for x in labels], "body": body, **kw}


# --- the tracker ---------------------------------------------------------------------------------------------


async def test_github_tracker_lifecycle(no_sleep: Any) -> None:
    page1 = [_issue(1, "made by hand")] + [_issue(100 + i, f"filler {i}") for i in range(98)]
    page1.append(_issue(7, _body()))
    page2 = [_issue(2, _body(), pull_request={"url": "x"}),  # a pull request carrying the label: skipped
             _issue(8, _body(finding(name="other", ghsa="GHSA-other")), "closed")]  # fmt: skip
    with respx.mock(assert_all_mocked=True) as r:
        r.get(REPO).mock(return_value=httpx.Response(200, json={"visibility": "private", "has_issues": True}))
        lst = r.get(f"{REPO}/issues").mock(side_effect=[httpx.Response(200, json=page1),
                                                         httpx.Response(200, json=page2)])  # fmt: skip
        create = r.post(f"{REPO}/issues").mock(return_value=httpx.Response(201, json=_issue(9, "", labels=(
            "limbowatch", "security"))))  # fmt: skip
        comment = r.post(f"{REPO}/issues/7/comments").mock(return_value=httpx.Response(201, json={}))
        patch = r.patch(f"{REPO}/issues/7").mock(return_value=httpx.Response(200, json={}))
        label = r.post(f"{REPO}/issues/7/labels").mock(return_value=httpx.Response(200, json=[]))
        async with HttpClient(sleep=no_sleep) as http:
            t = trackers.GitHub(http, "acme/app", "tok")
            await t.prepare()
            assert t.public is False
            found = await t.issues()
            assert sorted(i.number for i in found.values()) == [7, 8]
            assert found[finding().key].open and not found[finding(name="other", ghsa="GHSA-other").key].open
            made = await t.create("t", "b", ["limbowatch", "security"])
            assert made.number == 9 and made.labels == {"limbowatch", "security"}
            i7 = found[finding().key]
            await t.comment(i7, "hello")
            await t.set_open(i7, False)
            await t.set_open(i7, True)
            await t.add_labels(i7, ["limbowatch:visible"])
    assert lst.calls[0].request.url.params["labels"] == "limbowatch"
    assert lst.calls[0].request.url.params["state"] == "all" and lst.calls[1].request.url.params["page"] == "2"
    assert create.calls[0].request.headers["authorization"] == "Bearer tok"
    assert json.loads(create.calls[0].request.content) == {"title": "t", "body": "b",
                                                           "labels": ["limbowatch", "security"]}  # fmt: skip
    assert json.loads(comment.calls[0].request.content) == {"body": "hello"}
    assert [json.loads(c.request.content) for c in patch.calls] == [
        {"state": "closed", "state_reason": "completed"},
        {"state": "open", "state_reason": "reopened"},
    ]
    assert json.loads(label.calls[0].request.content) == {"labels": ["limbowatch:visible"]}
    assert i7.labels == {"limbowatch", "limbowatch:visible"} and i7.open


async def test_github_tracker_refuses_what_would_duplicate_or_fail(no_sleep: Any) -> None:
    with respx.mock(assert_all_mocked=True) as r:
        repo = r.get(REPO)
        async with HttpClient(sleep=no_sleep) as http:
            t = trackers.GitHub(http, "acme/app", "tok", "https://ghe.example/api/v3")
            assert t.api == "https://ghe.example/api/v3/repos/acme/app"
            t = trackers.GitHub(http, "acme/app", "tok")
            repo.mock(return_value=httpx.Response(200, json={"visibility": "public", "has_issues": False}))
            with pytest.raises(trackers.TrackerError, match="issues are disabled in acme/app"):
                await t.prepare()  # listing would answer 200 even so (F-147)
            for doc, public in (({"visibility": "public"}, True), ({"visibility": "internal"}, False),
                                ({"private": False}, True), ({}, True)):  # unknown: public  # fmt: skip
                repo.mock(return_value=httpx.Response(200, json=doc))
                await t.prepare()
                assert t.public is public, doc
            # GitHub drops labels for a token without push access (F-145): stop, or every run opens it again
            r.post(f"{REPO}/issues").mock(return_value=httpx.Response(201, json=_issue(5, "", labels=())))
            shut = r.patch(f"{REPO}/issues/5").mock(return_value=httpx.Response(200, json={}))
            with pytest.raises(trackers.TrackerError, match=r"without the 'limbowatch' label.*closed it and stopped"):
                await t.create("t", "b", ["limbowatch"])
            assert json.loads(shut.calls[0].request.content) == {"state": "closed", "state_reason": "not_planned"}
            r.post(f"{REPO}/issues/5/comments").mock(return_value=httpx.Response(
                404, json={"message": "Not Found"}))  # fmt: skip
            with pytest.raises(trackers.TrackerError, match="comment: HTTP 404 Not Found"):
                await t.comment(trackers.Issue(5, True, set()), "x")


# --- rate limits and spacing (F-146) -------------------------------------------------------------------------


async def test_github_writes_wait_out_rate_limits_and_are_spaced() -> None:
    slept: list[float] = []

    async def sleep(s: float) -> None:
        slept.append(s)

    with respx.mock() as r:
        secondary = httpx.Response(403, json={"message": "You have exceeded a secondary rate limit."})
        after = httpx.Response(429, headers={"retry-after": "7"})
        r.post(f"{REPO}/issues").mock(side_effect=[secondary, after, httpx.Response(201, json={})])
        r.post(f"{REPO}/issues/1/comments").mock(return_value=httpx.Response(201, json={}))
        r.get(f"{REPO}/forbidden").mock(return_value=httpx.Response(403, json={"message": "Resource not accessible"}))
        r.post("https://ghe.example/api/v3/x").mock(
            side_effect=[httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"})]
        )
        async with HttpClient(sleep=sleep, max_rate_limit_wait=600) as http:
            ok = await http.request("POST", f"{REPO}/issues", auth=None, json_body={})
            assert ok.status == 201
            assert 60.0 in slept and 8.0 in slept  # a minute for a secondary limit, retry-after + 1
            slept.clear()
            await http.request("POST", f"{REPO}/issues/1/comments", auth=None, json_body={})
            assert slept and 0 < slept[0] <= 1.0  # the next write waits for the spacing
            plain = await http.request("GET", f"{REPO}/forbidden", auth=None)
            assert plain.status == 403  # a permission error isn't a rate limit: no retry
            with pytest.raises(BudgetExhausted):  # Enterprise Server, by the caller's flag; reset too far away
                await http.request("POST", "https://ghe.example/api/v3/x", auth=None, github=True)


def test_github_wait_rules() -> None:
    from limbowatch.http import _github_wait

    assert _github_wait(httpx.Response(403, json={"message": "Bad credentials"}), 0) is None
    assert _github_wait(httpx.Response(403, headers={"retry-after": "soon"}), 0) == 60.0
    assert _github_wait(httpx.Response(403, text="secondary rate limit"), 2) == 240.0
    reset = _github_wait(httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "0"}), 0)
    assert reset == 5.0  # a reset in the past still waits a little


# --- planning and applying under limits ----------------------------------------------------------------------


def test_plan_caps_new_issues_most_severe_first_and_comments_first() -> None:
    fs = [finding(name=f"p{i}", ghsa=f"GHSA-{i}", sev=s) for i, s in enumerate(("low", "critical", "medium", None))]
    possible = finding(name="maybe", ghsa="GHSA-maybe", sev="critical")
    cur = state.entries([*fs, possible], "t")
    cur[possible.key]["affected"] = None  # a possible match: after the certain ones
    one = {f.key: f.model_dump(mode="json") for f in [*fs, possible]}
    old = finding(name="old", ghsa="GHSA-old")
    cur |= state.entries([old], "t")
    one[old.key] = old.model_dump(mode="json")
    existing = {old.key: trackers.Issue(3, True, {"limbowatch"}, {"key": old.key})}
    ch = [state.Change(old.key, state.ChangeKind.CHANGED, old.ghsa_id, "npm:old", ["CVE: CVE-2026-1"])]
    gone_issue = finding(name="gone", ghsa="GHSA-gone")
    existing[gone_issue.key] = trackers.Issue(4, True, {"limbowatch"}, {"key": gone_issue.key})
    acts = issues.plan(cur, one, existing, ch, {gone_issue.key: issues.Gone.FIXED}, issues.Policy(max_new=2), False)
    assert [a.kind for a in acts] == ["comment", "close", "create", "create", "later", "later", "later"]
    made = [a.title.split(":")[0] for a in acts if a.kind == "create"]
    assert made == ["[limbo] GHSA-1", "[limbo] GHSA-3"]  # critical, then unknown severity (ranked after high)
    assert [a.key for a in acts if a.kind == "later"][-1] == possible.key  # possible matches come last
    assert [a.kind for a in issues.plan(cur, one, {}, [], {}, issues.Policy(max_new=0), False)] == ["later"] * 6


class FakeTracker:
    name = "GitHub"
    public = False

    def __init__(self, fail_at: int | None = None, error: Exception | None = None) -> None:
        self.calls: list[str] = []
        self.fail_at, self.error = fail_at, error

    def _call(self, what: str) -> None:
        if self.fail_at is not None and len(self.calls) == self.fail_at:
            raise self.error or BudgetExhausted
        self.calls.append(what)

    async def prepare(self) -> None: ...

    async def issues(self) -> dict[str, trackers.Issue]:
        return {}

    async def create(self, title: str, body: str, labels: list[str]) -> trackers.Issue:
        self._call("create")
        return trackers.Issue(len(self.calls), True, set(labels))

    async def comment(self, issue: trackers.Issue, body: str) -> None:
        self._call(f"comment #{issue.number}")

    async def set_open(self, issue: trackers.Issue, is_open: bool) -> None:
        self._call(f"open={is_open} #{issue.number}")

    async def add_labels(self, issue: trackers.Issue, labels: list[str]) -> None:
        self._call(f"label #{issue.number}")


async def test_apply_stops_at_a_rate_limit_and_says_what_is_left() -> None:
    i1, i2 = trackers.Issue(1, True, set()), trackers.Issue(2, True, set())
    acts = [issues.Action("comment", "a", body="Changed: CVE.", issue=i1),
            issues.Action("comment", "b", body="Changed: severity.", issue=i2),
            issues.Action("create", "c", "t", "b", ["limbowatch"]), issues.Action("later", "d", "t2")]  # fmt: skip
    t = FakeTracker(fail_at=1)
    lines = await issues.apply(t, acts)  # type: ignore[arg-type]
    assert t.calls == ["comment #1"]
    assert lines[0] == "comment #1"
    assert lines[1].startswith("stopped: GitHub's rate limit; 1 issue change(s) left for the next run")
    assert lines[2] == "  #2: Changed: severity."  # a one-time comment: printed, never lost silently
    assert lines[3] == "1 more new issue(s) open on later runs (1 a run; --issues-max-new)"
    t2 = FakeTracker(fail_at=1, error=trackers.TrackerError("create issue: HTTP 410 gone"))
    with pytest.raises(
        trackers.TrackerError,
        match=r"HTTP 410 gone \(done before it: comment #1; comments not made: #2: Changed: severity\.\)",
    ):
        await issues.apply(t2, acts[:3])  # type: ignore[arg-type]
    t3 = FakeTracker(fail_at=0, error=trackers.TrackerError("boom"))
    with pytest.raises(trackers.TrackerError, match=r"^boom \(comments not made: #1: Changed: CVE\.\)$"):
        await issues.apply(t3, acts[:1])  # type: ignore[arg-type]


# --- listing an org or a user (F-146, F-147) -----------------------------------------------------------------


def _repo(name: str, **kw: Any) -> dict[str, Any]:
    full = f"acme/{name}"
    return {"full_name": full, "private": True, "visibility": "private", "archived": False, "disabled": False,
            "fork": False, "size": 0, "clone_url": f"https://github.com/{full}.git",
            "html_url": f"https://github.com/{full}", **kw}  # fmt: skip


def test_api_url() -> None:
    assert gh.api_url("https://github.com") == API
    assert gh.api_url("https://www.github.com/") == API
    assert gh.api_url("https://api.github.com") == API
    assert gh.api_url("https://ghe.example") == "https://ghe.example/api/v3"
    assert gh.api_url("https://ghe.example/api/v3/") == "https://ghe.example/api/v3"


async def test_org_listing_pages_and_skips(no_sleep: Any) -> None:
    nxt = f'<{API}/organizations/1/repos?type=all&per_page=100&page=2>; rel="next"'
    with respx.mock(assert_all_mocked=True) as r:
        first = r.get(f"{API}/orgs/acme/repos").mock(return_value=httpx.Response(200, headers={"link": nxt}, json=[
            _repo("app"), _repo("site", private=False, visibility="public"),
            _repo("ent", visibility="internal"), _repo("old", archived=True)]))  # fmt: skip
        r.get(f"{API}/organizations/1/repos").mock(return_value=httpx.Response(200, json=[
            _repo("off", disabled=True), _repo("fork", fork=True)]))  # fmt: skip
        async with HttpClient(sleep=no_sleep) as http:
            ls = await gh.list_org(http, "https://github.com", "acme", "tok")
    assert first.calls[0].request.headers["authorization"] == "Bearer tok"
    assert first.calls[0].request.url.params["type"] == "all"
    assert ls.error is None and ls.note is None and ls.kind is HostKind.GITHUB
    assert [(p.path, p.public) for p in ls.projects] == [("acme/app", False), ("acme/site", True),
                                                         ("acme/ent", False), ("acme/fork", False)]  # fmt: skip
    assert [(p.path, why) for p, why in ls.skipped] == [("acme/old", Skip.ARCHIVED), ("acme/off", Skip.NO_REPOSITORY)]
    assert ls.projects[0].name == "github.com/acme/app" and ls.projects[0].clone_url.endswith("acme/app.git")


async def test_user_listing_depends_on_whose_token(no_sleep: Any) -> None:
    with respx.mock(assert_all_mocked=True) as r:
        r.get(f"{API}/orgs/someone/repos").mock(return_value=httpx.Response(404, json={"message": "Not Found"}))
        me = r.get(f"{API}/user").mock(return_value=httpx.Response(200, json={"login": "Someone"}))
        mine = r.get(f"{API}/user/repos").mock(return_value=httpx.Response(200, json=[_repo("secret")]))
        theirs = r.get(f"{API}/users/someone/repos").mock(return_value=httpx.Response(200, json=[
            _repo("pub", private=False, visibility="public")]))  # fmt: skip
        async with HttpClient(sleep=no_sleep) as http:
            own = await gh.list_org(http, "https://github.com", "someone", "tok")
            me.mock(return_value=httpx.Response(200, json={"login": "other"}))
            other = await gh.list_org(http, "https://github.com", "someone", "tok")
            anon = await gh.list_org(http, "https://github.com", "someone", None)
    assert [p.path for p in own.projects] == ["acme/secret"] and own.note is None
    assert mine.calls[0].request.url.params["affiliation"] == "owner"
    assert [p.path for p in other.projects] == ["acme/pub"] and other.note and "public repositories only" in other.note
    assert anon.note == other.note and theirs.call_count == 2
    assert "authorization" not in theirs.calls[1].request.headers  # no token: nothing sent


async def test_listing_errors_are_never_an_empty_org(no_sleep: Any) -> None:
    with respx.mock(assert_all_mocked=True) as r:
        org_route = r.get(f"{API}/orgs/acme/repos")
        async with HttpClient(sleep=no_sleep, max_rate_limit_wait=60) as http:
            org_route.mock(return_value=httpx.Response(401, json={"message": "Bad credentials"}))
            bad = await gh.list_org(http, "https://github.com", "acme", "tok")
            org_route.mock(return_value=httpx.Response(200, json=[_repo("../../etc")]))
            unsafe = await gh.list_org(http, "https://github.com", "acme", "tok")
            org_route.mock(return_value=httpx.Response(200, headers={"link": '<https://evil.example/x>; rel="next"'},
                                                       json=[_repo("app")]))  # fmt: skip
            leaves = await gh.list_org(http, "https://github.com", "acme", "tok")
            org_route.mock(return_value=httpx.Response(
                403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"}))  # fmt: skip
            limited = await gh.list_org(http, "https://github.com", "acme", "tok")
    assert bad.error == "listing https://github.com/acme: HTTP 401 Bad credentials (a private org needs " \
                        "LIMBOWATCH_SOURCE_TOKEN with read access)"  # fmt: skip
    assert unsafe.error and "unexpected project path" in unsafe.error
    assert leaves.error and "pagination left" in leaves.error
    assert limited.error and "rate limit" in limited.error


def test_clone_auth_for_github() -> None:
    p = Project(HostKind.GITHUB, "https://github.com", "acme/app", "https://github.com/acme/app.git", "")
    env = git_host.environment(p, "ghp_secret", base={})
    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraHeader"
    value = env["GIT_CONFIG_VALUE_0"].removeprefix("Authorization: Basic ")
    assert base64.b64decode(value).decode() == "x-access-token:ghp_secret"


# --- org mode: empty repositories and partial listings -------------------------------------------------------


async def test_an_empty_clone_is_reported_not_checked(no_sleep: Any) -> None:
    a = Project(HostKind.GITHUB, "https://github.com", "acme/a", "https://github.com/acme/a.git", "", public=False)
    e = Project(HostKind.GITHUB, "https://github.com", "acme/empty", "https://github.com/acme/empty.git", "")
    ls = [Listing("https://github.com/acme", HostKind.GITHUB, [e, a], note="the token sees part")]

    def clone(p: Project, dest: Path, token: str | None) -> str:
        dest.mkdir(parents=True)
        return "" if p.path == "acme/empty" else "c0ffee"  # an empty repo clones with no HEAD (F-147)

    async with HttpClient(sleep=no_sleep) as http:
        w = await org.run(ls, http, feed_zip=_zip(), watchlist={}, now=datetime.now(UTC),
                          inventory=lambda _: Inventory(), token=None, upstream_check=False,
                          clone=clone)  # fmt: skip
    assert [c.project.path for c in w.checked] == ["acme/a"]
    assert w.skipped == [(e, Skip.EMPTY)]
    assert w.stats["projects"] == 1 and w.stats["projects_skipped"] == 1
    o = org_output.OrgReport([org_output.Entry(c.project, None, c.commit, "x") for c in w.checked], ls, w.skipped)
    assert "Sources listed in part (1):" in org_output.table(o) and "the token sees part" in org_output.table(o)
    assert json.loads(org_output.as_json(o))["sources"][0]["note"] == "the token sees part"
    assert "**Sources listed in part (1):**" in org_output.markdown(o)


# --- CLI ------------------------------------------------------------------------------------------------------


def test_github_org_arguments() -> None:
    assert cli._github_org("acme", "https://github.com") == ("https://github.com", "acme")
    assert cli._github_org("https://www.github.com/acme", "x") == ("https://github.com", "acme")
    assert cli._github_org("https://github.com/orgs/acme/repositories", "x") == ("https://github.com", "acme")
    assert cli._github_org("https://ghe.example/acme/", "x") == ("https://ghe.example", "acme")
    with pytest.raises(cli.hosts.SourceError):
        cli._github_org("https://github.com/acme/app", "x")


def test_github_token_note(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert cli._github_token_note(None) == "no LIMBOWATCH_SOURCE_TOKEN: public repositories only"
    assert cli._github_token_note("ghs_x") is None  # outside Actions: an app token installed where it's needed
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert "GITHUB_TOKEN" in (cli._github_token_note("ghs_x") or "")
    assert cli._github_token_note("ghp_pat") is None


def test_scan_rejects_an_unknown_tracker() -> None:
    from typer.testing import CliRunner

    r = CliRunner().invoke(cli.app, ["scan", ".", "--issues", "jira"])
    assert r.exit_code == 2 and "gitlab, gitea or github" in r.output.replace("\n", " ")


# --- end to end, offline: the CLI against a mocked GitHub ----------------------------------------------------

from test_e2e_upstream import mocked, project, run, world  # noqa: E402,F401  (world is a fixture)


def _gh_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LIMBOWATCH_ISSUES_TOKEN", "ghp_issues")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.delenv("GITHUB_API_URL", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)


def test_scan_issues_github_opens_then_closes(world: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    _gh_env(monkeypatch)
    state_file = world["tmp"] / "state.json"
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    with respx.mock(assert_all_called=False) as router:
        mocked(router)
        router.get(REPO).mock(return_value=httpx.Response(200, json={"visibility": "private", "has_issues": True}))
        router.get(f"{REPO}/issues").mock(return_value=httpx.Response(200, json=[]))
        create = router.post(f"{REPO}/issues").mock(return_value=httpx.Response(201, json=_issue(
            12, "", labels=("limbowatch", "security", "severity:high"))))  # fmt: skip
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--state", str(state_file), "--fail-on", "none",
                 "--issues", "github"])  # fmt: skip
    assert r.exit_code == 0, r.output
    assert "opened #12: [limbo] GHSA-c000-0000-0001" in r.output
    sent = json.loads(create.calls[0].request.content)
    assert create.calls[0].request.headers["authorization"] == "Bearer ghp_issues"
    assert sent["labels"] == ["limbowatch", "security", "severity:high"] and "<!-- limbowatch {" in sent["body"]

    # upgraded past the fix: the issue is commented on and closed
    q = world["tmp"] / "fixed"
    q.mkdir()
    p2 = project(q, world["tags"]["v1.2.0"])
    with respx.mock(assert_all_called=False) as router:
        mocked(router)
        router.get(REPO).mock(return_value=httpx.Response(200, json={"visibility": "private", "has_issues": True}))
        router.get(f"{REPO}/issues").mock(return_value=httpx.Response(200, json=[_issue(12, sent["body"])]))
        note = router.post(f"{REPO}/issues/12/comments").mock(return_value=httpx.Response(201, json={}))
        close = router.patch(f"{REPO}/issues/12").mock(return_value=httpx.Response(200, json={}))
        router.post(url__startswith="https://api.osv.dev/v1/vulns").mock(return_value=httpx.Response(404))
        router.get(url__startswith="https://api.osv.dev/v1/vulns").mock(return_value=httpx.Response(404))
        r = run(["scan", str(p2), "--cache", str(world["cache"]), "--state", str(state_file), "--fail-on", "none",
                 "--issues", "github"])  # fmt: skip
    assert r.exit_code == 0, r.output
    assert "close #12" in r.output and note.called
    assert json.loads(close.calls[0].request.content) == {"state": "closed", "state_reason": "completed"}


def test_scan_issues_github_in_a_public_repo_opens_nothing(
    world: dict[str, Any],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _gh_env(monkeypatch)
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    with respx.mock(assert_all_called=False) as router:
        mocked(router)
        router.get(REPO).mock(return_value=httpx.Response(200, json={"visibility": "public", "has_issues": True}))
        router.get(f"{REPO}/issues").mock(return_value=httpx.Response(200, json=[]))
        create = router.post(f"{REPO}/issues")
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--fail-on", "none", "--issues", "github"])
        assert not create.called
    assert "GitHub issues in acme/app are public; not opening new ones (--issues-public allows it)" in r.output
    # the dry run reads the tracker and says what it would do, with no token needed
    monkeypatch.delenv("LIMBOWATCH_ISSUES_TOKEN")
    with respx.mock(assert_all_called=False) as router:
        mocked(router)
        router.get(REPO).mock(return_value=httpx.Response(200, json={"visibility": "private", "has_issues": True}))
        router.get(f"{REPO}/issues").mock(return_value=httpx.Response(200, json=[]))
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--fail-on", "none", "--issues", "github",
                 "--issues-dry-run", "--issues-max-new", "0"])  # fmt: skip
    assert "would leave 1 new issue(s) for later runs (--issues-max-new)" in r.output, r.output
    # a rate limit while reading the tracker: nothing changes, and the scan still reports
    _gh_env(monkeypatch)
    with respx.mock(assert_all_called=False) as router:
        mocked(router)
        router.get(REPO).mock(return_value=httpx.Response(
            403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"}))  # fmt: skip
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--fail-on", "none", "--issues", "github"])
    assert r.exit_code == 0 and "GitHub's rate limit is used up; nothing changed this run" in r.output


def test_watch_github_org(world: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    from limbowatch.hosts import git as git_host

    _gh_env(monkeypatch)
    monkeypatch.setenv("LIMBOWATCH_SOURCE_TOKEN", "ghp_source")
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    monkeypatch.setattr(git_host, "command", lambda project, dest: [
        "git", "clone", "--depth", "1", "--no-recurse-submodules", "--quiet", f"file://{p}", str(dest)])  # fmt: skip
    with respx.mock(assert_all_called=False) as router:
        mocked(router)
        listing = router.get(f"{API}/orgs/acme/repos").mock(return_value=httpx.Response(200, json=[
            _repo("app"), _repo("old", archived=True)]))  # fmt: skip
        router.get(REPO).mock(return_value=httpx.Response(200, json={"visibility": "private", "has_issues": True}))
        router.get(f"{REPO}/issues").mock(return_value=httpx.Response(200, json=[]))
        create = router.post(f"{REPO}/issues").mock(return_value=httpx.Response(201, json=_issue(
            3, "", labels=("limbowatch",))))  # fmt: skip
        r = run(["watch", "--github-org", "acme", "--cache", str(world["cache"]), "--fail-on", "low",
                 "--issues", "--format", "json"])  # fmt: skip
    assert r.exit_code == 1, r.output
    assert listing.calls[0].request.headers["authorization"] == "Bearer ghp_source"
    assert create.calls[0].request.headers["authorization"] == "Bearer ghp_issues"
    rep = json.loads(r.stdout)
    assert [pr["project"] for pr in rep["projects"]] == ["github.com/acme/app"]
    assert rep["not_checked"] == [{"project": "github.com/acme/old", "url": "https://github.com/acme/old",
                                   "reason": "archived (--include-archived checks it)"}]  # fmt: skip
    assert rep["sources"][0]["note"] is None
    assert "github.com/acme/app: opened #3" in r.stderr


async def test_apply_every_kind_in_order() -> None:
    i = trackers.Issue(5, False, set())
    acts = [issues.Action("reopen", "a", body="Found again.", issue=i),
            issues.Action("label", "a", labels=["limbowatch:visible"], body="visible", issue=i),
            issues.Action("close", "a", body="fixed", issue=i)]  # fmt: skip
    t = FakeTracker()
    assert await issues.apply(t, acts) == ["reopen #5", "label #5", "close #5"]  # type: ignore[arg-type]
    assert t.calls == ["comment #5", "open=True #5", "comment #5", "label #5", "comment #5", "open=False #5"]


def test_a_real_clone_of_an_empty_repo_has_no_commit(tmp_path: Path) -> None:
    """Not faked: git prints "HEAD" for `rev-parse HEAD` in an empty repo, which once passed for a commit."""
    import shutil
    import subprocess

    if shutil.which("git") is None:
        pytest.skip("git not installed")
    bare = tmp_path / "empty.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    p = Project(HostKind.GIT, "file://", "empty", f"file://{bare}", "")
    assert git_host.clone(p, tmp_path / "out", None) == ""


# --- after the independent review (FINDINGS F-148) -----------------------------------------------------------


async def test_a_create_that_may_have_landed_is_not_retried(no_sleep: Any) -> None:
    with respx.mock() as r:
        gw = r.post(f"{REPO}/issues").mock(return_value=httpx.Response(502))
        timeout = r.post(f"{REPO}/issues/1/comments").mock(side_effect=httpx.ReadTimeout("slow"))
        refused = r.post(f"{REPO}/issues/2/comments").mock(side_effect=[httpx.ConnectError("refused"),
                                                                         httpx.Response(201, json={})])  # fmt: skip
        put = r.put("https://x.example/p").mock(side_effect=[httpx.Response(502), httpx.Response(200, json={})])
        async with HttpClient(sleep=no_sleep) as http:
            assert (await http.request("POST", f"{REPO}/issues", auth=None)).status == 502
            assert (await http.request("POST", f"{REPO}/issues/1/comments", auth=None)).status == -1
            assert (await http.request("POST", f"{REPO}/issues/2/comments", auth=None)).status == 201
            assert (await http.request("PUT", "https://x.example/p", auth=None)).status == 200  # idempotent
    assert gw.call_count == 1 and timeout.call_count == 1 and refused.call_count == 2 and put.call_count == 2


async def test_a_rate_limit_that_never_lifts_stops_cleanly(no_sleep: Any) -> None:
    with respx.mock() as r:
        limited = r.post(f"{REPO}/issues").mock(return_value=httpx.Response(403, headers={"retry-after": "60"}))
        async with HttpClient(sleep=no_sleep, max_rate_limit_wait=600) as http:
            with pytest.raises(BudgetExhausted):  # not a 403 for the caller to read as a failure
                await http.request("POST", f"{REPO}/issues", auth=None)
    assert limited.call_count == 5


async def test_trackers_send_no_header_without_a_token(no_sleep: Any) -> None:
    with respx.mock() as r:
        repo = r.get(REPO).mock(return_value=httpx.Response(200, json={"visibility": "public"}))
        async with HttpClient(sleep=no_sleep) as http:
            await trackers.GitHub(http, "acme/app", "").prepare()
    assert "authorization" not in repo.calls[0].request.headers


async def test_listing_notes_a_token_without_repo_scope(no_sleep: Any) -> None:
    with respx.mock() as r:
        r.get(f"{API}/orgs/acme/repos").mock(return_value=httpx.Response(
            200, headers={"x-oauth-scopes": "read:org, gist"}, json=[_repo("site", visibility="public")]))  # fmt: skip
        async with HttpClient(sleep=no_sleep) as http:
            ls = await gh.list_org(http, "https://github.com", "acme", "ghp_x")
            assert ls.note == gh.NO_REPO_SCOPE
            r.get(f"{API}/orgs/acme/repos").mock(return_value=httpx.Response(
                200, headers={"x-oauth-scopes": "repo, read:org"}, json=[]))  # fmt: skip
            assert (await gh.list_org(http, "https://github.com", "acme", "ghp_x")).note is None
    assert cli._github_token_note("github_pat_x") == "a fine-grained token lists only the repositories it was " \
                                                     "given access to"  # fmt: skip
    assert gh.api_url("https://acme.ghe.com", {"https://acme.ghe.com": "https://api.acme.ghe.com"}) == \
        "https://api.acme.ghe.com"  # fmt: skip


def test_unsent_changes_are_printed() -> None:
    ch = [state.Change("k", state.ChangeKind.CHANGED, "GHSA-x", "npm:a", ["CVE: CVE-2026-1"]),
          state.Change("n", state.ChangeKind.NEW, "GHSA-y", "npm:b")]  # fmt: skip
    assert issues.unsent(ch) == ["  GHSA-x (npm:a): Changed: CVE: CVE-2026-1."]
    assert cli._unsent_lines([]) == [] and len(cli._unsent_lines(ch)) == 2


def test_scan_keeps_its_reports_when_issues_fail(world: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    _gh_env(monkeypatch)
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    out = world["tmp"] / "report.json"
    with respx.mock(assert_all_called=False) as router:
        mocked(router)
        router.get(REPO).mock(return_value=httpx.Response(200, json={"visibility": "private", "has_issues": True}))
        router.get(f"{REPO}/issues").mock(return_value=httpx.Response(200, json=[]))
        router.post(f"{REPO}/issues").mock(return_value=httpx.Response(
            403, json={"message": "Resource not accessible by integration"}))  # a read-only GITHUB_TOKEN  # fmt: skip
        r = run(["scan", str(p), "--cache", str(world["cache"]), "--fail-on", "none", "--issues", "github",
                 "-o", f"json={out}"])  # fmt: skip
    assert r.exit_code == 2
    assert "issues couldn't be updated: create issue: HTTP 403 Resource not accessible by integration" in r.output
    assert json.loads(out.read_text())["findings"][0]["ghsa_id"] == "GHSA-c000-0000-0001"  # written all the same


def test_watch_stops_issues_on_a_host_after_a_dropped_label(
    world: dict[str, Any],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from limbowatch.hosts import git as git_host

    _gh_env(monkeypatch)
    monkeypatch.setenv("LIMBOWATCH_SOURCE_TOKEN", "ghp_source")
    p = project(world["tmp"], world["tags"]["v1.1.0"])
    monkeypatch.setattr(git_host, "command", lambda project, dest: [
        "git", "clone", "--depth", "1", "--no-recurse-submodules", "--quiet", f"file://{p}", str(dest)])  # fmt: skip
    with respx.mock(assert_all_called=False) as router:
        mocked(router)
        router.get(f"{API}/orgs/acme/repos").mock(return_value=httpx.Response(200, json=[_repo("a"), _repo("b")]))
        for name in ("a", "b"):
            base = f"{API}/repos/acme/{name}"
            router.get(base).mock(return_value=httpx.Response(200, json={"visibility": "private"}))
            router.get(f"{base}/issues").mock(return_value=httpx.Response(200, json=[]))
        made = router.post(f"{API}/repos/acme/a/issues").mock(return_value=httpx.Response(201, json=_issue(
            1, "", labels=())))  # fmt: skip
        router.patch(f"{API}/repos/acme/a/issues/1").mock(return_value=httpx.Response(200, json={}))
        other = router.post(f"{API}/repos/acme/b/issues")
        r = run(["watch", "--github-org", "acme", "--cache", str(world["cache"]), "--fail-on", "none", "--issues",
                 "--format", "json"])  # fmt: skip
        assert made.call_count == 1 and not other.called
    assert "github.com/acme/a: issues: GitHub opened #1 without the 'limbowatch' label" in r.stderr
    assert "github.com/acme/b: issues: not updated this run" in r.stderr
