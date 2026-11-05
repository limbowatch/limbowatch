"""Issue lifecycle and the GitLab / Gitea trackers (SPEC: GitLab integration; FINDINGS F-079, F-080)."""

import json
from typing import Any

import httpx
import respx
from limbowatch.http import HttpClient
from limbowatch.watch import issues, state, trackers
from test_output import finding

GL = "https://gitlab.example/api/v4/projects/group%2Fapp"
GT = "https://gitea.example/api/v1/repos/me/app"


def current(*fs: Any) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    cur = state.entries(list(fs), "t")
    one = {f.key: f.model_dump(mode="json") for f in fs}
    return cur, one


def test_marker_round_trip_and_body() -> None:
    f = finding()
    cur, one = current(f)
    e = cur[f.key] | {"key": f.key}
    text = issues.body(e, one[f.key])
    meta = trackers.read_marker(text)
    assert meta == {"key": f.key, "ghsa_id": f.ghsa_id, "ecosystem": "npm", "package": "lodash",
                    "range": "< 4.17.21", "fixed": "4.17.21"}  # fmt: skip
    assert "isn't in GitHub's reviewed Advisory Database or OSV yet" in text and "CC BY 4.0" in text
    assert issues.title(e) == "[limbo] GHSA-aaaa-bbbb-cccc: npm lodash 4.17.20 (high)"


def test_plan_lifecycle() -> None:
    new, closed, changed, visible, fixed = (
        finding(name=n, ghsa=f"GHSA-{n}") for n in ("new", "closed", "changed", "vis", "fix")
    )
    cur, one = current(new, closed, changed)
    existing = {
        closed.key: trackers.Issue(1, False, {"limbowatch"}, {"key": closed.key}),
        changed.key: trackers.Issue(2, True, {"limbowatch"}, {"key": changed.key}),
        visible.key: trackers.Issue(3, True, {"limbowatch"}, {"key": visible.key}),
        fixed.key: trackers.Issue(4, True, {"limbowatch"}, {"key": fixed.key}),
    }
    ch = [state.Change(changed.key, state.ChangeKind.CHANGED, changed.ghsa_id, "npm:changed", ["CVE: CVE-2026-1"])]
    gone = {visible.key: issues.Gone.VISIBLE, fixed.key: issues.Gone.FIXED}
    acts = issues.plan(cur, one, existing, ch, gone, issues.Policy(), public=False)
    got = [(a.kind, a.issue.number if a.issue else a.title.split(":")[0]) for a in acts]
    assert sorted(got, key=str) == sorted([("create", "[limbo] GHSA-new"), ("reopen", 1), ("comment", 2), ("label", 3),
                                           ("close", 4)], key=str)  # fmt: skip
    # idempotent: an issue already labelled visible gets nothing more
    existing[visible.key].labels.add(issues.VISIBLE_LABEL)
    assert not [a for a in issues.plan(cur, one, existing, [], gone, issues.Policy(), False) if a.kind == "label"]


def test_plan_respects_public_trackers_and_min_severity() -> None:
    low, crit = finding(name="l", ghsa="GHSA-l", sev="low"), finding(name="c", ghsa="GHSA-c", sev="critical")
    cur, one = current(low, crit)
    assert issues.plan(cur, one, {}, [], {}, issues.Policy(), public=True) == []
    acts = issues.plan(cur, one, {}, [], {}, issues.Policy(min_severity="high"), public=False)
    assert [a.key for a in acts] == [crit.key]


def test_still_affected() -> None:
    meta = {"ghsa_id": "GHSA-x", "ecosystem": "npm", "range": "< 2.0.0"}
    assert issues.still_affected(meta, ["1.0.0"], [{"GHSA-x"}]) is True  # OSV says so
    assert issues.still_affected(meta, ["1.0.0"], [set()]) is False  # OSV has it, not for this version
    assert issues.still_affected(meta, ["1.5.0"], []) is True  # not in OSV: the recorded range decides
    assert issues.still_affected(meta, ["2.1.0"], []) is False
    assert issues.still_affected(meta | {"range": "tbd"}, ["2.1.0"], []) is None  # can't tell: leave it open


async def test_gitlab_tracker(no_sleep: Any) -> None:
    body = issues.body(
        state.entries([finding()], "t")[finding().key] | {"key": finding().key}, finding().model_dump(mode="json")
    )
    with respx.mock(assert_all_mocked=True) as r:
        r.get(GL).mock(return_value=httpx.Response(200, json={"visibility": "public"}))
        r.get(f"{GL}/issues").mock(return_value=httpx.Response(200, json=[
            {"iid": 7, "state": "opened", "labels": ["limbowatch"], "description": body},
            {"iid": 8, "state": "opened", "labels": ["limbowatch"], "description": "made by hand"}]))  # fmt: skip
        create = r.post(f"{GL}/issues").mock(
            return_value=httpx.Response(201, json={"iid": 9, "labels": ["limbowatch"]})
        )
        note = r.post(f"{GL}/issues/7/notes").mock(return_value=httpx.Response(201, json={}))
        close = r.put(f"{GL}/issues/7").mock(return_value=httpx.Response(200, json={}))
        async with HttpClient(sleep=no_sleep) as http:
            gl = trackers.GitLab(http, "group/app", "tok", "https://gitlab.example")
            await gl.prepare()
            assert gl.public is False  # confidential issues aren't public even in a public project
            found = await gl.issues()
            assert list(found) == [finding().key] and found[finding().key].number == 7
            await gl.create("t", "b", ["limbowatch", "security"])
            await gl.comment(found[finding().key], "hello")
            await gl.set_open(found[finding().key], False)
    sent = json.loads(create.calls[0].request.content)
    assert sent["confidential"] is True and sent["labels"] == "limbowatch,security"
    assert create.calls[0].request.headers["private-token"] == "tok"
    assert json.loads(note.calls[0].request.content) == {"body": "hello"}
    assert json.loads(close.calls[0].request.content) == {"state_event": "close"}


async def test_gitea_tracker_resolves_label_ids(no_sleep: Any) -> None:
    with respx.mock(assert_all_mocked=True) as r:
        r.get(GT).mock(return_value=httpx.Response(200, json={"private": False}))
        r.get(f"{GT}/labels").mock(return_value=httpx.Response(200, json=[{"name": "limbowatch", "id": 1}]))
        newlabel = r.post(f"{GT}/labels").mock(return_value=httpx.Response(201, json={"name": "security", "id": 2}))
        create = r.post(f"{GT}/issues").mock(return_value=httpx.Response(201, json={"number": 3}))
        patch = r.patch(f"{GT}/issues/3").mock(return_value=httpx.Response(201, json={}))
        async with HttpClient(sleep=no_sleep) as http:
            gt = trackers.Gitea(http, "me/app", "tok", "https://gitea.example")
            await gt.prepare()
            assert gt.public is True  # a public repo: callers won't open issues here by default
            i = await gt.create("t", "b", ["limbowatch", "security"])
            await gt.set_open(i, False)
    assert json.loads(newlabel.calls[0].request.content)["name"] == "security"
    assert json.loads(create.calls[0].request.content)["labels"] == [1, 2]
    assert create.calls[0].request.headers["authorization"] == "token tok"
    assert json.loads(patch.calls[0].request.content) == {"state": "closed"}
