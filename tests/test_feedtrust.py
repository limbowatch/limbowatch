"""Feed safety (FINDINGS F-192 to F-194): the watcher uses the feed only if GitHub vouches for all.zip and for the
watchlist as part of the same build, and never reads more than a real feed's size. GitHub's answer is a recorded fixture
(tests/fixtures/attestations); no network."""

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from conftest import load
from limbowatch.http import HttpClient, ResponseTooLarge
from limbowatch.watch import candidates, feedtrust
from limbowatch.watch import scan as watch_scan
from limbowatch.watch.feedtrust import Verdict

ANSWER = load("attestations/feed_all_zip.json")  # GitHub's answer for the feed/all.zip built 2026-11-15 06:19 UTC
DIGEST = "447cb77acbe4baf0cc6f5902ea4adb4ac3c48ee9f06bb91d92fe4159e17f300a"
NOW = datetime(2026, 11, 15, 12, tzinfo=UTC)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def statement(answer: dict[str, Any] = ANSWER) -> dict[str, Any]:
    return dict(json.loads(base64.b64decode(answer["attestations"][0]["bundle"]["dsseEnvelope"]["payload"])))


def with_statement(st: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(ANSWER)
    out["attestations"][0]["bundle"]["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
    return out


def answer_for(*files: bytes) -> dict[str, Any]:
    """The recorded answer, its statement listing these files (one build)."""
    st = statement()
    st["subject"] = [{"name": f"f{i}", "digest": {"sha256": sha(b)}} for i, b in enumerate(files)]
    return with_statement(st)


def url(digest: str) -> str:
    return feedtrust.ATTESTATIONS.format(digest=digest)


async def no_waiting(_: float) -> None:
    raise AssertionError("verification must never wait")


async def _no_op(_: float) -> None:
    return None


# --- what counts as vouched for ---------------------------------------------------------------------------------------


def test_the_recorded_attestation_vouches_for_its_files() -> None:
    r = feedtrust.check(ANSWER, DIGEST)
    assert r.verdict is Verdict.VERIFIED and r.why == "built by limbowatch/limbowatch's site workflow on main"
    assert DIGEST in r.together and len(r.together) == 18  # the build's 18 distinct files, watchlist.json among them
    assert statement()["predicate"]["buildDefinition"]["externalParameters"]["workflow"] == feedtrust.WORKFLOW


def test_anything_else_is_refused() -> None:
    assert feedtrust.check(ANSWER, "0" * 64).verdict is Verdict.REJECTED  # another file
    assert feedtrust.check({"attestations": []}, DIGEST).verdict is Verdict.REJECTED  # GitHub's clear "none"

    def wf(s: dict[str, Any]) -> dict[str, Any]:
        return dict(s["predicate"]["buildDefinition"]["externalParameters"]["workflow"])

    def set_wf(**kw: str) -> Any:
        return lambda s: s["predicate"]["buildDefinition"]["externalParameters"].update(workflow=wf(s) | kw)

    for change in (
        set_wf(path=".github/workflows/x.yml"),
        set_wf(ref="refs/heads/evil"),
        set_wf(repository="https://github.com/someone/fork"),
        lambda s: s["predicate"]["runDetails"]["builder"].update(
            id="https://github.com/someone/fork/x@refs/heads/main"
        ),
        lambda s: s.update(predicateType="https://example.com/other"),
    ):
        st = statement()
        change(st)
        assert feedtrust.check(with_statement(st), DIGEST).verdict is Verdict.REJECTED


def test_an_answer_that_cant_be_read_is_unknown_not_a_rejection() -> None:
    """A proxy's HTML page, a changed format or a malformed statement mustn't refuse a genuine feed or crash (F-193)."""
    broken = copy.deepcopy(ANSWER)
    broken["attestations"][0]["bundle"]["dsseEnvelope"]["payload"] = "!!!"
    for body in (
        "<html>Sign in to the Wi-Fi</html>",
        {"message": "something else"},
        {"attestations": [{"bundle": None, "bundle_url": "https://example.invalid/b"}]},
        {"attestations": [None, 3, "x"]},
        broken,
    ):
        assert feedtrust.check(body, DIGEST).verdict is Verdict.UNKNOWN, body
    for odd in ({"predicate": 3, "subject": 7}, {"predicate": {"runDetails": []}, "subject": [1, {"digest": "x"}]}):
        st = statement() | odd
        assert feedtrust.check(with_statement(st), DIGEST).verdict is Verdict.REJECTED  # read, doesn't match: no crash
    # a readable attestation for another file next to an unreadable one: GitHub has spoken, it's a no
    other = statement()
    other["subject"] = [{"name": "x", "digest": {"sha256": "1" * 64}}]
    both = with_statement(other)
    both["attestations"].append(broken["attestations"][0])
    assert feedtrust.check(both, DIGEST).verdict is Verdict.REJECTED


# --- asking GitHub --------------------------------------------------------------------------------------------------

FEED, WATCHLIST = b"the feed", b'{"generated_at": "2026-11-15T06:00:00Z", "repos": {}}'


async def test_verified_once_then_from_the_cache(tmp_path: Path) -> None:
    with respx.mock() as router:
        route = router.get(url(sha(FEED))).mock(return_value=httpx.Response(200, json=answer_for(FEED, WATCHLIST)))
        async with HttpClient(sleep=no_waiting) as http:
            assert (await feedtrust.verify(http, FEED, WATCHLIST, tmp_path)).verdict is Verdict.VERIFIED
            assert (await feedtrust.verify(http, FEED, WATCHLIST, tmp_path)).why == "verified earlier"
    assert route.call_count == 1
    assert (tmp_path / feedtrust.VERIFIED_FILE).read_text().split() == [f"{sha(FEED)}:{sha(WATCHLIST)}"]


async def test_an_older_genuine_feed_with_a_newer_watchlist_is_refused(tmp_path: Path) -> None:
    """Rollback: every build's attestation stays valid, so the pair must come from one build (F-194)."""
    old_watchlist = b'{"generated_at": "2026-10-01T06:00:00Z", "repos": {}}'
    with respx.mock() as router:
        router.get(url(sha(FEED))).mock(return_value=httpx.Response(200, json=answer_for(FEED, old_watchlist)))
        async with HttpClient(sleep=no_waiting) as http:
            r = await feedtrust.verify(http, FEED, WATCHLIST, tmp_path)
    assert (r.verdict, r.mixed, r.why) == (Verdict.REJECTED, True, "its watchlist.json comes from a different build")
    assert not (tmp_path / feedtrust.VERIFIED_FILE).exists()


async def test_no_attestation_is_a_rejection_and_trouble_is_unknown(tmp_path: Path) -> None:
    limited = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "99999999999"}
    cases = [
        (httpx.Response(404, json={"message": "Not Found"}), Verdict.REJECTED),
        (httpx.Response(500), Verdict.UNKNOWN),
        (httpx.Response(403, headers=limited), Verdict.UNKNOWN),
        (httpx.Response(429, headers={"retry-after": "3600"}), Verdict.UNKNOWN),
        (httpx.Response(200, text="<html>proxy</html>"), Verdict.UNKNOWN),
    ]
    for answer, want in cases:
        with respx.mock() as router:
            router.get(url(sha(FEED))).mock(return_value=answer)
            async with HttpClient(sleep=no_waiting) as http:
                assert (await feedtrust.verify(http, FEED, WATCHLIST, tmp_path)).verdict is want, answer.status_code


async def test_one_attempt_no_waiting_when_github_is_unreachable_or_failing(tmp_path: Path) -> None:
    for answer in (httpx.ConnectTimeout("blocked"), httpx.Response(503)):
        with respx.mock() as router:
            route = router.get(url(sha(FEED))).mock(side_effect=[answer] * 6)
            async with HttpClient(sleep=no_waiting) as http:
                assert (await feedtrust.verify(http, FEED, WATCHLIST, tmp_path)).verdict is Verdict.UNKNOWN
        assert route.call_count == 1


async def test_a_refused_token_is_retried_without_it_but_a_404_is_final(tmp_path: Path) -> None:
    body = answer_for(FEED, WATCHLIST)
    with respx.mock() as router:
        route = router.get(url(sha(FEED))).mock(
            side_effect=lambda req: httpx.Response(401 if "authorization" in req.headers else 200, json=body)
        )
        async with HttpClient("expired-token", sleep=no_waiting) as http:
            assert (await feedtrust.verify(http, FEED, WATCHLIST, tmp_path)).verdict is Verdict.VERIFIED
    assert route.call_count == 2
    with respx.mock() as router:
        route = router.get(url(sha(FEED))).mock(return_value=httpx.Response(404))
        async with HttpClient("good-token", sleep=no_waiting) as http:
            assert (await feedtrust.verify(http, FEED, WATCHLIST, tmp_path / "fresh")).verdict is Verdict.REJECTED
    assert route.call_count == 1  # GitHub's "none" with a working token isn't asked again (F-194)


async def test_a_read_only_or_damaged_cache_never_fails_the_scan(tmp_path: Path) -> None:
    ro = tmp_path / "ro"
    ro.mkdir()
    (ro / feedtrust.VERIFIED_FILE).write_bytes(b"\xff\xfe not utf-8")
    (ro / feedtrust.VERIFIED_FILE).chmod(0o400)
    ro.chmod(0o500)
    try:
        with respx.mock() as router:
            router.get(url(sha(FEED))).mock(return_value=httpx.Response(200, json=answer_for(FEED, WATCHLIST)))
            async with HttpClient(sleep=no_waiting) as http:
                assert (await feedtrust.verify(http, FEED, WATCHLIST, ro)).verdict is Verdict.VERIFIED
    finally:
        ro.chmod(0o700)


# --- loading the feed ---------------------------------------------------------------------------------------------


def feed_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("GHSA-a.json", json.dumps({"id": "GHSA-a", "affected": []}))
    return buf.getvalue()


ZIP = feed_zip()


def mock_feed(
    router: respx.MockRouter, answer: httpx.Response, feed: bytes = ZIP, watchlist: bytes = WATCHLIST
) -> respx.Route:
    router.get(watch_scan.FEED_URL).mock(return_value=httpx.Response(200, content=feed))
    router.get(watch_scan.WATCHLIST_URL).mock(return_value=httpx.Response(200, content=watchlist))
    return router.get(url__startswith="https://api.github.com/repos/limbowatch/limbowatch/attestations/").mock(
        return_value=answer
    )


async def load(cache: Path, mode: str, warnings: list[str]) -> tuple[bytes, dict[str, Any]]:
    async with HttpClient(sleep=no_waiting) as http:
        return await watch_scan.load_feed(http, cache, mode, warnings.append, NOW)


async def test_load_feed_uses_a_vouched_pair_quietly(tmp_path: Path) -> None:
    warnings: list[str] = []
    with respx.mock() as router:
        lookups = mock_feed(router, httpx.Response(200, json=answer_for(ZIP, WATCHLIST)))
        got, doc = await load(tmp_path, "require", warnings)
    assert got == ZIP and doc["generated_at"] == "2026-11-15T06:00:00Z" and warnings == []
    assert lookups.call_count == 1  # one lookup proves both files


async def test_load_feed_refuses_what_github_doesnt_vouch_for(tmp_path: Path) -> None:
    for mode, answer, outcome in (
        ("auto", httpx.Response(404), r"failed verification \(GitHub has no attestation for it\)"),
        ("require", httpx.Response(404), "failed verification"),
        ("auto", httpx.Response(200, json=answer_for(ZIP, b"another watchlist")), "comes from a different build"),
        ("require", httpx.Response(500), r"couldn't be verified \(GitHub's attestation API answered 500\)"),
    ):
        cache = tmp_path / f"{mode}-{answer.status_code}"
        warnings: list[str] = []
        with respx.mock() as router:
            mock_feed(router, answer)
            with pytest.raises(RuntimeError, match=outcome):
                await load(cache, mode, warnings)
        assert warnings == []
        if answer.status_code != 500:  # refused: the cached copies are forgotten
            assert not (cache / "all.zip").exists() and not (cache / "watchlist.json").exists()


async def test_load_feed_warns_once_when_github_cant_be_asked(tmp_path: Path) -> None:
    warnings: list[str] = []
    with respx.mock() as router:
        lookups = mock_feed(router, httpx.Response(503))
        assert (await load(tmp_path, "auto", warnings))[0] == ZIP
    assert lookups.call_count == 1
    want = "limbowatch: couldn't verify the limbo feed (GitHub's attestation API answered 503); using it unverified"
    assert warnings == [want]
    with respx.mock() as router:
        router.get(watch_scan.FEED_URL).mock(return_value=httpx.Response(200, content=ZIP))
        router.get(watch_scan.WATCHLIST_URL).mock(return_value=httpx.Response(200, content=WATCHLIST))
        assert (await load(tmp_path / "off", "off", warnings))[0] == ZIP  # off: GitHub isn't asked at all


async def test_a_mix_this_run_caused_by_falling_back_to_the_cache_is_a_warning(tmp_path: Path) -> None:
    """The watchlist download failed and yesterday's cached copy stood in: genuine, but from another build."""
    old = b'{"generated_at": "2026-11-14T06:00:00Z", "repos": {}}'
    (tmp_path / "watchlist.json").write_bytes(old)
    (tmp_path / "watchlist.json.etag").write_text('"old"')
    warnings: list[str] = []
    with respx.mock() as router:
        router.get(watch_scan.FEED_URL).mock(return_value=httpx.Response(200, content=ZIP))
        router.get(watch_scan.WATCHLIST_URL).mock(side_effect=httpx.ConnectError("down"))
        router.get(url(sha(ZIP))).mock(return_value=httpx.Response(200, json=answer_for(ZIP, WATCHLIST)))
        async with HttpClient(sleep=_no_op) as http:
            got, doc = await watch_scan.load_feed(http, tmp_path, "auto", warnings.append, NOW)
            assert got == ZIP and doc["generated_at"] == "2026-11-14T06:00:00Z"
            with pytest.raises(RuntimeError, match="different build"):  # require: still refused
                await watch_scan.load_feed(http, tmp_path, "require", warnings.append, NOW)
    assert warnings == [
        "limbowatch: couldn't download all of the limbo feed; "
        "the older cached feed/watchlist.json is from another build"
    ]


async def test_an_old_feed_is_a_warning(tmp_path: Path) -> None:
    """A rolled-back pair verifies (both files from one old build): its age shows it (F-194)."""
    old = b'{"generated_at": "2026-11-01T06:00:00Z", "repos": {}}'
    warnings: list[str] = []
    with respx.mock() as router:
        mock_feed(router, httpx.Response(200, json=answer_for(ZIP, old)), watchlist=old)
        await load(tmp_path, "auto", warnings)
    assert warnings == [
        "limbowatch: the limbo feed is from 2026-11-01T06:00:00Z, more than 3 days ago: newer advisories in limbo "
        "aren't in it"
    ]
    assert NOW - timedelta(days=3) > datetime(2026, 11, 1, tzinfo=UTC)


# --- size limits and damaged feeds --------------------------------------------------------------------------------


async def test_downloads_are_capped_even_when_compressed() -> None:
    bomb = gzip.compress(b"\0" * 2_000_000)  # 2 KB on the wire, 2 MB unpacked
    with respx.mock() as router:
        router.get("https://limbo.watch/big").mock(return_value=httpx.Response(200, content=b"x" * 2_000))
        router.get("https://limbo.watch/bomb").mock(
            return_value=httpx.Response(200, content=bomb, headers={"content-encoding": "gzip"})
        )
        router.get("https://limbo.watch/ok").mock(
            return_value=httpx.Response(200, content=gzip.compress(b"fine"), headers={"content-encoding": "gzip"})
        )
        async with HttpClient() as http:
            with pytest.raises(ResponseTooLarge, match="larger than 1,000 bytes"):
                await http.get("https://limbo.watch/big", raw=True, max_bytes=1_000)
            with pytest.raises(ResponseTooLarge):
                await http.get("https://limbo.watch/bomb", raw=True, max_bytes=1_000_000)
            r = await http.get("https://limbo.watch/ok", raw=True, max_bytes=1_000)
            assert r.status == 200 and r.body == b"fine"
            with pytest.raises(RuntimeError, match="far larger than the real feed"):
                await watch_scan.fetch(http, "https://limbo.watch/big", None, max_bytes=1_000)


def test_the_feed_zip_is_checked_before_unpacking(monkeypatch: pytest.MonkeyPatch) -> None:
    def zipped(records: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for n, b in records.items():
                z.writestr(n, b)
        return buf.getvalue()

    record = json.dumps({"id": "GHSA-a", "affected": []}).encode()
    assert len(candidates.from_feed_zip(zipped({"GHSA-a.json": record}))) == 1
    monkeypatch.setattr(candidates, "MAX_RECORDS", 2)
    with pytest.raises(candidates.FeedTooLarge, match="3 records"):
        candidates.from_feed_zip(zipped({f"GHSA-{i}.json": record for i in range(3)}))
    monkeypatch.setattr(candidates, "MAX_RECORD_BYTES", 1_000)
    with pytest.raises(candidates.FeedTooLarge, match=r"GHSA-big\.json is 5,000 bytes"):
        candidates.from_feed_zip(zipped({"GHSA-big.json": b" " * 5_000}))
    monkeypatch.setattr(candidates, "MAX_UNPACKED_BYTES", 1_500)
    with pytest.raises(candidates.FeedTooLarge, match="unpacks to 1,800 bytes"):
        candidates.from_feed_zip(zipped({"GHSA-1.json": b" " * 900, "GHSA-2.json": b" " * 900}))


async def test_a_damaged_feed_is_a_clean_error() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("GHSA-a.json", b"{not json")
    with pytest.raises(candidates.FeedUnreadable, match=r"GHSA-a\.json: JSONDecodeError"):
        candidates.from_feed_zip(buf.getvalue())
    async with HttpClient() as http:
        for data in (buf.getvalue(), b"not a zip"):
            with pytest.raises(RuntimeError, match="the limbo feed couldn't be read"):
                await watch_scan.prepare([], http, feed_zip=data, watchlist={}, now=NOW)
    with respx.mock() as router:
        router.get(watch_scan.FEED_URL).mock(return_value=httpx.Response(200, content=ZIP))
        router.get(watch_scan.WATCHLIST_URL).mock(return_value=httpx.Response(200, content=b"<html>"))
        async with HttpClient() as http:
            with pytest.raises(RuntimeError, match="watchlist isn't JSON"):
                await watch_scan.load_feed(http, None, "off", lambda _: None, NOW)


def test_previous_feed_timestamps_must_parse() -> None:
    from limbowatch.publish.feed import previous_modified

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i, mod in enumerate(["2026-13-45T10:00:00Z", "2026-11-14T24:00:00Z", "２０２６-11-14T10:00:00Z",
                                 "2026-11-14T10:00:00Z"]):  # fmt: skip
            z.writestr(f"GHSA-{i}.json", json.dumps({"id": f"GHSA-{i}", "modified": mod}))
    assert list(previous_modified(buf.getvalue())) == ["GHSA-3"]
