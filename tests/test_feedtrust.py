"""Feed safety (FINDINGS F-192): the watcher refuses a feed GitHub doesn't vouch for, and never reads more than a real
feed's size. GitHub's answer is a recorded fixture (tests/fixtures/attestations); no network."""

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime
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


def statement(answer: dict[str, Any]) -> dict[str, Any]:
    return dict(json.loads(base64.b64decode(answer["attestations"][0]["bundle"]["dsseEnvelope"]["payload"])))


def with_statement(st: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(ANSWER)
    out["attestations"][0]["bundle"]["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
    return out


# --- what counts as vouched for ---------------------------------------------------------------------------------------


def test_the_recorded_attestation_vouches_for_its_file() -> None:
    assert feedtrust.check(ANSWER, DIGEST) == (
        Verdict.VERIFIED,
        "built by limbowatch/limbowatch's site workflow on main",
    )
    assert statement(ANSWER)["predicate"]["buildDefinition"]["externalParameters"]["workflow"] == feedtrust.WORKFLOW


def test_anything_else_is_refused() -> None:
    assert feedtrust.check(ANSWER, "0" * 64)[0] is Verdict.REJECTED  # another file
    assert feedtrust.check({"attestations": []}, DIGEST)[0] is Verdict.REJECTED
    assert feedtrust.check({"attestations": []}, DIGEST)[0] is Verdict.REJECTED  # GitHub's clear "none"
    for change in (
        lambda s: s["predicate"]["buildDefinition"]["externalParameters"]["workflow"].update(
            path=".github/workflows/x.yml"
        ),
        lambda s: s["predicate"]["buildDefinition"]["externalParameters"]["workflow"].update(ref="refs/heads/evil"),
        lambda s: s["predicate"]["buildDefinition"]["externalParameters"]["workflow"].update(
            repository="https://github.com/someone/fork"
        ),
        lambda s: s["predicate"]["runDetails"]["builder"].update(
            id="https://github.com/someone/fork/x@refs/heads/main"
        ),
        lambda s: s.update(predicateType="https://example.com/other"),
    ):
        st = statement(ANSWER)
        change(st)
        assert feedtrust.check(with_statement(st), DIGEST)[0] is Verdict.REJECTED


def test_an_answer_that_cant_be_read_is_unknown_not_a_rejection() -> None:
    """A proxy's HTML page or a changed format mustn't refuse a genuine feed (F-193)."""
    broken = copy.deepcopy(ANSWER)
    broken["attestations"][0]["bundle"]["dsseEnvelope"]["payload"] = "!!!"
    for body in (
        "<html>Sign in to the Wi-Fi</html>",
        {"message": "something else"},
        {"attestations": [{"bundle": None, "bundle_url": "https://example.invalid/b"}]},
        broken,
    ):
        assert feedtrust.check(body, DIGEST)[0] is Verdict.UNKNOWN, body
    # one readable attestation for another file, plus an unreadable one: GitHub has spoken, it's a no
    other = statement(ANSWER)
    other["subject"] = [{"name": "x", "digest": {"sha256": "1" * 64}}]
    both = with_statement(other)
    both["attestations"].append(broken["attestations"][0])
    assert feedtrust.check(both, DIGEST)[0] is Verdict.REJECTED


# --- asking GitHub --------------------------------------------------------------------------------------------------


def url(digest: str) -> str:
    return feedtrust.ATTESTATIONS.format(digest=digest)


async def no_waiting(_: float) -> None:
    raise AssertionError("verification must never wait on a rate limit")


@pytest.fixture
def patched_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    real = hashlib.sha256

    def sha256(data: bytes = b"") -> Any:
        return type("H", (), {"hexdigest": lambda self: DIGEST})() if data == b"the feed" else real(data)

    monkeypatch.setattr(feedtrust.hashlib, "sha256", sha256)


async def test_verified_once_then_from_the_cache(tmp_path: Path, patched_digest: None) -> None:
    with respx.mock() as router:
        route = router.get(url(DIGEST)).mock(return_value=httpx.Response(200, json=ANSWER))
        async with HttpClient(sleep=no_waiting) as http:
            assert (await feedtrust.verify(http, b"the feed", tmp_path))[0] is Verdict.VERIFIED
            assert await feedtrust.verify(http, b"the feed", tmp_path) == (Verdict.VERIFIED, "verified earlier")
    assert route.call_count == 1
    assert (tmp_path / feedtrust.VERIFIED_FILE).read_text().split() == [DIGEST]


async def test_no_attestation_is_a_rejection_and_trouble_is_unknown(tmp_path: Path) -> None:
    other = hashlib.sha256(b"tampered").hexdigest()
    cases = [
        (httpx.Response(404, json={"message": "Not Found"}), Verdict.REJECTED),
        (httpx.Response(500), Verdict.UNKNOWN),
        (
            httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"}),
            Verdict.UNKNOWN,
        ),
        (httpx.Response(429, headers={"retry-after": "3600"}), Verdict.UNKNOWN),
    ]
    for answer, want in cases:
        with respx.mock() as router:
            router.get(url(other)).mock(return_value=answer)
            async with HttpClient(sleep=lambda _: _no_op()) as http:
                assert (await feedtrust.verify(http, b"tampered", tmp_path))[0] is want, answer.status_code
    assert not (tmp_path / feedtrust.VERIFIED_FILE).exists()


async def _no_op() -> None:
    return None


# --- loading the feed ---------------------------------------------------------------------------------------------


def feed_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("GHSA-a.json", json.dumps({"id": "GHSA-a", "affected": []}))
    return buf.getvalue()


def mock_feed(router: respx.MockRouter, feed: bytes, watchlist: bytes, answer: httpx.Response) -> None:
    router.get(watch_scan.FEED_URL).mock(return_value=httpx.Response(200, content=feed))
    router.get(watch_scan.WATCHLIST_URL).mock(return_value=httpx.Response(200, content=watchlist))
    router.get(url__startswith="https://api.github.com/repos/limbowatch/limbowatch/attestations/").mock(
        return_value=answer
    )


async def test_load_feed_refuses_what_github_doesnt_vouch_for(tmp_path: Path) -> None:
    warnings: list[str] = []
    feed, wl = feed_zip(), b'{"repos": {}}'
    for mode, answer, outcome in (
        ("auto", httpx.Response(404), "failed verification (GitHub has no attestation for it)"),
        ("require", httpx.Response(404), "failed verification"),
        (
            "require",
            httpx.Response(500),
            "couldn't be verified (GitHub's attestation API answered 500)",
        ),
        ("require", httpx.Response(403, headers={"x-ratelimit-remaining": "0"}), "API answered 403); --verify-feed"),
    ):
        with respx.mock() as router:
            mock_feed(router, feed, wl, answer)
            async with HttpClient(sleep=lambda _: _no_op()) as http:
                with pytest.raises(RuntimeError, match=outcome.replace("(", r"\(").replace(")", r"\)")):
                    await watch_scan.load_feed(http, tmp_path / mode, mode, warnings.append)
    assert warnings == []

    # auto, GitHub unreachable: a warning, and the feed is used
    with respx.mock() as router:
        mock_feed(router, feed, wl, httpx.Response(503))
        async with HttpClient(sleep=lambda _: _no_op()) as http:
            got, doc = await watch_scan.load_feed(http, tmp_path / "auto2", "auto", warnings.append)
    assert got == feed and doc == {"repos": {}}
    assert warnings == [
        "limbowatch: couldn't verify the limbo feed (GitHub's attestation API answered 503); using it unverified"
    ]

    # off: GitHub isn't asked at all
    with respx.mock() as router:
        router.get(watch_scan.FEED_URL).mock(return_value=httpx.Response(200, content=feed))
        router.get(watch_scan.WATCHLIST_URL).mock(return_value=httpx.Response(200, content=wl))
        async with HttpClient() as http:
            assert (await watch_scan.load_feed(http, tmp_path / "off", "off", warnings.append))[0] == feed


async def test_load_feed_with_both_files_attested(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    feed, wl = feed_zip(), b'{"repos": {"a/b": "2026-11-14T00:00:00Z"}}'
    answers = {}
    for data in (feed, wl):
        st = statement(ANSWER)
        st["subject"] = [{"name": "f", "digest": {"sha256": hashlib.sha256(data).hexdigest()}}]
        answers[hashlib.sha256(data).hexdigest()] = with_statement(st)
    with respx.mock() as router:
        router.get(watch_scan.FEED_URL).mock(return_value=httpx.Response(200, content=feed))
        router.get(watch_scan.WATCHLIST_URL).mock(return_value=httpx.Response(200, content=wl))
        for d, body in answers.items():
            router.get(url(d)).mock(return_value=httpx.Response(200, json=body))
        async with HttpClient(sleep=no_waiting) as http:
            got, doc = await watch_scan.load_feed(http, tmp_path, "require", lambda m: pytest.fail(m))
    assert got == feed and doc["repos"] == {"a/b": "2026-11-14T00:00:00Z"}


# --- size limits --------------------------------------------------------------------------------------------------


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


# --- from the independent review (F-193) ----------------------------------------------------------------------------


async def test_a_read_only_or_damaged_cache_never_fails_the_scan(tmp_path: Path, patched_digest: None) -> None:
    ro = tmp_path / "ro"
    ro.mkdir()
    (ro / feedtrust.VERIFIED_FILE).write_bytes(b"\xff\xfe not utf-8")
    ro.chmod(0o500)
    (ro / feedtrust.VERIFIED_FILE).chmod(0o400)
    try:
        with respx.mock() as router:
            router.get(url(DIGEST)).mock(return_value=httpx.Response(200, json=ANSWER))
            async with HttpClient(sleep=no_waiting) as http:
                assert (await feedtrust.verify(http, b"the feed", ro))[0] is Verdict.VERIFIED
    finally:
        ro.chmod(0o700)


async def test_a_refused_token_is_retried_without_it(tmp_path: Path, patched_digest: None) -> None:
    with respx.mock() as router:
        route = router.get(url(DIGEST)).mock(
            side_effect=lambda req: httpx.Response(401 if "authorization" in req.headers else 200, json=ANSWER)
        )
        async with HttpClient("expired-token", sleep=no_waiting) as http:
            assert (await feedtrust.verify(http, b"the feed", tmp_path))[0] is Verdict.VERIFIED
    assert route.call_count == 2


async def test_one_attempt_no_waiting_when_github_is_unreachable_or_failing(tmp_path: Path) -> None:
    other = hashlib.sha256(b"x").hexdigest()
    for answer in (httpx.ConnectTimeout("blocked"), httpx.Response(503)):
        with respx.mock() as router:
            route = router.get(url(other)).mock(side_effect=[answer] * 6)
            async with HttpClient(sleep=no_waiting) as http:
                assert (await feedtrust.verify(http, b"x", tmp_path))[0] is Verdict.UNKNOWN
        assert route.call_count == 1


async def test_unknown_warns_once_and_a_rejected_copy_is_forgotten(tmp_path: Path) -> None:
    feed, wl = feed_zip(), b'{"repos": {}}'
    warnings: list[str] = []
    with respx.mock() as router:
        mock_feed(router, feed, wl, httpx.Response(503))
        lookups = router.routes[2]
        async with HttpClient(sleep=no_waiting) as http:
            await watch_scan.load_feed(http, tmp_path / "a", "auto", warnings.append)
    assert lookups.call_count == 1 and len(warnings) == 1
    assert (
        warnings[0]
        == "limbowatch: couldn't verify the limbo feed (GitHub's attestation API answered 503); using it unverified"
    )

    cache = tmp_path / "b"
    with respx.mock() as router:
        mock_feed(router, feed, wl, httpx.Response(404))
        async with HttpClient(sleep=no_waiting) as http:
            with pytest.raises(RuntimeError, match="failed verification"):
                await watch_scan.load_feed(http, cache, "auto", warnings.append)
    assert not (cache / "all.zip").exists() and not (cache / "all.zip.etag").exists()


async def test_a_damaged_record_is_a_clean_error(monkeypatch: pytest.MonkeyPatch) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("GHSA-a.json", b"{not json")
    with pytest.raises(candidates.FeedUnreadable, match=r"GHSA-a\.json: JSONDecodeError"):
        candidates.from_feed_zip(buf.getvalue())
    async with HttpClient() as http:
        with pytest.raises(RuntimeError, match=r"the limbo feed couldn't be read: GHSA-a\.json"):
            await watch_scan.prepare([], http, feed_zip=buf.getvalue(), watchlist={}, now=datetime.now(UTC))
        with pytest.raises(RuntimeError, match="couldn't be read"):
            await watch_scan.prepare([], http, feed_zip=b"not a zip", watchlist={}, now=datetime.now(UTC))


def test_previous_feed_timestamps_must_parse() -> None:
    from limbowatch.publish.feed import previous_modified

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i, mod in enumerate(["2026-13-45T10:00:00Z", "2026-11-14T24:00:00Z", "２０２６-11-14T10:00:00Z",
                                 "2026-11-14T10:00:00Z"]):  # fmt: skip
            z.writestr(f"GHSA-{i}.json", json.dumps({"id": f"GHSA-{i}", "modified": mod}))
    assert [k for k in previous_modified(buf.getvalue())] == ["GHSA-3"]
