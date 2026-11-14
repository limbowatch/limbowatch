"""scripts/check_hosting.py's comparison, on made-up responses: it must notice what differs (no network)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_hosting", ROOT / "scripts" / "check_hosting.py")
assert _spec and _spec.loader
ch = importlib.util.module_from_spec(_spec)
sys.modules["check_hosting"] = ch
_spec.loader.exec_module(ch)

SEC = {h: "x" for h in ch.SECURITY}


def resp(status: int = 200, body: bytes = b"a", **headers: str) -> httpx.Response:
    return httpx.Response(status, content=body, headers={"content-type": "text/html", **SEC, **headers})


def test_same_answers_pass() -> None:
    assert ch.compare("/", resp(), resp()) == []
    old = resp(301, b"", location="http://limbo.watch/tracker/?fix=yes")
    new = resp(301, b"", location="https://next.limbo.watch/tracker/?fix=yes")
    assert ch.compare("/tracker?fix=yes", old, new) == []


def test_differences_are_named() -> None:
    assert ch.compare("/", resp(), resp(404))[0] == "status 200 vs 404"
    assert ch.compare("/", resp(body=b"a"), resp(body=b"b"))[0].startswith("body ")
    assert ch.compare("/", resp(), resp(**{"content-type": "text/plain"})) == [
        "content-type: 'text/html' vs 'text/plain'"
    ]
    missing = resp()
    del missing.headers["content-security-policy"]
    assert ch.compare("/nope", resp(404), missing.__class__(404, headers=missing.headers)) == [
        "content-security-policy: 'x' vs None"
    ]
    old = resp(301, b"", location="http://limbo.watch/a/")
    assert ch.compare("/a", old, resp(301, b"", location="https://next.limbo.watch/b/")) == [
        "location 'http://limbo.watch/a/' vs 'https://next.limbo.watch/b/'"
    ]
    assert ch.compare("/a", old, resp(301, b"", location="http://next.limbo.watch/a/")) == ["redirect to http://"]
