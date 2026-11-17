from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def no_sleep() -> Any:
    async def _sleep(_: float) -> None:
        return None

    return _sleep


@pytest.fixture(autouse=True)
def _close_stores(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Every Store a test makes is closed after it, so no SQLite connection is left for the garbage collector
    (a ResourceWarning on Python 3.13 and later)."""
    from limbowatch.store import Store

    made: list[Store] = []
    init = Store.__init__

    def tracked(self: Store, *args: Any, **kwargs: Any) -> None:
        init(self, *args, **kwargs)
        made.append(self)

    monkeypatch.setattr(Store, "__init__", tracked)
    yield
    for store in made:
        store.close()


@pytest.fixture(autouse=True)
def _feed_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scan tests mock the feed but not GitHub's attestation API: verification is off unless a test turns it on
    (tests/test_feedtrust.py does)."""
    monkeypatch.setenv("LIMBOWATCH_VERIFY_FEED", "off")
    monkeypatch.delenv("LIMBOWATCH_FEED", raising=False)  # the limbo feed, unless a test asks for none
