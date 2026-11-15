from __future__ import annotations

import json
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
def _feed_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scan tests mock the feed but not GitHub's attestation API: verification is off unless a test turns it on
    (tests/test_feedtrust.py does)."""
    monkeypatch.setenv("LIMBOWATCH_VERIFY_FEED", "off")
