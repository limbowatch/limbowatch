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
