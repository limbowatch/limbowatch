"""checks.locate finds the same line as before it indexed lockfiles (F-204), on every package in the test lockfiles."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
from limbowatch.inventory import checks

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REFERENCE = Path(__file__).resolve().parent / "locate_reference.py"


def _reference():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("locate_reference", REFERENCE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["locate_reference"] = mod
    spec.loader.exec_module(mod)
    return mod.locate


LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "Cargo.lock", "yarn.lock", "pnpm-lock.yaml", "go.mod",
         "poetry.lock", "uv.lock", "Gemfile.lock", "composer.lock", "pom.xml")  # fmt: skip


def _files() -> list[Path]:
    out = [
        p
        for p in FIXTURES.rglob("*")
        if p.is_file() and (p.name in LOCKS or re.fullmatch(r"requirements.*\.txt", p.name))
    ]
    assert len(out) >= 8
    return sorted(out)


def _names(text: str) -> set[str]:
    """Plausible package names in a file, plus near misses."""
    words = set(re.findall(r"[@A-Za-z0-9_./:-]{2,80}", text))
    return {w.strip("./:") for w in words if w.strip("./:")} | {"absent-package", "", "a", "-", "requests", "Requests"}


@pytest.mark.parametrize("path", _files(), ids=lambda p: str(p.relative_to(FIXTURES)))
def test_same_line_as_the_reference(path: Path) -> None:
    ref = _reference()
    text = path.read_text(errors="replace")
    rel = path.relative_to(FIXTURES).as_posix()
    names = sorted(_names(text))[:400]
    for name in names:
        for version in ("", "1.0.0", "4.17.21"):
            assert checks.locate(text, rel, name, version) == ref(text, rel, name, version), (rel, name, version)


def test_edge_cases_match_the_reference() -> None:
    ref = _reference()
    cases = [
        ("requirements.txt", "Django==4.2\nreqUests>=2\n  requests_oauthlib ; python_version>'3'\nrequeſts==1\n"),
        ("package-lock.json", '{\n"packages": {\n"node_modules/a/node_modules/b": {},\n"node_modules/b": {}\n}\n}'),
        ("Cargo.lock", 'name = "serde"\nname = "serde_json"\r\nname = "serde"\n'),
        ("go.mod", "require (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/a/b/v2 v2.0.0\n)\n"),
        ("x.txt", "İstanbul==1\nkKelvin\nlast"),
    ]
    for fname, text in cases:
        for name in ("requests", "requests-oauthlib", "b", "serde", "github.com/a/b", "github.com/a/b/v2", "kkelvin",
                     "istanbul", "Django", "last", "", "nope"):  # fmt: skip
            for version in ("", "1.0.0", "v2.0.0"):
                assert checks.locate(text, fname, name, version) == ref(text, fname, name, version), (fname, name)
