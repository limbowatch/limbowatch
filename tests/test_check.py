"""The browser checker (publish/check.js) against the Python code `limbowatch scan` uses.

check.js ports univers' version orderings to JavaScript. These tests run it under Node and require the same answer
as Python for every comparison and verdict, so the checker on limbo.watch can't drift from the CLI. Node is on
GitHub's runners; locally the tests skip without it, in CI they fail.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any

import pytest
from limbowatch.models import AdvisoryPackage, Assessment, CveLabel, Dependency, Facts, RepoAdvisory, Status
from limbowatch.publish import Item
from limbowatch.publish.check import entry, index
from limbowatch.versions import VERSION_CLASS, _mk
from limbowatch.watch.match import _version

SCRIPT = str(files("limbowatch.publish").joinpath("check.js"))
NODE = shutil.which("node")
if NODE is None and os.environ.get("CI"):
    raise RuntimeError("tests/test_check.py needs Node in CI")
pytestmark = pytest.mark.skipif(NODE is None, reason="needs Node")

RUNNER = """
const c = require(process.argv[1]);
const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = cases.map(([fn, ...args]) => {
  if (fn === 'affected') return c.affected(...args);
  if (fn === 'verdict') return c.verdict(...args)[0];
  if (fn === 'findings') return c.findings(...args).map(f => [f.e.g, f.hit]);
  throw new Error(fn);
});
process.stdout.write(JSON.stringify(out));
"""


def node(cases: list[list[Any]]) -> list[Any]:
    assert NODE is not None
    r = subprocess.run(
        [NODE, "-e", RUNNER, SCRIPT], input=json.dumps(cases), capture_output=True, text=True, check=True, timeout=60
    )
    return json.loads(r.stdout)


VERSIONS = {
    "npm": [
        "1.0.0", "1.0", "1", "v1.2.3", "V1.2.3", "1.2.3", "1.2.3-alpha", "1.2.3-alpha.1", "1.2.3-alpha.beta",
        "1.2.3-beta.2", "1.2.3-beta.11", "1.2.3-rc.1", "1.2.3+build.1", "1.2.3+build.2", "1.2.3-rc.1+b", "1.2.3.4",
        "1.2.3.4.5", "01.2.3", "1.02.3", "1.2.3-01", "1.2.3-0", "1.2.3-x.7.z.92", "10.0.0", "2.0.0", "1.10.0", "1.9.0",
        "1.2.3_beta", "1.2.3beta", "1.2.3-", "1.2.3+", "abc", "", "1.x", "*", "1.2.3-alpha_1", "0.0.0",
        "999999999999999999999.0.0", "1.2.3-beta.999999999999999999999", "1.2.3-beta.999999999999999999998",
        "1.2.3+01", "1.2.3-a..b", "1 .2.3", "4.17.21", "0.0.1-security",
    ],
    "pip": [
        "1.0", "1.0.0", "1", "1.0a1", "1.0a", "1.0.alpha1", "1.0b2", "1.0rc1", "1.0c1", "1.0.post1", "1.0-1",
        "1.0.dev1",
        "1.0a1.dev1", "1.0.post1.dev1", "1!1.0", "1.0+local.1", "1.0+local.a", "1.0+1", "1.0+abc", "2.0", "10.0",
        "1.0.0.0.1", "v1.0", "1.0-preview", "1.0r1", "1.0rev2", "1..0", "abc", "1.0.x", "1.0-dev", "1.0_post_1",
        "0.9.9", "1.0+ubuntu-1", "1.0+Ubuntu.1", "1.0a1+local", "1.0.dev", "2024.1", "0.0", "", "1.0RC1", "1.0.0-rc.1",
        "6.1.3", "3.13.0",
    ],
    "rust": ["1.0.0", "1.0", "0.1.0", "0.1.0-alpha.1", "1.54.1", "1.2.3+meta", "1.2.3-0.3.7", "abc"],
    "maven": [
        "1.0", "1.0.0", "1", "1-SNAPSHOT", "1.0-SNAPSHOT", "1.0-alpha-1", "1.0-alpha1", "1.0a1", "1.0-beta", "1.0b1",
        "1.0-m1", "1.0-rc1", "1.0-cr1", "1.0-RC2", "1.0.RELEASE", "1.0-ga", "1.0-final", "1.0-sp1", "1.0-foo", "1.0-1",
        "1.0.1", "1.0-0", "1.0--1", "1.0.", "2.0", "1.0.0-jre", "33.0.0-android", "4.2.0-RC2", "1.0.0.Final", "5.3.21",
        "6.1.0-M1", "2.0.0.M1", "abc", "1.0-SNAPSHOT-1", "1.0.0-20200101.120000-1", "1-0", "1..0",
        "1.0-alpha-1-SNAPSHOT", "2.17.1", "2.0-beta9", "1.0-1-1", "1.0.0-0.0", "v2.0", "",
    ],
}  # fmt: skip
OPS = ["<", "<=", ">", ">=", "=", "!="]


def python_affected(eco: str, version: str, op: str, bound: str) -> bool | None:
    """versions.affected for a single constraint, without re-parsing range text."""
    cls = VERSION_CLASS[eco]
    if not version:
        return None
    try:
        v, b = _mk(cls, version), _mk(cls, bound)
        return v != b if op == "!=" else {"<": v < b, "<=": v <= b, ">": v > b, ">=": v >= b, "=": v == b}[op]
    except Exception:
        return None


@pytest.mark.parametrize("eco", sorted(VERSIONS))
def test_version_orderings_match_univers(eco: str) -> None:
    vs = VERSIONS[eco]
    cases = [[eco, a, op, b] for a in vs for b in vs if b for op in OPS]
    got = node([["affected", e, a, [[[op, b]]]] for e, a, op, b in cases])
    diff = [(c, g, python_affected(*c)) for c, g in zip(cases, got, strict=True) if g != python_affected(*c)]
    assert not diff, f"{len(diff)} of {len(cases)} differ, e.g. {diff[:5]}"


VERDICTS = [
    # one upper bound per release line (F-159, F-160): in a line, past its fix, between lines, a pre-release
    ("npm", "2.12.6", "<= 2.12.6, <= 2.11.15", "2.14.0, 2.12.7, 2.11.16"),
    ("npm", "2.11.16", "<= 2.12.6, <= 2.11.15", "2.14.0, 2.12.7, 2.11.16"),
    ("npm", "2.13.1", "<= 2.14.2, <= 2.12.11", "2.14.3, 2.12.12"),
    ("npm", "2.12.0-rc.1", "<= 2.12.6, <= 2.11.15", "2.12.7, 2.11.16"),
    ("npm", "2.12.3", "< 2.12.0, <= 2.14.3", None),
    ("pip", "2.12.0rc1", "<= 2.12.6, <= 2.11.15", "2.12.7, 2.11.16"),
    ("pip", "2.11.20", "<= 2.12.6, <= 2.11.15", "2.12.7, 2.11.16"),
    ("maven", "4.2.0.CR1", "<= 4.1.136.Final, <= 4.2.9.Final", "4.1.137.Final, 4.2.10.Final"),
    ("maven", "4.2.5.Final", "<= 4.1.136.Final, <= 4.2.9.Final", "4.1.137.Final, 4.2.10.Final"),
    ("npm", "1.2.3", "< 1.2.4", "1.2.4"),
    ("npm", "1.2.4", "< 1.2.4", "1.2.4"),
    ("npm", "2.0.1", ">= 1.0.0, < 1.5.0, >= 2.0.0, < 2.0.5", "1.5.0, 2.0.5"),  # commas re-read as "or" (F-085)
    ("npm", "1.6.0", ">= 1.0.0, < 1.5.0, >= 2.0.0, < 2.0.5", "1.5.0, 2.0.5"),
    ("npm", "1.0.0", "<= 3.0.10, 4.0.0", None),
    ("npm", "4.0.0", "<= 3.0.10, 4.0.0", None),
    ("npm", "3.5.0", "<= 3.0.10, 4.0.0", None),
    ("npm", "4.30.0", ">= 4.29.0", "4.30.0"),  # in range, but at the fix: possible (F-051)
    ("npm", "4.29.5", ">= 4.29.0", "4.30.0"),
    ("npm", "1.0.0", None, "1.1.0"),
    ("npm", "1.0.0", "garbage", None),
    ("npm", "1.0.0-beta", "< 1.0.0", None),
    ("npm", "1.0.0+b", "= 1.0.0", None),
    ("npm", "0.9.5", "^0.9.0", None),
    ("npm", "0.10.0", "^0.9.0", None),
    ("npm", "0.9.9", "~0.9.0", None),
    ("npm", "1.2.3", "1.2.0 - 1.3.0", None),
    ("npm", "2.1.0", "< 2.0.3 || >= 2.1.0, < 2.1.4", "2.0.3, 2.1.4"),
    ("npm", "2.0.5", "< 2.0.3 || >= 2.1.0, < 2.1.4", "2.0.3, 2.1.4"),
    ("npm", "1.5.0", "1.2.0 and earlier", None),
    ("npm", "1.2.0", "1.2.0 and earlier", None),
    ("npm", "2.5.0", "2.0.0 to 3.0.0", None),
    ("npm", "1.0", "<= 1.0.0", None),
    ("rust", "1.5.0", "1.0.0..2.0.0", None),  # both readings agree
    ("rust", "2.0.0", "1.0.0..2.0.0", None),  # they disagree: possible
    ("rust", "2.5.0", "1.0.0..2.0.0", None),
    ("rust", "0.3.2", "< 0.3.3", "0.3.3"),
    ("pip", "1.0rc1", "< 1.0", None),
    ("pip", "1.0.post1", "<= 1.0", None),
    ("pip", "2.0", ">=1.0,<2.0", "2.0"),
    ("pip", "1.0", "1.0.0", None),
    ("pip", "1.9.dev1", "< 1.9", None),
    ("pip", "6.1.3", ">= 6.0, < 6.1.4", "6.1.4"),
    ("pip", "6.0.9", ">= 6.1, < 6.1.4; >= 5.2, < 5.2.9", "6.1.4, 5.2.9"),
    ("pip", "1.0", "<= 0.9.x", None),
    ("maven", "1.0-SNAPSHOT", "< 1.0", None),
    ("maven", "1.0.RELEASE", "<= 1.0", None),
    ("maven", "5.3.21", "[5.0.0,5.3.22)", None),
    ("maven", "2.17.0", "< 2.17.1", "2.17.1"),
    ("maven", "2.17.1", ">= 2.0-beta9, < 2.17.1", None),
    ("maven", "2.0-beta10", ">= 2.0-beta9, < 2.17.1", None),
    ("maven", "4.2.0-RC2", "< 4.2.0", None),
    ("maven", "2.0.0.M1", ">= 2.0.0", None),
    ("maven", "1.2.3", "<= 1.2.3, 2.0.0", "1.2.4"),
]


def test_verdicts_match_the_watcher() -> None:
    got = node([["verdict", eco, v, entry(eco, rng, fix)] for eco, v, rng, fix in VERDICTS])
    want = [
        _version(
            Dependency(ecosystem=eco, name="pkg", version=v, source="x"),
            AdvisoryPackage(ecosystem=eco, name="pkg", vulnerable_version_range=rng, patched_versions=fix),
        )[0]
        for eco, v, rng, fix in VERDICTS
    ]
    diff = [(c, g, w) for c, g, w in zip(VERDICTS, got, want, strict=True) if g != w]
    assert not diff, diff
    assert {True, False, None} <= set(want)  # the cases cover every outcome


def _pkg(eco: str, name: str, rng: str, fix: str | None = None) -> AdvisoryPackage:
    return AdvisoryPackage(ecosystem=eco, name=name, vulnerable_version_range=rng, patched_versions=fix)


def _item(ghsa: str, pkgs: list[AdvisoryPackage], status: Status = Status.LIMBO) -> Item:
    adv = RepoAdvisory(
        ghsa_id=ghsa,
        repo="o/r",
        state="published",
        severity="high",
        cve_id="CVE-2026-1",
        packages=tuple(pkgs),
        published_at=datetime(2026, 11, 1, tzinfo=UTC),
        html_url=f"https://github.com/o/r/security/advisories/{ghsa}",
    )
    facts = Facts(ghsa_id=ghsa, repo="o/r", repo_state="published", reviewed=False, cited_cve="CVE-2026-1")
    assessment = Assessment(ghsa_id=ghsa, status=status, cve_label=CveLabel.NONE, likely_permanent=False)
    return Item(adv, facts, assessment, "")


def test_index_holds_advisories_in_limbo_by_normalized_name() -> None:
    items = [
        _item("GHSA-aaaa-aaaa-aaaa", [_pkg("pip", "Foo_Bar", "< 2.0", "2.0")]),
        _item("GHSA-bbbb-bbbb-bbbb", [_pkg("npm", "left-pad", "< 1.3.0")], Status.REVIEWED),
        _item("GHSA-cccc-cccc-cccc", [_pkg("npm", "not a package!", "< 1"), _pkg("go", "example.com/m", "< 1")]),
        _item("GHSA-dddd-dddd-dddd", [_pkg("rust", "serde", "0.1..0.2")]),
    ]
    ix = index(items, "2026-11-09T00:00:00Z")
    assert ix["advisories"] == 2
    assert set(ix["ecosystems"]) == {"npm", "pip", "rust", "maven"}
    assert ix["ecosystems"]["npm"] == {}  # reviewed, and an unusable name, and Go isn't in deps.dev's trees
    (e,) = ix["ecosystems"]["pip"]["foo-bar"]
    assert e["g"] == "GHSA-aaaa-aaaa-aaaa" and e["a"] == [[["<", "2.0"]]] and e["x"] == ["2.0"]
    both = [[[[">=", "0.1"], ["<", "0.2"]]], [[[">=", "0.1"], ["<=", "0.2"]]]]
    assert ix["ecosystems"]["rust"]["serde"][0]["d"] == both
    json.dumps(ix)  # serializable as published
    got = node([["findings", ix, "pip", "foo.bar", "1.5"], ["findings", ix, "pip", "FOO-BAR", "2.0"]])
    assert got == [[["GHSA-aaaa-aaaa-aaaa", True]], []]
