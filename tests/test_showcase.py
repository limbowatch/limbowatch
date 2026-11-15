"""The popular projects the home page counts: matching their dependencies against the feed (F-203)."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from limbowatch.publish import site
from limbowatch.publish.showcase import counts
from test_match import rec

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 15, 12, tzinfo=UTC)


def adv(ghsa: str, repo: str, pkg: tuple[str, str, str | None, str | None], severity: str = "high",
        published: str = "2026-10-01T00:00:00Z") -> dict[str, Any]:  # fmt: skip
    r = rec(ghsa, repo, pkg)
    r["database_specific"]["limbowatch"]["severity"] = severity
    r["published"] = published
    return r


FEED = [
    adv("GHSA-a", "secdev/scapy", ("PyPI", "scapy", "< 2.8.0", "2.8.0"), "high", "2026-09-01T00:00:00Z"),
    adv("GHSA-b", "secdev/scapy", ("PyPI", "scapy", "<= 2.7.0", "2.7.1"), "low"),
    adv("GHSA-c", "secdev/scapy", ("PyPI", "scapy", "< 2.8.0", None), "critical"),  # no fix: not counted
    adv("GHSA-d", "nats-io/nats-server", ("Go", "github.com/nats-io/nats-server/v2", "< 2.12.7", "2.12.7"), "critical"),
    adv("GHSA-e", "nats-io/nats-server", ("Go", "github.com/nats-io/nats-server", "< 2.14.9", "2.14.9")),  # possible
    adv("GHSA-f", "lodash/lodash", ("npm", "lodash", "< 4.17.22", "4.17.22"), "medium"),
]
DATA = {
    "scanned_at": "2026-11-15T04:41:00Z",
    "tool": "osv-scanner 2.7.1",
    "projects": [
        {"repo": "acme/shop", "commit": "abc1234", "dependencies": [
            ["pip", "scapy", "2.7.0", "requirements.txt"],
            ["go", "github.com/nats-io/nats-server/v2", "2.12.6", "go.mod"],
            ["npm", "left-pad", "1.0.0", "package-lock.json"]]},
        {"repo": "acme/core", "commit": "def5678", "dependencies": [
            ["pip", "scapy", "2.7.0", "uv.lock"], ["npm", "lodash", "4.17.21", "package-lock.json"]]},
        {"repo": "acme/clean", "commit": "0000000", "dependencies": [["pip", "scapy", "2.8.0", "uv.lock"]]},
        {"repo": "acme/gone", "error": "RuntimeError: clone failed"},
    ],
}  # fmt: skip


def test_counts_per_project_and_in_total() -> None:
    sc = counts(FEED, DATA)
    by = {p.repo: p for p in sc.projects}
    assert by["acme/shop"].ids == {"GHSA-a", "GHSA-b", "GHSA-d"} and by["acme/shop"].serious == {"GHSA-a", "GHSA-d"}
    assert by["acme/core"].ids == {"GHSA-a", "GHSA-b", "GHSA-f"}
    assert by["acme/clean"].ids == set() and by["acme/gone"].error == "RuntimeError: clone failed"
    assert sc.ids == {"GHSA-a", "GHSA-b", "GHSA-d", "GHSA-f"} and sc.serious == {"GHSA-a", "GHSA-d"}
    assert [p.repo for p in sc.affected] == ["acme/shop", "acme/core"] and len(sc.read) == 3


def test_packages_by_reach_with_one_fix_for_all() -> None:
    sc = counts(FEED, DATA)
    first = sc.packages[0]
    assert (first.name, first.versions, first.projects) == ("scapy", ("2.7.0",), ("acme/core", "acme/shop"))
    assert first.ids == {"GHSA-a", "GHSA-b"} and first.worst == "high" and first.worst_id == "GHSA-a"
    assert first.fix == "2.8.0" and first.oldest == datetime(2026, 9, 1, tzinfo=UTC)
    assert [k.name for k in sc.packages] == ["scapy", "github.com/nats-io/nats-server/v2", "lodash"]


def test_home_page_and_popular_page() -> None:
    sc = counts(FEED, DATA)
    pair = site.showcase_pair(sc)
    assert '<p class="rv">0</p>' in pair and '<p class="rv">2</p>' in pair and "(4 in all" in pair
    assert "3 popular open-source projects, such as shop and acme, checked" in pair  # acme/core reads as its owner
    assert "2 of them pin" in pair
    cards = site.showcase_section(sc, NOW)
    assert cards.count('class="exc"') == 3 and "nats-io/nats-server/v2" in cards and "Pinned by" in cards
    assert '<a class="exc" href="/advisory/GHSA-a/">' in cards and "75 days" in cards
    page = site.popular(sc)
    assert (
        "acme/gone" in page
        and "couldn’t be read today" in page
        and 'href="https://github.com/acme/shop/tree/abc1234"' in page
    )
    data = json.loads(site.popular_data(sc))
    assert data["advisories"] == 4 and data["projects"][0]["advisories"] == ["GHSA-a", "GHSA-b", "GHSA-d"]
    assert data["projects"][3] == {"repo": "acme/gone", "commit": None, "dependencies": 0, "advisories": [],
                                   "high_or_critical": [], "error": "RuntimeError: clone failed"}  # fmt: skip


def test_nothing_to_show_falls_back() -> None:
    empty = counts(FEED, {"projects": [{"repo": "acme/gone", "error": "x"}]})
    assert site.showcase_pair(empty) == "" and site.showcase_section(empty, NOW) == ""
    assert site.showcase_pair(None) == "" and site.showcase_section(None, NOW) == ""


def test_labels() -> None:
    assert site.project_label("home-assistant/core") == "home-assistant" and site.project_label("n8n-io/n8n") == "n8n"
    assert (
        site.package_label("go", "github.com/jackc/pgx/v5") == "jackc/pgx/v5"
        and site.package_label("npm", "a/b") == "a/b"
    )


def _script() -> Any:
    spec = importlib.util.spec_from_file_location("showcase_script", ROOT / "scripts" / "showcase.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["showcase_script"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_project_list(tmp_path: Path) -> None:
    script = _script()
    names = script.projects(ROOT / "tracker" / "showcase" / "projects.txt")
    assert len(names) == 55 and "n8n-io/n8n" in names and "kubernetes/kubernetes" in names
    (tmp_path / "p.txt").write_text("# c\na/b\n\na/b  # again\n")
    with pytest.raises(ValueError, match="twice"):
        script.projects(tmp_path / "p.txt")
    (tmp_path / "p.txt").write_text("https://github.com/a/b\n")
    with pytest.raises(ValueError, match="owner/name"):
        script.projects(tmp_path / "p.txt")


def test_a_package_at_several_versions_is_one_card() -> None:
    data = {"projects": [
        {"repo": "a/one", "commit": "1", "dependencies": [["pip", "scapy", "2.6.0", "uv.lock"]]},
        {"repo": "a/two", "commit": "2", "dependencies": [["pip", "scapy", "2.7.0", "uv.lock"]]},
        {"repo": "a/three", "commit": "3", "dependencies": [["pip", "scapy", "2.7.0", "uv.lock"]]},
    ]}  # fmt: skip
    (k,) = counts(FEED, data).packages
    assert k.versions == ("2.6.0", "2.7.0") and len(k.projects) == 3 and k.fix == "2.8.0"
    card = site.showcase_section(counts(FEED, data), NOW)
    assert "2 versions" in card and "3 of 3 projects" in card
