"""The home page's proof numbers: what `limbowatch scan` reports for the proof repository's pins (F-201)."""

from __future__ import annotations

import json
from importlib.resources import files

import pytest
from limbowatch.publish import site
from limbowatch.publish.proof import PINS, counts
from test_match import rec

PIN = [{"ecosystem": "PyPI", "name": "scapy", "version": "2.7.0", "repo": "secdev/scapy", "file": "requirements.txt"}]
GO = [
    {
        "ecosystem": "Go",
        "name": "github.com/nats-io/nats-server/v2",
        "version": "v2.12.6",
        "repo": "nats-io/nats-server",
        "file": "go.mod",
    }
]


def sev(r: dict, s: str) -> dict:
    r["database_specific"]["limbowatch"]["severity"] = s
    return r


def test_counts_certain_findings_with_a_fix_and_splits_the_serious_ones() -> None:
    p = counts(
        [
            sev(rec("GHSA-a", "secdev/scapy", ("PyPI", "scapy", "< 2.8.0", "2.8.0")), "high"),
            sev(rec("GHSA-b", "secdev/scapy", ("PyPI", "scapy", "<= 2.7.0", "2.7.1")), "low"),
            sev(rec("GHSA-c", "secdev/scapy", ("PyPI", "scapy", "< 2.7.0", "2.7.0")), "critical"),  # not affected
            sev(rec("GHSA-d", "secdev/scapy", ("PyPI", "scapy", "< 2.8.0", None)), "critical"),  # no fix released
            sev(rec("GHSA-e", "secdev/scapy", ("PyPI", "scapy", "nonsense", "2.8.0")), "critical"),  # only possible
            sev(rec("GHSA-f", "other/repo", ("PyPI", "requests", "< 9", "9")), "critical"),  # another package
        ],
        PIN,
    )
    assert p.ids == {"GHSA-a", "GHSA-b"} and p.serious == {"GHSA-a"} and p.total == 2 and p.packages == 1


def test_go_versions_and_other_major_versions() -> None:
    p = counts(
        [
            rec("GHSA-g", "nats-io/nats-server", ("Go", "github.com/nats-io/nats-server/v2", "< 2.12.7", "2.12.7")),
            # the module without /v2: a maintainer's slip, so `limbowatch scan` says only "possibly affected"
            rec("GHSA-h", "nats-io/nats-server", ("Go", "github.com/nats-io/nats-server", "<= 2.14.8", "2.14.9")),
        ],
        GO,
    )
    assert p.ids == {"GHSA-g"} and p.serious == {"GHSA-g"}


def test_pins_are_the_proof_repositorys_and_well_formed() -> None:
    data = json.loads(files("limbowatch.publish").joinpath("proof.json").read_text())
    assert data["proof"] == site.POC_URL and len(PINS) == 7
    assert all(set(p) == {"ecosystem", "name", "version", "repo", "file"} for p in PINS)
    with pytest.raises(ValueError, match="unknown ecosystem"):
        counts([], [{**PIN[0], "ecosystem": "Nope"}])


def test_home_page_shows_the_counts_or_nothing() -> None:
    p = counts([sev(rec("GHSA-a", "secdev/scapy", ("PyPI", "scapy", "< 2.8.0", "2.8.0")), "high")], PIN)
    html = site.proof_pair(p)
    assert '<p class="rv">0</p>' in html and '<p class="rv">1</p>' in html
    assert "of 1 high and critical advisories" in html and "(1 in all, counting medium and low)" in html
    assert site.proof_pair(None) == "" and site.proof_pair(counts([], PIN)) == ""
