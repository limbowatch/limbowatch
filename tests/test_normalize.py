from conftest import load
from limbowatch.normalize import cve_record, repo_advisory, reviewed_entry

FORBIDDEN = ("REDACTED", "redacted")


def test_repo_advisory_keeps_facts_only() -> None:
    raw = load("repo_advisories_regexp2.json")[0]
    adv = repo_advisory(raw, "dlclark/regexp2")
    assert adv.ghsa_id == "GHSA-wq9v-j77v-qr26"
    assert adv.cve_id == "CVE-2026-77299"
    assert adv.packages[0].name == "github.com/dlclark/regexp2"
    assert adv.packages[0].vulnerable_version_range == "< 2.3.0"
    assert adv.cvss_v3_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    assert adv.cwe_ids == ("CWE-400", "CWE-770")
    dumped = adv.model_dump_json()
    assert not any(f in dumped for f in FORBIDDEN), "summary/description/author/credits must be dropped (F-047)"


def test_empty_string_cve_is_none() -> None:
    raw = dict(load("repo_advisories_regexp2.json")[0], cve_id="")
    assert repo_advisory(raw, "dlclark/regexp2").cve_id is None


def test_cve_record_finds_ghsa_and_repo_refs_case_insensitively() -> None:
    info = cve_record(load("cve_CVE-2026-110858.json"))
    assert info.cna == "VulnCheck"
    assert info.state == "PUBLISHED"
    assert "GHSA-F9J4-QGGQ-H239" in info.ghsa_refs  # upper-cased (F-050)
    assert "gitpython-developers/gitpython" in info.repo_refs


def test_reviewed_entry_origin_repo() -> None:
    e = reviewed_entry(load("reviewed_page.json")[0])
    assert e.origin_repo == "gitpython-developers/gitpython"
    assert e.reviewed_at is not None
