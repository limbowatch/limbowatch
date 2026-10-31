from conftest import load
from limbowatch.classify import assess, cve_label, status, transitions
from limbowatch.models import CveLabel, Facts, Status
from limbowatch.normalize import repo_advisory


def facts(**kw: object) -> Facts:
    base: dict[str, object] = {
        "ghsa_id": "SOTTO_SECRET_5d4ef0b1",
        "repo": "o/r",
        "repo_state": "published",
        "reviewed": False,
    }
    return Facts.model_validate(base | kw)


def test_status_order() -> None:
    assert status(facts()) is Status.LIMBO
    assert status(facts(reviewed=True)) is Status.REVIEWED
    assert status(facts(in_osv=True)) is Status.REVIEWED
    assert status(facts(repo_state="withdrawn")) is Status.WITHDRAWN
    assert status(facts(repo_state="gone")) is Status.NOT_PUBLISHED
    assert status(facts(duplicate_of=("SOTTO_SECRET_6c0f6e6a",))) is Status.DUPLICATE


def test_cve_labels() -> None:
    assert cve_label(facts()) is CveLabel.NONE
    assert cve_label(facts(cited_cve="CVE-1", cited_cve_state="RESERVED")) is CveLabel.RESERVED
    assert cve_label(facts(cited_cve="CVE-1", cited_cve_state="PUBLISHED")) is CveLabel.PUBLISHED_CITED
    assert cve_label(facts(uncited_cves=("CVE-2",))) is CveLabel.PUBLISHED_UNCITED


def test_unsupported_ecosystem_is_likely_permanent() -> None:
    raw = dict(load("repo_advisories_regexp2.json")[0])
    raw["vulnerabilities"] = [{"package": {"ecosystem": "c++/c", "name": "x"}}]
    adv = repo_advisory(raw, "o/r")
    assert assess(adv, facts()).likely_permanent
    adv2 = repo_advisory(load("repo_advisories_regexp2.json")[0], "dlclark/regexp2")
    assert not assess(adv2, facts()).likely_permanent


def test_transitions() -> None:
    old = facts(cited_cve="CVE-1", cited_cve_state="RESERVED")
    assert transitions(None, old) == ["first seen"]
    assert transitions(old, old) == []
    new = facts(cited_cve="CVE-1", cited_cve_state="PUBLISHED", reviewed=True, uncited_cves=("CVE-9",))
    ev = transitions(old, new)
    assert "in limbo -> reviewed" in ev
    assert "CVE-1 RESERVED -> PUBLISHED" in ev
    assert "new CVE from another CNA: CVE-9" in ev
    gh = facts(uncited_cves=("CVE-8", "CVE-9"))
    assert transitions(facts(), gh, {"CVE-8": "GitHub_M", "CVE-9": "VulnCheck"}) == [
        "new CVE from GitHub's CNA, not cited: CVE-8",
        "new CVE from another CNA: CVE-9",
    ]
