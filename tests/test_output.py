"""Scan state, change detection, output formats and the CI gate (SPEC: formats and exit codes)."""

import json

from limbowatch.models import CveLabel, Dependency, Finding, MatchKind, Unchecked, UnresolvedDependency
from limbowatch.watch import output, state
from limbowatch.watch.match import key


def finding(name: str = "lodash", version: str = "4.17.20", ghsa: str = "GHSA-aaaa-bbbb-cccc", sev: str | None = "high",
            source: str = "package-lock.json", line: int = 7, affected: bool | None = True,
            fixed: str = "4.17.21") -> Finding:  # fmt: skip
    d = Dependency(ecosystem="npm", name=name, version=version, source=source, line=line)
    return Finding(key=key(d, ghsa), dependency=d, ghsa_id=ghsa, url=f"https://github.com/o/r/security/advisories/{ghsa}",
                   repo="o/r", severity=sev, cve=CveLabel.NONE, affected=affected, match=MatchKind.PACKAGE,
                   advisory_package=name, vulnerable_range="< 4.17.21", fixed=fixed, evidence="in range")  # fmt: skip


def report(*fs: Finding, ignored: set[str] | None = None) -> output.Report:
    unresolved = [
        UnresolvedDependency(reason=Unchecked.RANGE_ONLY, source="requirements.txt", name="flask"),
        UnresolvedDependency(reason=Unchecked.NO_REPO, source="go.mod", name="x"),
    ]
    return output.Report(list(fs), unresolved, {"dependencies": 10}, "osv-scanner 2.7.0", "2026-11-05T22:03:46Z",
                         ignored=ignored or set())  # fmt: skip


def test_state_diff_reports_new_changed_visible_and_fixed() -> None:
    a, b, c = (
        finding(),
        finding(name="qs", ghsa="GHSA-1111-2222-3333"),
        finding(name="gone", ghsa="GHSA-9999-8888-7777"),
    )
    s1, ch1 = state.diff(None, [a, b, c], "t1", set())
    assert [x.kind for x in ch1] == [state.ChangeKind.NEW] * 3
    up = finding(version="4.17.19")  # same key: an upgrade inside the range is a change, not a new finding
    s2, ch2 = state.diff(s1, [up], "t2", visible={"GHSA-1111-2222-3333"})
    kinds = {(x.kind, x.ghsa_id) for x in ch2}
    assert kinds == {
        (state.ChangeKind.CHANGED, "GHSA-aaaa-bbbb-cccc"),
        (state.ChangeKind.VISIBLE, "GHSA-1111-2222-3333"),  # reached OSV: the usual scanner reports it now
        (state.ChangeKind.FIXED, "GHSA-9999-8888-7777"),
    }
    assert s2["findings"][up.key]["first_seen"] == "t1"
    assert state.vanished(s1, [up]) == {"GHSA-1111-2222-3333", "GHSA-9999-8888-7777"}
    _, ch3 = state.diff(s2, [up], "t3", set())
    assert ch3 == []


def test_gate() -> None:
    assert output.gate(report(finding(sev="low")), "low")
    assert not output.gate(report(finding(sev="low")), "high")
    assert output.gate(report(finding(sev=None)), "critical")  # unscored fails by default (PHASE0_PLAN §13.4)
    assert not output.gate(report(finding(sev=None)), "critical", fail_on_unknown=False)
    assert not output.gate(report(finding(), ignored={"ghsa-aaaa-bbbb-cccc"}), "low")
    assert not output.gate(report(finding(sev="critical")), "none")
    assert not output.gate(report(), "low")


def test_formats_carry_findings_unresolved_and_attribution() -> None:
    r = report(
        finding(), finding(source="other/package-lock.json", line=3), finding(name="p", ghsa="GHSA-p", affected=None)
    )
    text = output.table(r)
    assert "2 advisories in limbo affect 2 packages" in text and "HIGH?" in text  # ? marks a possible finding
    assert "other/package-lock.json:3, package-lock.json:7" in text
    assert "1 dependency can't be checked; 1 was checked by name only." in text
    assert output.ATTRIBUTION in text
    md = output.markdown(r)
    assert "| high | [GHSA-aaaa-bbbb-cccc]" in md and "high (possibly)" in md and output.ATTRIBUTION in md
    doc = json.loads(output.as_json(r))
    assert len(doc["findings"]) == 3 and doc["attribution"] == output.ATTRIBUTION and len(doc["unresolved"]) == 2

    cq = json.loads(output.codequality(r))
    assert len(cq) == 3 and len({i["fingerprint"] for i in cq}) == 3
    for item in cq:
        assert {"description", "check_name", "fingerprint", "severity", "location"} <= set(item)
        assert item["severity"] in ("info", "minor", "major", "critical", "blocker")
        assert isinstance(item["location"]["lines"]["begin"], int) and not item["location"]["path"].startswith("./")

    sarif = json.loads(output.sarif(r))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and len(run["results"]) == 3 and len(run["tool"]["driver"]["rules"]) == 2
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] in (3, 7)
    assert run["properties"]["attribution"] == output.ATTRIBUTION


def test_fixed_version_for_the_release_line() -> None:
    f = finding(name="@sinclair/typebox", version="0.27.10", fixed="0.26.9, 0.27.12, 0.28.22")
    assert "0.27.12 (for 0.27.x)" in output.table(report(f))


def test_ignored_findings_are_listed_not_failed() -> None:
    r = report(finding(), ignored={"GHSA-aaaa-bbbb-cccc"})
    assert "Accepted (ignored): GHSA-aaaa-bbbb-cccc" in output.table(r)
    assert json.loads(output.codequality(r)) == []


def test_machine_formats_give_paths_from_the_repo_root() -> None:
    """A scan of a subdirectory (the component's `path:` input) must point Code Quality and SARIF at
    `services/api/<lockfile>`, which is where GitLab and code scanning look the file up."""
    r = report(finding())
    src = r.findings[0].dependency.source.removeprefix("./")
    assert json.loads(output.codequality(r))[0]["location"]["path"] == src
    r.base = "services/api"
    cq = json.loads(output.codequality(r))[0]["location"]["path"]
    uri = json.loads(output.sarif(r))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert cq == uri["uri"] == f"services/api/{src}"


def test_unchecked_line_agrees_in_number() -> None:
    assert output._unchecked_line(2, 0) == "2 dependencies can't be checked; 0 were checked by name only."
    assert output._unchecked_line(1, 1) == "1 dependency can't be checked; 1 was checked by name only."
