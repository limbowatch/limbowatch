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
    assert "\nother/package-lock.json\n" in text and "\npackage-lock.json\n" in text  # one table per lockfile
    assert "To fix: upgrade 2 packages" in text and "lodash  4.17.20 → 4.17.21" in text
    assert text.rstrip().endswith("FAILED  3 findings at or above low (--fail-on low): 3 high.")
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
    text = output.table(report(f))
    assert "@sinclair/typebox  0.27.10 → 0.27.12" in text and "0.26.9" not in text


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


def test_upgrade_target_is_the_highest_fix_by_version_not_text() -> None:
    a = finding(fixed="4.17.9", ghsa="GHSA-1111-1111-1111", version="4.17.8")
    b = finding(fixed="4.17.10", ghsa="GHSA-2222-2222-2222", version="4.17.8")  # "4.17.10" < "4.17.9" as text
    (u,) = output.upgrades(report(a, b))
    assert u.to == "4.17.10" and u.fixed_by_to == 2 and u.advisories == ("GHSA-1111-1111-1111", "GHSA-2222-2222-2222")
    c = finding(fixed="tbd", ghsa="GHSA-3333-3333-3333", version="4.17.8")
    (u,) = output.upgrades(report(a, c))
    assert u.to == "4.17.9" and u.fixed_by_to == 1 and "check the rest" in output._upgrade_note(u)


def test_gate_follows_the_report_and_json_says_so() -> None:
    r = report(finding(sev="low"), finding(name="qs", ghsa="GHSA-1111-2222-3333", sev="high"))
    r.fail_on = "high"
    assert r.failed and output.verdict(r) == (True, "1 finding at or above high (--fail-on high): 1 high.")
    doc = json.loads(output.as_json(r))
    assert doc["schema_version"] == 1 and doc["gate"]["failed"] and doc["gate"]["failing_findings"] == 1
    assert doc["gate"]["message"] == "1 finding at or above high (--fail-on high): 1 high."
    assert doc["summary"]["by_severity"] == {"critical": 0, "high": 1, "medium": 0, "low": 1, "unknown": 0}
    assert [f["fails_build"] for f in doc["findings"]] == [True, False]
    r.fail_on = "none"
    assert output.verdict(r) == (False, "2 findings; --fail-on none never fails the build.")
    assert output.verdict(report()) == (False, "No dependency is affected by an advisory in limbo.")


def test_junit_fails_only_what_fails_the_build() -> None:
    from xml.etree import ElementTree

    r = report(finding(sev="low"), finding(name="qs", ghsa="GHSA-1111-2222-3333", sev="high"),
               finding(name="ok", ghsa="GHSA-9999-9999-9999"), ignored={"GHSA-9999-9999-9999"})  # fmt: skip
    r.fail_on = "high"
    root = ElementTree.fromstring(output.junit(r))
    assert (root.get("tests"), root.get("failures"), root.get("skipped")) == ("3", "1", "2")
    (failure,) = root.iter("failure")
    assert failure.get("type") == "high" and "upgrade qs to 4.17.21" in (failure.get("message") or "")
    empty = ElementTree.fromstring(output.junit(report()))
    assert (empty.get("tests"), empty.get("failures")) == ("1", "0")


def test_csv_html_markdown_escape_maintainer_text() -> None:
    page = output.as_html(report(finding(name="<script>x</script>")))
    assert "<script>x" not in page and "&lt;script&gt;x" in page
    md = output.markdown(report(finding(fixed="1.0 | see notes")))  # not plain versions: shown as entered
    assert "1.0 \\| see notes" in md  # a raw pipe would split the table row
    rows = output.as_csv(report(finding(fixed="=HYPERLINK(1)"))).removeprefix("\ufeff").splitlines()
    assert rows[0].startswith("severity,fails_build,advisory") and "'=HYPERLINK(1)" in rows[1]


def test_cyclonedx_links_each_vulnerability_to_its_components() -> None:
    r = report(finding(), finding(name="qs", ghsa="GHSA-1111-2222-3333"),
               finding(name="qs", ghsa="GHSA-aaaa-bbbb-cccc"))  # fmt: skip
    doc = json.loads(output.cyclonedx(r))
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    refs = {c["bom-ref"] for c in doc["components"]}
    assert refs == {"pkg:npm/lodash@4.17.20", "pkg:npm/qs@4.17.20"}
    by_id = {v["id"]: v for v in doc["vulnerabilities"]}
    assert sorted(by_id) == ["GHSA-1111-2222-3333", "GHSA-aaaa-bbbb-cccc"]
    assert {a["ref"] for a in by_id["GHSA-aaaa-bbbb-cccc"]["affects"]} == refs
    assert all(a["ref"] in refs for v in doc["vulnerabilities"] for a in v["affects"])


def test_github_annotations_escape_properties() -> None:
    (line,) = output.github(report(finding(source="a,b/package-lock.json"))).splitlines()
    assert line.startswith("::error file=a%2Cb/package-lock.json,line=7,title=lodash 4.17.20%3A 1 advisory in limbo")
    assert "Upgrade to 4.17.21" in line


def test_github_annotations_are_one_per_package() -> None:
    """GitHub keeps 10 annotations per level per step (F-096): 51 findings in one package must be one annotation."""
    many = [finding(name="scapy", ghsa=f"GHSA-{i:04d}-aaaa-bbbb", sev="medium" if i else "high") for i in range(51)]
    r = report(*many, finding(name="qs", ghsa="GHSA-1111-2222-3333", sev="low"))
    r.fail_on = "high"
    lines = output.github(r).splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("::error ")
    assert "scapy 4.17.20%3A 51 advisories in limbo (1 high%2C 50 medium)" in lines[0]
    assert "and 43 more" in lines[0]
    assert lines[1].startswith("::notice ")  # low, below --fail-on


def test_table_cuts_long_packages_but_keeps_what_matters() -> None:
    many = [finding(name="scapy", ghsa=f"GHSA-{i:04d}-aaaa-bbbb", sev="high" if i < 4 else "low") for i in range(51)]
    r = report(*many)
    r.fail_on = "high"
    text = output.table(r)
    assert all(f"GHSA-000{i}-aaaa-bbbb" in text for i in range(4))  # every high row is shown
    assert "+47 more for scapy 4.17.20 (47 low); -v lists them" in text
    assert "+47 more" not in output.table(r, verbose=True)
    few = report(*many[:4], many[4])  # one left over: shown, not cut
    assert "more for scapy" not in output.table(few)


def test_colour_only_when_asked() -> None:
    r = report(finding())
    assert "\x1b[" not in output.table(r)
    coloured = output.table(r, paint=output.Paint(color=True, links=True))
    assert "\x1b[31mHIGH" in coloured and "\x1b]8;;https://github.com/o/r/security/advisories/" in coloured


def test_one_advisory_in_two_files_counts_once() -> None:
    a = finding(source="go.mod")
    b = finding(source="vendor/go.mod", line=3)  # the same package and advisory, declared twice
    (u,) = output.upgrades(report(a, b))
    assert u.advisories == ("GHSA-aaaa-bbbb-cccc",) and u.fixed_by_to == 1
    assert output._upgrade_note(u) == "clears 1 advisory"


def test_our_own_cyclonedx_report_is_not_read_as_an_sbom() -> None:
    from limbowatch.inventory.osv_scanner import own_report

    assert own_report(output.cyclonedx(report(finding())))
    sbom = json.dumps({"bomFormat": "CycloneDX", "metadata": {"tools": {"components": [{"name": "syft"}]}}})
    assert not own_report(sbom) and not own_report("not json limbowatch CycloneDX")


def test_markdown_folds_long_tables() -> None:
    many = [finding(name="scapy", ghsa=f"GHSA-{i:04d}-aaaa-bbbb", sev="high" if i < 2 else "low") for i in range(30)]
    r = report(*many)
    r.fail_on = "high"
    md = output.markdown(r)
    assert "### Findings that fail the build (2)" in md and "<details><summary>All 30 findings</summary>" in md
    assert "findings</summary>" not in output.markdown(report(*many[:5]))
