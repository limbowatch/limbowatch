"""The watcher's inventory reports every dependency it can't check (SPEC; FINDINGS F-078).

`osv_scanner.json` / `.stderr` are OSV-Scanner 2.7.0's real output for `fixtures/inventory/proj`,
recorded offline with paths rewritten to /ROOT.
"""

import json
import shutil
from pathlib import Path

import pytest
from conftest import FIXTURES
from limbowatch.inventory import checks, osv_scanner, purl, sbom
from limbowatch.models import Unchecked

INV = FIXTURES / "inventory"
ROOT = Path("/ROOT")


def _read(p: Path) -> str | None:
    f = INV / "proj" / p.relative_to(ROOT)
    return f.read_text() if f.exists() else None


def _recorded() -> object:
    return osv_scanner.parse(
        json.loads((INV / "osv_scanner.json").read_text()), (INV / "osv_scanner.stderr").read_text(), 127, ROOT, _read
    )


def test_osv_scanner_inventory_checks_what_it_can() -> None:
    inv = _recorded()
    got = {(d.ecosystem, d.name, d.version, d.source) for d in inv.dependencies}  # type: ignore[attr-defined]
    assert got == {
        ("npm", "@vendure/core", "3.0.0", "npm/package-lock.json"),
        ("npm", "no-resolved", "1.0.0", "npm/package-lock.json"),  # no `resolved`, but a registry package (#3177)
        ("go", "github.com/gin-gonic/gin", "1.9.1", "go/go.mod"),
        ("rust", "serde", "1.0.200", "cargo/Cargo.lock"),
        ("pip", "requests", "2.31.0", "py/requirements.txt"),
    }
    by_name = {d.name: d for d in inv.dependencies}  # type: ignore[attr-defined]
    assert by_name["no-resolved"].note and "3177" in by_name["no-resolved"].note
    assert by_name["requests"].line == 1 and by_name["serde"].line == 4
    assert by_name["@vendure/core"].line == 3


def test_osv_scanner_inventory_names_everything_else() -> None:
    inv = _recorded()
    got = {(u.reason, u.source, u.name) for u in inv.unresolved}  # type: ignore[attr-defined]
    assert got == {
        (Unchecked.LOCKFILE_UNREADABLE, "bad/package-lock.json", ""),
        (Unchecked.LOCAL, "npm/package-lock.json", "local-thing"),
        (Unchecked.VCS, "npm/package-lock.json", "https://github.com/owner/gitdep"),
        (Unchecked.PATH, "go/go.mod", "../local"),
        (Unchecked.LOCAL, "cargo/Cargo.lock", "mylocal"),
        (Unchecked.VCS, "cargo/Cargo.lock", "gitcrate"),  # reported as crates.io by OSV-Scanner
        (Unchecked.RANGE_ONLY, "py/requirements.txt", "flask"),  # reported as version "2"
        (Unchecked.NO_VERSION, "py/requirements.txt", "numpy"),
        (Unchecked.VCS, "py/requirements.txt", "pkg"),  # left out by OSV-Scanner
        (Unchecked.PATH, "py/requirements.txt", ""),  # -e ./localpkg, left out too
    }
    assert "bad/package-lock.json" not in inv.sources  # type: ignore[attr-defined]


def test_osv_scanner_exit_codes() -> None:
    none = osv_scanner.parse({}, "", 128, ROOT, _read)
    assert [u.reason for u in none.unresolved] == [Unchecked.NO_LOCKFILES]
    with pytest.raises(osv_scanner.InventoryError):
        osv_scanner.parse({}, "something else broke", 127, ROOT, _read)


def test_osv_scanner_groups_unreadable_files_of_one_kind() -> None:
    """Several unreadable files of one kind follow the error line, one per tab-indented line (F-131).
    Recorded from OSV-Scanner 2.7.0, paths rewritten; it drops their leading "/" (F-078)."""
    stderr = (
        "Error during extraction: (extracting as java/pomxml) ROOT/a/pom.xml: could not extract pom from "
        "ROOT/a/pom.xml: EOF\n"
        "Error during extraction: (extracting as javascript/packagelockjson) \n"
        "\tROOT/w1/package-lock.json: could not extract: invalid character 'x' looking for beginning of object key "
        "string\n"
        "\tROOT/w2/package-lock.json: could not extract: invalid character 'x' looking for beginning of object key "
        "string\n"
        "No package sources found, --help for usage information.\n"
    )
    inv = osv_scanner.parse({}, stderr, 127, ROOT, _read)
    got = [(u.reason, u.source) for u in inv.unresolved]
    assert got == [(Unchecked.LOCKFILE_UNREADABLE, p) for p in ("a/pom.xml", "w1/package-lock.json",
                                                               "w2/package-lock.json")]  # fmt: skip
    assert inv.unresolved[1].detail.startswith("could not extract: invalid character")


MAVEN = INV / "maven"


def _maven(resolve: bool = True, stderr: str | None = None) -> object:
    """`maven/proj` (hand-made), recorded with OSV-Scanner 2.7.0: offline, then the pom.xml-only resolving run
    (F-132), paths rewritten to /ROOT."""

    def read(p: Path) -> str | None:
        f = MAVEN / "proj" / p.relative_to(ROOT)
        return f.read_text() if f.exists() else None

    res = osv_scanner.Resolution(
        json.loads((MAVEN / "resolved.json").read_text()), stderr or (MAVEN / "resolved.stderr").read_text()
    )
    return osv_scanner.parse(
        json.loads((MAVEN / "offline.json").read_text()), (MAVEN / "offline.stderr").read_text(), 0, ROOT, read,
        maven=res if resolve else None, resolve_maven=resolve,
        gradle_builds=osv_scanner.gradle_builds(MAVEN / "proj"),
    )  # fmt: skip


def test_maven_resolution_matches_maven() -> None:
    """app/pom.xml's dependencies are exactly what `mvn dependency:list` resolves (recorded beside it), the
    BOM-managed one included; a pom.xml whose dependencies have none of their own is resolved too."""
    inv = _maven()
    app = {(d.name, d.version) for d in inv.dependencies if d.source == "app/pom.xml"}  # type: ignore[attr-defined]
    mvn = set()
    for ln in (MAVEN / "app.mvn-dependency-list.txt").read_text().splitlines():
        if ln.startswith("   "):
            g, a, _, v, _ = ln.split(" -- ")[0].strip().split(":")
            mvn.add((f"{g}:{a}", v))
    assert app == mvn and len(mvn) == 6
    by = {(u.source, u.reason) for u in inv.unresolved}  # type: ignore[attr-defined]
    assert ("app/pom.xml", Unchecked.NO_VERSION) not in by  # jackson-databind's version came from the BOM
    assert ("leaf/pom.xml", Unchecked.TRANSITIVE) not in by
    assert {(d.name, d.version) for d in inv.dependencies if d.source == "leaf/pom.xml"} == {  # type: ignore[attr-defined]
        ("javax.inject:javax.inject", "1")
    }


def test_unresolved_pom_and_unlocked_gradle_are_reported() -> None:
    inv = _maven()
    got = {(u.reason, u.source) for u in inv.unresolved}  # type: ignore[attr-defined]
    assert got == {(Unchecked.TRANSITIVE, "mod/pom.xml"), (Unchecked.NO_GRADLE_LOCKFILE, "svc/build.gradle")}
    mod = next(u for u in inv.unresolved if u.source == "mod/pom.xml")  # type: ignore[attr-defined]
    assert "com.example:sibling" in mod.detail  # the unreleased sibling module it depends on
    assert {d.name for d in inv.dependencies if d.source == "mod/pom.xml"} == {  # type: ignore[attr-defined]
        "com.example:sibling", "javax.inject:javax.inject"}  # fmt: skip
    assert "com.google.guava:guava" in {d.name for d in inv.dependencies}  # type: ignore[attr-defined]


def test_without_resolution_every_pom_says_so() -> None:
    inv = _maven(resolve=False)
    trans = sorted(u.source for u in inv.unresolved if u.reason is Unchecked.TRANSITIVE)  # type: ignore[attr-defined]
    assert trans == ["app/pom.xml", "leaf/pom.xml", "mod/pom.xml"]
    assert ("com.fasterxml.jackson.core:jackson-databind", Unchecked.NO_VERSION) in {
        (u.name, u.reason)
        for u in inv.unresolved  # type: ignore[attr-defined]
    }
    assert {d.source for d in inv.dependencies} >= {"app/pom.xml"}  # type: ignore[attr-defined]
    assert len([d for d in inv.dependencies if d.source == "app/pom.xml"]) == 1  # type: ignore[attr-defined]


def test_a_failed_resolving_run_reports_every_pom() -> None:
    def read(p: Path) -> str | None:
        f = MAVEN / "proj" / p.relative_to(ROOT)
        return f.read_text() if f.exists() else None

    inv = osv_scanner.parse(
        json.loads((MAVEN / "offline.json").read_text()), "", 0, ROOT, read,
        maven=osv_scanner.Resolution({}, "", "resolving timed out after 900 s"),
    )  # fmt: skip
    trans = {u.source: u.detail for u in inv.unresolved if u.reason is Unchecked.TRANSITIVE}
    assert set(trans) == {"app/pom.xml", "leaf/pom.xml", "mod/pom.xml"} and "timed out" in trans["app/pom.xml"]


def test_pom_files_count_as_maven_manifests() -> None:
    assert osv_scanner._is_pom("a/pom.xml") and osv_scanner._is_pom("repo/x/1.0/x-1.0.pom")
    assert not osv_scanner._is_pom("pom.xml.bak") and not osv_scanner._is_pom("a/xpom.xml")


def test_maven_command_enables_only_the_pom_plugins() -> None:
    cmd = osv_scanner.maven_command("osv-scanner", Path("/p"), Path("/db"))
    assert cmd[cmd.index("--x-plugins") + 1] == "java/pomxml,transitivedependency/pomxml"
    assert "--x-no-default-plugins" in cmd and "--offline-vulnerabilities" in cmd and "--offline" not in cmd


@pytest.mark.skipif(shutil.which("osv-scanner") is None, reason="osv-scanner not installed")
def test_osv_scanner_runs_offline_on_the_fixture_tree(tmp_path: Path) -> None:
    shutil.copytree(INV / "proj", tmp_path / "proj")
    inv = osv_scanner.run(tmp_path / "proj", resolve_maven=False)  # tests never hit the network
    assert {d.name for d in inv.dependencies} >= {"@vendure/core", "requests", "serde"}
    assert any(u.reason is Unchecked.LOCKFILE_UNREADABLE for u in inv.unresolved)


def test_requirements_classification() -> None:
    text = (
        "requests==2.31.0\nflask>=2\nDjango [bcrypt] == 4.2.1 ; python_version >= '3.10'\n"
        "pkg @ https://example.com/pkg.tar.gz\n-e git+https://github.com/o/r.git#egg=Thing\n"
        "--hash=sha256:abc\nnumpy \\\n  ==1.26.4 \\\n  --hash=sha256:def\n./wheels/x-1.0-py3-none-any.whl\n# comment\n"
    )
    got = [(r.name, r.kind, r.line) for r in checks.requirements(text)]
    assert got == [
        ("requests", "pinned", 1),
        ("flask", "range", 2),
        ("django", "pinned", 3),
        ("pkg", "vcs", 4),
        ("thing", "vcs", 5),
        ("numpy", "pinned", 7),
        ("", "path", 10),
    ]


def test_purl_names_per_ecosystem() -> None:
    cases = {
        "pkg:npm/%40scope/name@1.0.0": ("npm", "@scope/name", "1.0.0"),
        "pkg:maven/org.example/lib@2.1": ("maven", "org.example:lib", "2.1"),
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1": ("go", "github.com/gin-gonic/gin", "v1.9.1"),
        "pkg:pypi/requests@2.31.0?arch=any": ("pip", "requests", "2.31.0"),
        "pkg:composer/vendor/package@1.0": ("composer", "vendor/package", "1.0"),
    }
    for ref, (eco, name, ver) in cases.items():
        p = purl.parse(ref)
        assert p is not None and purl.package(p) == (eco, name) and p.version == ver
    assert purl.parse("not a purl") is None
    p = purl.parse("pkg:deb/debian/curl@7.0")
    assert p is not None and purl.package(p) is None


def test_sbom_inventory() -> None:
    cdx = {
        "bomFormat": "CycloneDX",
        "components": [
            {"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
            {"type": "library", "name": "nopurl", "version": "1.0"},
            {"type": "library", "name": "curl", "version": "7", "purl": "pkg:deb/debian/curl@7"},
            {"type": "library", "name": "outer", "purl": "pkg:pypi/outer@1.0",
             "components": [{"type": "library", "name": "inner", "purl": "pkg:pypi/inner"}]},
        ],
    }  # fmt: skip
    inv = sbom.parse(json.dumps(cdx, indent=1), "bom.json")
    assert {(d.ecosystem, d.name, d.version) for d in inv.dependencies} == {
        ("npm", "lodash", "4.17.20"),
        ("pip", "outer", "1.0"),
    }
    assert {(u.reason, u.name) for u in inv.unresolved} == {
        (Unchecked.NO_PURL, "nopurl"),
        (Unchecked.UNKNOWN_ECOSYSTEM, "curl"),
        (Unchecked.NO_VERSION, "inner"),
    }
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "packages": [{"name": "gin", "versionInfo": "v1.9.1", "externalRefs": [
            {"referenceType": "purl", "referenceLocator": "pkg:golang/github.com/gin-gonic/gin@v1.9.1"}]}],
    }  # fmt: skip
    assert [d.name for d in sbom.parse(json.dumps(spdx), "sbom.spdx.json").dependencies] == ["github.com/gin-gonic/gin"]
    assert sbom.parse("{", "x.json").unresolved[0].reason is Unchecked.LOCKFILE_UNREADABLE


def test_uv_lock_sources() -> None:
    text = (
        '[[package]]\nname = "app"\nsource = { editable = "." }\n\n'
        '[[package]]\nname = "httpx"\nversion = "0.27.0"\nsource = { registry = "https://pypi.org/simple" }\n\n'
        '[[package]]\nname = "tool"\nversion = "1.0"\nsource = { git = "https://github.com/o/tool?rev=abc" }\n'
    )
    assert checks.uv_sources(text) == {"app": "path", "httpx": "registry", "tool": "vcs"}
