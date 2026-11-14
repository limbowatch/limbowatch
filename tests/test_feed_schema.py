"""Feed records validate against the OSV JSON schema (vendored, tests/fixtures/osv_schema.json)."""

import io
import json
from datetime import UTC, datetime

import jsonschema
from conftest import FIXTURES, load
from limbowatch.classify import assess
from limbowatch.models import Facts, Status
from limbowatch.normalize import repo_advisory
from limbowatch.publish import Item
from limbowatch.publish.feed import record


def test_feed_record_is_valid_osv() -> None:
    schema = json.loads((FIXTURES / "osv_schema.json").read_text())
    for name, repo in (
        ("repo_advisories_regexp2.json", "dlclark/regexp2"),
        ("repo_advisories_gitpython.json", "gitpython-developers/gitpython"),
    ):
        for raw in load(name):
            adv = repo_advisory(raw, repo)
            f = Facts(ghsa_id=adv.ghsa_id, repo=repo, repo_state="published", reviewed=False, cited_cve=adv.cve_id)
            rec = record(
                Item(adv, f, assess(adv, f), "2026-10-26T00:00:00Z"),
                datetime(2026, 10, 26, tzinfo=UTC).isoformat().replace("+00:00", "Z"),
            )
            jsonschema.validate(rec, schema)


def test_feed_by_ecosystem_matches_osv_download_layout() -> None:
    """OSV-Scanner fails a whole offline scan if any ecosystem's zip is missing, so every one is written (F-074)."""
    import io
    import zipfile

    from limbowatch.publish.feed import OFFLINE_ECOSYSTEMS, bundle, by_ecosystem, crc32c, goog_hash

    def rec(i: str, *ecos: str) -> dict[str, object]:
        return {"id": i, "affected": [{"package": {"ecosystem": e, "name": "x"}} for e in ecos]}

    zips = by_ecosystem([rec("GHSA-a", "PyPI"), rec("GHSA-b", "npm", "PyPI"), rec("GHSA-c", "Bitbucket")])
    assert set(OFFLINE_ECOSYSTEMS) | {"Bitbucket"} == set(zips)
    assert sorted(zipfile.ZipFile(io.BytesIO(zips["PyPI"])).namelist()) == ["GHSA-a.json", "GHSA-b.json"]
    assert zipfile.ZipFile(io.BytesIO(zips["npm"])).namelist() == ["GHSA-b.json"]
    assert zipfile.ZipFile(io.BytesIO(zips["Debian"])).namelist() == []
    assert zipfile.ZipFile(io.BytesIO(zips["PyPI"])).infolist()[0].compress_type == zipfile.ZIP_DEFLATED
    assert by_ecosystem([rec("GHSA-a", "PyPI")])["PyPI"] == by_ecosystem([rec("GHSA-a", "PyPI")])["PyPI"]

    names = zipfile.ZipFile(io.BytesIO(bundle(zips))).namelist()
    assert "osv-scalibr/GitHub Actions/all.zip" in names and len(names) == len(zips)

    assert crc32c(b"123456789") == 0xE3069283  # the standard CRC-32C check value
    assert goog_hash(b"") == "crc32c=AAAAAA=="


def test_go_records_name_the_module_and_import_the_package() -> None:
    """OSV's Go form once the tracker has resolved the module (F-113); valid OSV, and the watcher reads it back."""
    from limbowatch.models import AdvisoryPackage
    from limbowatch.publish import with_go_modules
    from limbowatch.watch.candidates import from_feed_record

    schema = json.loads((FIXTURES / "osv_schema.json").read_text())
    adv = repo_advisory(load("repo_advisories_regexp2.json")[0], "dlclark/regexp2")
    pkgs = (
        AdvisoryPackage(ecosystem="go", name="go.opentelemetry.io/otel/baggage", vulnerable_version_range="< 1.47.0"),
        AdvisoryPackage(
            ecosystem="go", name="github.com/aws/aws-sdk-go-v2/service/kinesis", vulnerable_version_range="< 1.42.2"
        ),
        AdvisoryPackage(ecosystem="go", name="example.com/unresolved/pkg", vulnerable_version_range="< 2.0.0"),
    )
    modules = {"go.opentelemetry.io/otel/baggage": "go.opentelemetry.io/otel",
               "github.com/aws/aws-sdk-go-v2/service/kinesis": "github.com/aws/aws-sdk-go-v2/service/kinesis",
               "example.com/unresolved/pkg": None}  # fmt: skip
    adv = with_go_modules(adv.model_copy(update={"packages": pkgs}), modules)
    f = Facts(ghsa_id=adv.ghsa_id, repo="dlclark/regexp2", repo_state="published", reviewed=False)
    rec = record(Item(adv, f, assess(adv, f), "2026-11-08T00:00:00Z"), "2026-11-08T00:00:00Z")
    jsonschema.validate(rec, schema)
    baggage, kinesis, unresolved = rec["affected"]
    assert baggage["package"]["name"] == "go.opentelemetry.io/otel"
    assert baggage["ecosystem_specific"] == {"imports": [{"path": "go.opentelemetry.io/otel/baggage"}]}
    assert kinesis["package"]["name"] == "github.com/aws/aws-sdk-go-v2/service/kinesis"
    assert (
        "ecosystem_specific" not in kinesis and kinesis["database_specific"]["go_module"] == kinesis["package"]["name"]
    )
    assert (
        unresolved["package"]["name"] == "example.com/unresolved/pkg"
        and "go_module" not in unresolved["database_specific"]
    )
    back = from_feed_record(rec).adv.packages
    assert [(p.name, p.module) for p in back] == [
        ("go.opentelemetry.io/otel/baggage", "go.opentelemetry.io/otel"),
        ("github.com/aws/aws-sdk-go-v2/service/kinesis", "github.com/aws/aws-sdk-go-v2/service/kinesis"),
        ("example.com/unresolved/pkg", None),
    ]


def _items() -> list[Item]:
    out = []
    for raw in load("repo_advisories_gitpython.json"):
        adv = repo_advisory(raw, "gitpython-developers/gitpython")
        f = Facts(ghsa_id=adv.ghsa_id, repo=adv.repo, repo_state="published", reviewed=False, cited_cve=adv.cve_id)
        out.append(Item(adv, f, assess(adv, f), "2026-10-26T00:00:00Z"))
    return out


def test_unchanged_records_keep_the_previous_feeds_modified() -> None:
    """`modified` says when a record last changed, not when the site was built, so unchanged records' files are byte
    for byte the same from one build to the next (F-174)."""
    import zipfile

    from limbowatch.publish.feed import build, previous_modified

    items = [i for i in _items() if i.assessment.status is Status.LIMBO]
    assert len(items) >= 2
    day1, day2 = "2026-11-13T15:00:00Z", "2026-11-14T15:00:00Z"
    recs1, zip1 = build(items, day1)
    assert {r["modified"] for r in recs1} == {day1}

    recs2, zip2 = build(items, day2, previous_modified(zip1))
    assert {r["modified"] for r in recs2} == {day1}
    assert zip2 == zip1

    # one record changes: only it gets the new time
    changed = items[0]
    facts = changed.facts.model_copy(update={"in_osv": False})
    items2 = [Item(changed.adv, facts, changed.assessment, changed.first_seen), *items[1:]]
    recs3, _ = build(items2, day2, previous_modified(zip1))
    assert [r["modified"] for r in recs3 if r["id"] == changed.adv.ghsa_id] == [day2]
    assert {r["modified"] for r in recs3 if r["id"] != changed.adv.ghsa_id} == {day1}

    # no previous feed, or a record new since it: now
    assert {r["modified"] for r in build(items, day2)[0]} == {day2}
    assert {r["modified"] for r in build(items, day2, {})[0]} == {day2}

    # a previous timestamp later than this build isn't taken
    prev = {k: (key, "2027-01-01T00:00:00Z") for k, (key, _) in previous_modified(zip1).items()}
    assert {r["modified"] for r in build(items, day2, prev)[0]} == {day2}
    assert zipfile.ZipFile(io.BytesIO(zip2)).namelist() == [f"{r['id']}.json" for r in recs2]


def test_previous_feed_is_read_as_untrusted() -> None:
    """The previous feed comes over the network: only well-formed records lend a timestamp."""
    import zipfile

    import pytest
    from limbowatch.publish.feed import _MAX_RECORD, content_key, previous_modified

    good = {"id": "GHSA-a", "modified": "2026-11-13T15:00:00Z", "affected": []}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("GHSA-a.json", json.dumps(good))
        z.writestr("GHSA-b.json", json.dumps({"id": "GHSA-b", "modified": "yesterday"}))
        z.writestr("GHSA-c.json", json.dumps({"id": "GHSA-c"}))
        z.writestr("GHSA-d.json", "not json")
        z.writestr("GHSA-e.json", json.dumps(["a list"]))
        z.writestr("GHSA-f.json", json.dumps({"id": 7, "modified": "2026-11-13T15:00:00Z"}))
        z.writestr("GHSA-g.json", " " * (_MAX_RECORD + 1))
        z.writestr("README.txt", "x")
        z.writestr("dir/", "")
    assert previous_modified(buf.getvalue()) == {"GHSA-a": (content_key(good), "2026-11-13T15:00:00Z")}
    with pytest.raises(zipfile.BadZipFile):
        previous_modified(b"<html>not a zip</html>")
