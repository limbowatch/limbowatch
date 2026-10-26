"""Feed records validate against the OSV JSON schema (vendored, tests/fixtures/osv_schema.json)."""

import json
from datetime import UTC, datetime

import jsonschema
from conftest import FIXTURES, load
from limbowatch.classify import assess
from limbowatch.models import Facts
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
