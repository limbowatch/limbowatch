"""Fields scanners can't use, and the suggested fix for each (FINDINGS F-069)."""

import pytest
from conftest import load
from limbowatch.classify import assess
from limbowatch.models import Facts
from limbowatch.normalize import repo_advisory
from limbowatch.publish import Item, repos_with_advisories
from limbowatch.publish.quality import NAME, problems, range_problem
from limbowatch.store import Repo, Store
from limbowatch.versions import osv_ranges


@pytest.mark.parametrize(
    ("rng", "patched", "issue", "fix"),
    [
        (None, "1.2.3", "No affected versions given", "`< 1.2.3`"),
        ("0.26.0 .. 0.26.1", None, "`A .. B`", "`>= 0.26.0, < 0.26.1` if 0.26.1 is fixed"),
        ("tbd", None, "Not a range", "`>= 0`"),
        ("> 8.2", None, "Uses `>`", "`>=`"),
        ("<2.11.7,<2.12.1", None, "Several upper bounds", "`< 2.11.7` and `>= 2.12.0, < 2.12.1`"),
        ("<2.1.1, <2.1.4", None, "Several upper bounds", "e.g. `>= 2.0.0, < 2.0.3`"),  # one release line: no guess
        (">= 2.0.0", "1.5.0", "doesn't close the range", "`< 1.5.0`"),
        (">= 3.0.0", "2.0.5, 2.1.3", "lists several versions", "once per release line"),
        (">= 0.65.0", "<0.81.0", "isn't a version", "first fixed version"),
    ],
)
def test_range_problem(rng: str | None, patched: str | None, issue: str, fix: str) -> None:
    assert osv_ranges("npm", rng, patched) is None  # only unconvertible ranges are ever explained
    got_issue, got_fix = range_problem("npm", rng, patched)
    assert issue in got_issue
    assert fix in got_fix


def test_problems_lists_exact_name_fixes() -> None:
    raw = load("repo_advisories_gitpython.json")[0]
    adv = repo_advisory(raw, "gitpython-developers/gitpython")
    f = Facts(ghsa_id=adv.ghsa_id, repo=adv.repo, repo_state="published", reviewed=False)
    probs = problems([Item(adv, f, assess(adv, f), "2026-10-26T00:00:00Z")])
    names = [p for p in probs if p.field == NAME]
    assert names and names[0].certain and names[0].as_entered == "Gitpython"
    assert names[0].fix == "Change it to `gitpython`."


def test_repos_with_advisories_lists_names_only() -> None:
    store = Store()
    with store.session() as s:
        s.add_all(
            [
                Repo(full_name="b/two", first_seen="x", advisory_count=3, poll_status=304),
                Repo(full_name="A/One", first_seen="x", advisory_count=1, poll_status=200),
                Repo(full_name="c/none", first_seen="x", advisory_count=0, poll_status=200),
                Repo(full_name="d/gone", first_seen="x", advisory_count=2, poll_status=404),
            ]
        )
    text = repos_with_advisories(store, "2026-11-05T00:00:00Z")
    assert [ln for ln in text.splitlines() if not ln.startswith("#")] == ["a/one", "b/two"]
    assert "watchlist of 4 repositories; 2 listed" in text


def test_watchlist_lists_checked_repos_with_times() -> None:
    from limbowatch.publish import watchlist

    store = Store()
    with store.session() as s:
        s.add_all(
            [
                Repo(full_name="A/One", first_seen="x", last_polled_at="2026-11-05T13:00:00Z", poll_status=304),
                Repo(full_name="b/new", first_seen="x"),
                Repo(full_name="c/gone", first_seen="x", last_polled_at="2026-11-01T13:00:00Z", poll_status=404),
            ]
        )
    assert watchlist(store, "t")["repos"] == {"a/one": "2026-11-05T13:00:00Z"}
