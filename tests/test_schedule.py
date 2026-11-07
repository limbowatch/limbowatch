from datetime import UTC, datetime, timedelta

from limbowatch.schedule import Tier, due_order, overdue, tier

NOW = datetime(2026, 10, 28, 6, 17, tzinfo=UTC)


def test_tiers() -> None:
    assert tier(True, 3, 200) is Tier.LIMBO
    assert tier(False, 3, 200) is Tier.ACTIVE
    assert tier(False, 0, 200) is Tier.QUIET
    assert tier(True, 3, 404) is Tier.GONE


def test_daily_run_drift_still_counts_as_due() -> None:
    # checked by yesterday's run, which started 40 minutes later than today's
    assert overdue(Tier.LIMBO, NOW - timedelta(hours=23, minutes=20), None, NOW) >= 1
    assert overdue(Tier.QUIET, NOW - timedelta(days=1), None, NOW) < 1


def test_short_budget_slows_every_tier_alike() -> None:
    # two days without a run: the limbo repo is twice overdue, the quiet one isn't due yet
    limbo = overdue(Tier.LIMBO, NOW - timedelta(days=2), None, NOW)
    quiet = overdue(Tier.QUIET, NOW - timedelta(days=2), None, NOW)
    stale_quiet = overdue(Tier.QUIET, NOW - timedelta(days=21), None, NOW)
    assert due_order([("quiet", quiet), ("limbo", limbo), ("stale", stale_quiet)]) == ["stale", "limbo"]


def test_new_repos_rank_above_merely_due_ones_but_not_far_overdue_ones() -> None:
    new = overdue(Tier.QUIET, None, NOW - timedelta(hours=1), NOW)
    due = overdue(Tier.LIMBO, NOW - timedelta(days=1), None, NOW)
    very_late = overdue(Tier.LIMBO, NOW - timedelta(days=4), None, NOW)
    assert due_order([("due", due), ("new", new), ("late", very_late)]) == ["late", "new", "due"]


def test_a_large_seed_list_cannot_starve_due_rechecks() -> None:
    """45,000 new repos outrank every due repo (F-099): a run takes at most max_new of them, then the due ones."""
    from typing import Any, cast

    from limbowatch.store import Repo, Store
    from limbowatch.tracker import Tracker, TrackerConfig

    store = Store()
    old = (datetime.now(UTC) - timedelta(days=8)).isoformat().replace("+00:00", "Z")
    with store.session() as s:
        s.add(Repo(full_name="due/quiet", sources=["seed"], first_seen=old, last_polled_at=old, poll_status=200))
    t = Tracker(store, cast(Any, None), TrackerConfig(max_new=2))
    t.add_repos({f"new/r{i}" for i in range(5)}, "seed:top-packages")
    order = [r.full_name for r in t.poll_order()]
    assert order[:2] == ["new/r0", "new/r1"] and order[2:] == ["due/quiet"]  # 2 new first, the due one still runs
    t.cfg.max_new = None
    assert len(t.poll_order()) == 6


def test_coverage_per_ecosystem_counts_watched_and_checked() -> None:
    from limbowatch.publish import ecosystem_coverage
    from limbowatch.store import Repo

    repos = [Repo(full_name="a/x", sources=[], first_seen="t", last_polled_at="t", poll_status=200, advisory_count=2),
             Repo(full_name="b/y", sources=[], first_seen="t")]  # fmt: skip
    top = {"top": 1000, "generated": "2026-11-07", "registries": {"npmjs.org": ["A/x", "b/y", "c/z"]}}
    cov = ecosystem_coverage(repos, top)
    npm = {"top": 1000, "repos": 3, "watched": 2, "checked": 1, "with_advisories": 1}
    assert cov == {"top": 1000, "generated": "2026-11-07", "ecosystems": {"npm": npm}}
    assert ecosystem_coverage(repos, None) is None
