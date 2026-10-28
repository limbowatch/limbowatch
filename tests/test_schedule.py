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
