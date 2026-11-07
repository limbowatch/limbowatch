"""When to re-check each watched repository.

Most watched repos never publish an advisory, so checking all of them every day wastes the
GitHub rate limit (5,000 requests an hour, shared by everything using the same account). Each
repo gets a target interval from what it has published:

- an advisory currently in limbo: daily, since that's where changes matter;
- other advisories: every 3 days;
- none yet: weekly;
- the repo answered 404: weekly, until it reappears.

A run checks only repos that are due, most overdue first, where "overdue" is time since the
last check divided by the target interval. When the budget can't cover everything that's due,
every tier slows down by the same factor instead of the quiet repos never being checked.
Never-checked repos rank above anything merely due, so a new seed list is covered within days. A
large list is capped per run (`TrackerConfig.max_new`, `limbowatch track --max-new`), so its first
polls can't use the whole budget and starve the daily tier.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum


class Tier(StrEnum):
    LIMBO = "daily: has an advisory in limbo"
    ACTIVE = "every 3 days: has advisories, none in limbo"
    QUIET = "weekly: no advisories yet"
    GONE = "weekly: repository not found"


INTERVAL = {
    Tier.LIMBO: timedelta(days=1),
    Tier.ACTIVE: timedelta(days=3),
    Tier.QUIET: timedelta(days=7),
    Tier.GONE: timedelta(days=7),
}
SLACK = timedelta(hours=2)  # daily runs drift; a repo checked 23 hours ago is due again
NEW_BASE = 2.0  # never-checked repos start here and gain one point per week waiting


def tier(has_limbo: bool, advisory_count: int, poll_status: int | None) -> Tier:
    if poll_status == 404:
        return Tier.GONE
    if has_limbo:
        return Tier.LIMBO
    return Tier.ACTIVE if advisory_count else Tier.QUIET


def overdue(t: Tier, last_polled: datetime | None, first_seen: datetime | None, now: datetime) -> float:
    """How overdue a repo is: below 1 it's not due yet; higher is more urgent."""
    if last_polled is None:
        waited = (now - first_seen).total_seconds() if first_seen else 0.0
        return NEW_BASE + waited / INTERVAL[Tier.QUIET].total_seconds()
    return (now - last_polled + SLACK) / INTERVAL[t]


def due_order(repos: list[tuple[str, float]]) -> list[str]:
    """Names of the due repos (overdue >= 1), most overdue first; ties by name, for stable runs."""
    return [name for name, score in sorted(repos, key=lambda r: (-r[1], r[0])) if score >= 1]
