"""Daily report: a Markdown summary of what changed since the previous report.

The previous report's time and headline counts are kept in the `daily_report` cursor, so a skipped
day is covered by the next report instead of being lost. Factual metadata only (FINDINGS F-059).
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from limbowatch.ecosystems import package_name
from limbowatch.mdsafe import advisory_link, code
from limbowatch.models import Status
from limbowatch.publish import ATTRIBUTION, Item, days_since, fixes_text, items, metrics
from limbowatch.store import Event, Repo, Reviewed, Store

CURSOR = "daily_report"
NEW_WINDOW = timedelta(days=2)  # "newly published" = published within this long before the report
TABLE_ROWS = 25
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
RECENT = timedelta(days=90)  # "Longest waiting" covers this window; older ones would top it every day
TRACKER_URL = "https://limbo.watch/tracker/"  # lists every advisory in limbo, newest first
COMMENT_LIMIT = 65_000  # bytes; GitHub's issue comments hold 65,536 characters
# CVE changes, most telling first: a reserved CVE that's now public, a CVE newly cited, then other CNAs' and GitHub's
_CVE_ORDER = (("RESERVED -> PUBLISHED", 0), ("cites ", 1), ("new CVE from another CNA", 2), ("new CVE from GitHub", 3))
_PLAIN = re.compile(r"[A-Za-z0-9 ,:'()>.-]*")  # event text with nothing Markdown could read as syntax


@dataclass
class Report:
    date: str
    markdown: str
    summary: dict[str, Any]


def _pkgs(it: Item) -> str:
    names = sorted({f"{p.ecosystem}:{n.name}" for p in it.adv.packages if (n := package_name(p.ecosystem, p.name))})
    names = names or [it.adv.repo]
    s = ", ".join(names)
    return s if len(s) <= 60 else s[:57] + "…"


def _fix(it: Item) -> str:
    return fixes_text(it)[:40] or "–"


def _sev(s: str | None) -> str:
    """GitHub's severity as is; anything else as code (the table is posted to a public issue, F-164)."""
    return s if s in SEVERITY_ORDER else code(s, table=True) if s else "–"


def _cve(it: Item) -> str:
    f = it.facts
    cves = [c for c in [f.cited_cve, *f.uncited_cves] if c]
    return f"{it.assessment.cve_label.value}{' (' + code(', '.join(cves), table=True) + ')' if cves else ''}"


def _table(rows: list[Item], now: datetime, more: str = "") -> list[str]:
    out = ["| Advisory | Package | Severity | CVE | Days | Fixed in |", "|---|---|---|---|---:|---|"]
    for it in rows[:TABLE_ROWS]:
        age = days_since(it.adv.published_at, now)
        out.append(
            f"| {advisory_link(it.adv.ghsa_id, it.adv.html_url)} | {code(_pkgs(it), table=True)} | "
            f"{_sev(it.adv.severity)} | {_cve(it)} | {'' if age is None else int(age)} | "
            f"{code(_fix(it), table=True)} |"
        )
    if len(rows) > TABLE_ROWS:
        out.append(f"\n…and {len(rows) - TABLE_ROWS:,} more{more}.")
    return out


def _event(e: str) -> str:
    """A CVE change as text when it's plain (they're the tracker's own), else as code: the CVE IDs in it come from
    advisories and CVE records (F-164)."""
    return e if _PLAIN.fullmatch(e) else code(e, table=True)


def _cve_rank(change: tuple[Item, str]) -> tuple[int, int, str]:
    it, e = change
    kind = next((r for k, r in _CVE_ORDER if k in e), len(_CVE_ORDER))
    return kind, SEVERITY_ORDER.get(it.adv.severity or "", 9), it.adv.ghsa_id


def _ids(rows: list[Item]) -> list[str]:
    return sorted(i.adv.ghsa_id for i in rows)


def _delta(now_v: int, prev: int | None, parts: str = "") -> str:
    if prev is None:
        return ""
    d = now_v - prev
    return f" ({'+' if d >= 0 else '−'}{abs(d):,} since the last report{': ' + parts if parts else ''})"


def _parts(new: int, found: int, left: int, net: int | None, moved: tuple[int, int, str] | None = None) -> str:
    """Why a count moved: newly found advisories aren't new limbo (F-067). `moved`: advisories that came from and went
    to the other count (their packages changed ecosystem; F-167), and what that other count is called. Without it
    (the first report after the IDs were kept), what's left is "other changes"."""
    if net is None:
        return ""
    out = [f"{new:,} newly published", f"{found:,} older ones found for the first time", f"{left:,} left limbo"]
    other = net - (new + found - left)
    if moved is not None:
        came, went, name = moved
        if came:
            out.append(f"{came:,} moved in from {name}")
        if went:
            out.append(f"{went:,} moved to {name}")
        other -= came - went
    if other:
        out.append(f"{'+' if other > 0 else '−'}{abs(other):,} other changes")
    return ", ".join(out)


def build(store: Store, now: datetime | None = None) -> Report:
    now = now or datetime.now(UTC)
    prev = json.loads(store.cursor(CURSOR) or "null")
    since = datetime.fromisoformat(prev["at"].replace("Z", "+00:00")) if prev else None
    m = metrics(store, now)
    all_items = items(store)
    by_id = {i.adv.ghsa_id: i for i in all_items}
    pending = [i for i in all_items if i.assessment.status is Status.LIMBO and not i.assessment.likely_permanent]
    permanent = [i for i in all_items if i.assessment.status is Status.LIMBO and i.assessment.likely_permanent]

    with store.session() as s:
        # Event IDs, not timestamps: timestamps have one-second resolution.
        events = list(s.execute(select(Event).where(Event.id > (prev or {}).get("event_id", 0))).scalars())
        new_repos = {r.full_name for r in s.execute(select(Repo)).scalars() if since and _after(r.first_seen, since)}
        # GitHub's reviews in the period, of any advisory, not only those in limbo here (F-167); with the ones seen
        # leaving limbo by review, whose review GitHub may list after the last report although it's dated before it
        reviewed_rows = [(g, at) for g, at in s.execute(select(Reviewed.ghsa_id, Reviewed.reviewed_at))]
    last_event_id = max((e.id for e in events), default=(prev or {}).get("event_id", 0))
    left_reviewed = {e.ghsa_id for e in events if e.event == "in limbo -> reviewed"}
    reviewed_all = (
        len({g for g, at in reviewed_rows if _after(at, since) or g in left_reviewed}) if since is not None else None
    )

    left: Counter[str] = Counter()
    left_pending = 0
    cve_changes: list[tuple[Item, str]] = []
    first_seen: set[str] = set()
    for e in events:
        it = by_id.get(e.ghsa_id)
        if it is None:
            continue
        if e.event == "first seen":
            first_seen.add(e.ghsa_id)
        elif e.event.startswith("in limbo -> "):
            left[e.event.removeprefix("in limbo -> ")] += 1
            left_pending += not it.assessment.likely_permanent
        elif "CVE" in e.event or e.event.startswith("cites "):
            cve_changes.append((it, e.event))

    def sev_key(i: Item) -> tuple[int, float]:
        return (SEVERITY_ORDER.get(i.adv.severity or "", 9), -(days_since(i.adv.published_at, now) or 0))

    fresh_cut = now - NEW_WINDOW if since is None else min(since, now - NEW_WINDOW)

    def first_seen_split(bucket: list[Item]) -> tuple[list[Item], list[Item]]:
        seen = [i for i in bucket if i.adv.ghsa_id in first_seen]
        fresh = [i for i in seen if i.adv.published_at and i.adv.published_at >= fresh_cut]
        return sorted(fresh, key=sev_key), [i for i in seen if i not in fresh]

    new_pub, discovered = first_seen_split(pending)
    new_perm, discovered_perm = first_seen_split(permanent)
    # moves between in limbo and likely permanent, from the IDs the last report kept (none before F-167)
    moves: tuple[tuple[int, int, str], tuple[int, int, str]] | None = None
    if prev and "pending_ids" in prev and "permanent_ids" in prev:
        was_p, was_m = set(prev["pending_ids"]), set(prev["permanent_ids"])
        now_p, now_m = set(_ids(pending)), set(_ids(permanent))
        to_perm, to_pend = len(was_p & now_m), len(was_m & now_p)
        moves = ((to_pend, to_perm, "likely permanent"), (to_perm, to_pend, "the in-limbo count"))
    in_new_repos = sum(1 for i in discovered if i.adv.repo in new_repos)
    ages = {i.adv.ghsa_id: days_since(i.adv.published_at, now) or 0 for i in pending}
    over_year = sum(1 for a in ages.values() if a > 365)
    recent = [i for i in pending if ages[i.adv.ghsa_id] <= RECENT.days]
    oldest = sorted(recent, key=lambda i: ages[i.adv.ghsa_id], reverse=True)[:5]

    li, lp, cov = m["in_limbo"], m["likely_permanent"], m["coverage"]
    date = now.strftime("%Y-%m-%d")
    lines = [
        f"# Limbo Tracker daily report — {date}",
        "",
        f"Generated {m['generated_at'].replace('T', ' ').replace('Z', ' UTC')}"
        + (f"; changes since {prev['at'].replace('T', ' ').replace('Z', ' UTC')}." if prev else "; first report."),
        "",
        "## Now",
        "",
        f"- **{li['count']:,} advisories in limbo**"
        + _delta(
            li["count"],
            prev_limbo := prev and prev.get("limbo"),
            _parts(
                len(new_pub),
                len(discovered),
                left_pending,
                None if prev_limbo is None else li["count"] - prev_limbo,
                moves and moves[0],
            ),
        )
        + ": published by "
        "maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.",
        f"  - {li['by_cve'].get('no CVE anywhere', 0):,} with no CVE anywhere · "
        f"{li['rbp']['count']:,} citing a CVE that's still only reserved · "
        f"{li['by_cve'].get('CVE published by another CNA, not cited', 0):,} with a CVE from another CNA "
        "they don't cite",
        f"  - severity: {li['by_severity']['critical']:,} critical, {li['by_severity']['high']:,} high, "
        f"{li['by_severity']['medium']:,} medium, {li['by_severity']['low']:,} low · median wait so far "
        f"{li['age_days_median']} days",
        f"- **{lp['count']:,} more are likely permanent**"
        + _delta(
            lp["count"],
            prev_perm := prev and prev.get("permanent"),
            _parts(
                len(new_perm),
                len(discovered_perm),
                left.total() - left_pending,
                None if prev_perm is None else lp["count"] - prev_perm,
                moves and moves[1],
            ),
        )
        + ": "
        "in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.",
        "",
        "## Since the last report",
        "",
        f"- **{len(new_pub):,} newly published** advisories entered limbo.",
        f"- {len(discovered):,} older advisories were found for the first time"
        + (f" ({in_new_repos:,} in newly watched repos)." if discovered else "."),
        f"- **Left limbo** (likely permanent included): {left.get('reviewed', 0):,} reviewed by GitHub, "
        f"{left.get('duplicate of a reviewed advisory', 0):,} found to duplicate a reviewed advisory, "
        f"{left.get('withdrawn', 0) + left.get('no longer published', 0):,} withdrawn or unpublished."
        + (
            ""
            if reviewed_all is None
            else " **GitHub reviewed no advisories at all in this period.**"
            if reviewed_all == 0
            else f" GitHub reviewed {reviewed_all:,} {'advisory' if reviewed_all == 1 else 'advisories'} "
            "in all in this period, from any repository."
        ),
        f"- **CVE changes:** {len(cve_changes):,}"
        + (
            f" ({sum('RESERVED -> PUBLISHED' in e for _, e in cve_changes):,} reserved CVEs published, "
            f"{sum(e.startswith('new CVE from another CNA') for _, e in cve_changes):,} new CVEs from other CNAs)"
            if cve_changes
            else ""
        )
        + ".",
        "",
    ]
    if new_pub:
        more = f": [the tracker]({TRACKER_URL}) lists them all, newest first"
        lines += ["## Newly published, in limbo", "", *_table(new_pub, now, more), ""]
    if cve_changes:
        cve_changes.sort(key=_cve_rank)
        lines += ["## CVE changes", "", "| Advisory | Change |", "|---|---|"]
        lines += [
            f"| {advisory_link(it.adv.ghsa_id, it.adv.html_url)} | {_event(e)} |" for it, e in cve_changes[:TABLE_ROWS]
        ]
        if len(cve_changes) > TABLE_ROWS:
            lines.append(f"\n…and {len(cve_changes) - TABLE_ROWS:,} more.")
        lines.append("")
    if oldest:
        lines += [
            f"## Longest waiting, published in the last {RECENT.days} days",
            "",
            *_table(oldest, now),
            "",
            f"{over_year:,} advisories in limbo have waited more than a year.",
            "",
        ]
    run = m.get("last_run") or {}
    lines += [
        "## Coverage",
        "",
        f"Watchlist {cov['watchlist_repos']:,} repositories; {cov['on_schedule']:,} up to date on their schedule "
        "(daily for repos with an advisory in limbo, every 3 days for other repos with advisories, "
        "every 30 days and after each release for the rest); "
        f"{cov['polled_last_24h']:,} checked in the last 24 hours"
        + (f"; the last run stopped early ({run['stopped_early']})" if run.get("stopped_early") else "")
        + f"; {cov['reviewed_advisories_known']:,} reviewed advisories known. Every number is a floor: the tracker "
        "only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.",
        "",
        f"_{ATTRIBUTION}_",
        "",
    ]
    summary = {
        "at": m["generated_at"],
        "event_id": last_event_id,
        "limbo": li["count"],
        "permanent": lp["count"],
        "new": len(new_pub),
        "reviewed": left.get("reviewed", 0),
        "cve_changes": len(cve_changes),
        "reviewed_all": reviewed_all,
        # for the next report's moves between the two counts (F-167)
        "pending_ids": _ids(pending),
        "permanent_ids": _ids(permanent),
    }
    return Report(date, "\n".join(lines), summary)


def _after(stamp: str | None, since: datetime | None) -> bool:
    return bool(stamp) and since is not None and datetime.fromisoformat(str(stamp).replace("Z", "+00:00")) > since


def comment(markdown: str, full_url: str, limit: int = COMMENT_LIMIT) -> str:
    """The report as an issue comment: whole when it fits in `limit` bytes, else cut at a line break with a note
    linking the full report."""
    if len(markdown.encode()) <= limit:
        return markdown
    note = f"\n\n_The report is longer than an issue comment allows; [read all of it]({full_url})._\n"
    room = limit - len(note.encode())
    cut = markdown.encode()[:room].decode(errors="ignore")
    return cut[: cut.rfind("\n")] + note if "\n" in cut else cut + note


def commit(store: Store, report: Report) -> None:
    """Remember this report as the baseline for the next one."""
    store.set_cursor(CURSOR, json.dumps(report.summary, separators=(",", ":")))
