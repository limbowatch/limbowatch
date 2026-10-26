"""Build the public outputs from tracker state: the limbo feed, metrics and the static site."""

from __future__ import annotations

import json
import statistics
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from limbowatch import __version__
from limbowatch.classify import assess
from limbowatch.ecosystems import info, reviewable
from limbowatch.models import Assessment, Facts, RepoAdvisory, Status
from limbowatch.store import Event, Repo, Reviewed, Run, Store

ATTRIBUTION = (
    "Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database "
    "(https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API "
    "(this product uses the NVD API but is not endorsed or certified by the NVD). "
    "Compiled by Limbowatch (https://limbo.watch), CC BY 4.0."
)
AGE_BUCKETS = [
    ("< 3 days", 0, 3),
    ("3–7 days", 3, 7),
    ("1–2 weeks", 7, 14),
    ("2–4 weeks", 14, 30),
    ("1–2 months", 30, 60),
    ("2–3 months", 60, 90),
    ("> 3 months", 90, 10**6),
]


@dataclass
class Item:
    adv: RepoAdvisory
    facts: Facts
    assessment: Assessment
    first_seen: str


def items(store: Store) -> list[Item]:
    """Every advisory with a recorded fact snapshot, with its current assessment."""
    from limbowatch.store import Advisory

    latest = store.latest_facts()
    out = []
    with store.session() as s:
        for a in s.execute(select(Advisory)).scalars():
            f = latest.get(a.ghsa_id)
            if f is None:
                continue
            adv = RepoAdvisory.model_validate(a.data)
            facts = Facts.model_validate(f)
            out.append(Item(adv, facts, assess(adv, facts), a.first_seen))
    return out


def eco_label(ghsa_ecosystem: str) -> str:
    return info(ghsa_ecosystem).osv or ghsa_ecosystem


def days_since(d: datetime | None, now: datetime) -> float | None:
    return None if d is None else (now - d).total_seconds() / 86400


def metrics(store: Store, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    all_items = items(store)
    in_limbo = [i for i in all_items if i.assessment.status is Status.LIMBO]
    # Headline = pending: in ecosystems GitHub reviews. The rest will likely never be reviewed.
    limbo = [i for i in in_limbo if not i.assessment.likely_permanent]
    permanent = [i for i in in_limbo if i.assessment.likely_permanent]
    ages = [x for i in limbo if (x := days_since(i.adv.published_at, now)) is not None]
    with store.session() as s:
        repos = list(s.execute(select(Repo)).scalars())
        reviewed = list(s.execute(select(Reviewed)).scalars())
        runs = list(s.execute(select(Run).order_by(Run.id.desc()).limit(1)).scalars())
        events = list(s.execute(select(Event).order_by(Event.id.desc()).limit(200)).scalars())
    polled_24h = sum(
        1
        for r in repos
        if r.last_polled_at
        and (now - datetime.fromisoformat(r.last_polled_at.replace("Z", "+00:00"))).total_seconds() < 86400
    )
    # completed review lag: advisories we saw in limbo that were later reviewed
    lag = [
        (i.facts.reviewed_at - i.adv.published_at).total_seconds() / 86400
        for i in all_items
        if i.facts.reviewed_at and i.adv.published_at
    ]
    rbp = [i for i in limbo if i.assessment.cve_label.name == "RESERVED"]
    sev = Counter(i.adv.severity or "unknown" for i in limbo)
    return {
        "generated_at": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "limbowatch_version": __version__,
        "coverage": {
            "watchlist_repos": len(repos),
            "polled_last_24h": polled_24h,
            "repos_with_advisories": sum(1 for r in repos if r.advisory_count),
            "reviewed_advisories_known": len(reviewed),
            "note": "Every number is a floor: only repositories on the watchlist are seen.",
        },
        "in_limbo": {
            "count": len(limbo),
            "by_cve": dict(Counter(i.assessment.cve_label.value for i in limbo).most_common()),
            "by_severity": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low", "unknown")},
            "by_ecosystem": dict(
                Counter(eco_label(e) for i in limbo for e in i.assessment.ecosystems if reviewable(e)).most_common()
            ),
            "age_days_median": round(statistics.median(ages), 1) if ages else None,
            "age_buckets": {n: sum(1 for x in ages if lo <= max(x, 0) < hi) for n, lo, hi in AGE_BUCKETS},
            "rbp": {
                "count": len(rbp),
                "over_72h": sum(1 for i in rbp if (days_since(i.adv.published_at, now) or 0) > 3),
            },
        },
        "likely_permanent": {
            "count": len(permanent),
            "note": "Published advisories in ecosystems GitHub doesn't review (free text, 'other', C/C++, "
            "container images, ...): scanners that read GitHub's database will probably never see them.",
            "by_cve": dict(Counter(i.assessment.cve_label.value for i in permanent).most_common()),
            "age_days_median": round(statistics.median(pa), 1)
            if (pa := [x for i in permanent if (x := days_since(i.adv.published_at, now)) is not None])
            else None,
        },
        "left_limbo": {
            "reviewed": sum(1 for i in all_items if i.assessment.status is Status.REVIEWED),
            "duplicates": sum(1 for i in all_items if i.assessment.status is Status.DUPLICATE),
            "withdrawn_or_gone": sum(
                1 for i in all_items if i.assessment.status in (Status.WITHDRAWN, Status.NOT_PUBLISHED)
            ),
            "review_lag_days_median": round(statistics.median(lag), 1) if lag else None,
        },
        "last_run": runs[0].stats if runs else None,
        "recent_events": [
            {"ghsa_id": e.ghsa_id, "at": e.at, "event": e.event} for e in events if e.event != "first seen"
        ][:50],
        "attribution": ATTRIBUTION,
    }


def dumps(obj: Any) -> str:
    return json.dumps(obj, indent=1, sort_keys=True, default=str) + "\n"
