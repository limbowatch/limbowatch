"""Build the public outputs from tracker state: the limbo feed, metrics and the static site."""

from __future__ import annotations

import json
import statistics
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from limbowatch import __version__, schedule
from limbowatch.classify import assess
from limbowatch.ecosystems import info, reviewable
from limbowatch.models import Assessment, Facts, RepoAdvisory, Status
from limbowatch.store import Event, Repo, Reviewed, Run, Store
from limbowatch.versions import fixed_versions, no_fix

ATTRIBUTION = (
    "Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database "
    "(https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API "
    "(this product uses the NVD API but is not endorsed or certified by the NVD). "
    "Compiled by Limbowatch (https://limbo.watch), CC BY 4.0."
)
# The watchlist includes repos chosen from ecosyste.ms package rankings (CC BY-SA 4.0), so the two files that list it
# carry that license and attribution (PHASE0_PLAN §13.12); advisory data stays CC BY 4.0.
WATCHLIST_LICENSE = "CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)"
WATCHLIST_ATTRIBUTION = (
    "includes source repositories of the most-used packages per ecosystem, ranked by ecosyste.ms "
    "(https://ecosyste.ms, CC BY-SA 4.0)."
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
FLOW_DAYS = 7


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


def fixes_text(i: Item) -> str:
    """Fixed versions for display: plain versions where the field reads as such, else the text as entered."""
    out: list[str] = []
    for p in i.adv.packages:
        if p.patched_versions and not no_fix(p.patched_versions):
            out += fixed_versions(p.patched_versions) or [p.patched_versions.strip()]
    return ", ".join(dict.fromkeys(out))


def all_events(store: Store) -> list[dict[str, Any]]:
    with store.session() as s:
        return [{"ghsa_id": e.ghsa_id, "at": e.at, "event": e.event} for e in s.execute(select(Event)).scalars()]


def eco_label(ghsa_ecosystem: str) -> str:
    return info(ghsa_ecosystem).osv or ghsa_ecosystem


def days_since(d: datetime | None, now: datetime) -> float | None:
    return None if d is None else (now - d).total_seconds() / 86400


REGISTRY_LABEL = {
    "npmjs.org": "npm",
    "pypi.org": "PyPI",
    "proxy.golang.org": "Go",
    "repo1.maven.org": "Maven",
    "crates.io": "crates.io",
    "nuget.org": "NuGet",
    "rubygems.org": "RubyGems",
    "packagist.org": "Packagist",
}


def ecosystem_coverage(repos: list[Repo], top_packages: dict[str, Any] | None) -> dict[str, Any] | None:
    """For each ecosystem, how many source repos of its top packages are watched and already checked (F-099)."""
    if not top_packages:
        return None
    by_name = {r.full_name.lower(): r for r in repos}
    out: dict[str, Any] = {}
    for reg, names in (top_packages.get("registries") or {}).items():
        rows = [by_name.get(n.lower()) for n in names]
        out[REGISTRY_LABEL.get(reg, reg)] = {
            "repos": len(names),
            "watched": sum(1 for r in rows if r is not None),
            "checked": sum(1 for r in rows if r is not None and r.last_polled_at and r.poll_status in (200, 304)),
            "with_advisories": sum(1 for r in rows if r is not None and r.advisory_count),
        }
    return {"top": top_packages.get("top"), "generated": top_packages.get("generated"), "ecosystems": out}


def metrics(store: Store, now: datetime | None = None, top_packages: dict[str, Any] | None = None) -> dict[str, Any]:
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
        exits = list(s.execute(select(Event).where(Event.event.like("in limbo -> %"))).scalars())
    limbo_repos = {i.adv.repo for i in in_limbo}
    tiers: Counter[str] = Counter()
    on_schedule = 0
    for r in repos:
        t = schedule.tier(r.full_name in limbo_repos, r.advisory_count, r.poll_status)
        tiers[t.value] += 1
        last = datetime.fromisoformat(r.last_polled_at.replace("Z", "+00:00")) if r.last_polled_at else None
        on_schedule += last is not None and schedule.overdue(t, last, None, now) < 1
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
    # The last 7 days in reviewable ecosystems: newly published advisories against advisories that left limbo.
    # The window ends at the last tracker run, not at publish time: nothing newer has been looked at yet.
    end = min(now, _at(runs[0].finished_at)) if runs and runs[0].finished_at else now
    week = end - timedelta(days=FLOW_DAYS)
    reviewable_ids = {i.adv.ghsa_id for i in all_items if not i.assessment.likely_permanent}
    left_week = [e for e in exits if e.ghsa_id in reviewable_ids and week <= _at(e.at) <= end]
    sev = Counter(i.adv.severity or "unknown" for i in limbo)
    return {
        "generated_at": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "limbowatch_version": __version__,
        "coverage": {
            "watchlist_repos": len(repos),
            "polled_last_24h": polled_24h,
            "on_schedule": on_schedule,
            "by_schedule": {t.value: tiers.get(t.value, 0) for t in schedule.Tier},
            "repos_with_advisories": sum(1 for r in repos if r.advisory_count),
            # why repos are on the watchlist; a repo can have several reasons (FINDINGS F-098)
            "by_source": dict(Counter(src for r in repos for src in set(r.sources or [])).most_common()),
            # the top packages per ecosystem (tracker/seeds/top-packages.json): watched and checked
            "top_packages": ecosystem_coverage(repos, top_packages),
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
        "flow_7d": {
            "days": FLOW_DAYS,
            "published": sum(
                1
                for i in all_items
                if not i.assessment.likely_permanent and i.adv.published_at and week <= i.adv.published_at <= end
            ),
            "ends_at": end.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "published_all_ecosystems": sum(
                1 for i in all_items if i.adv.published_at and week <= i.adv.published_at <= end
            ),
            "left": len(left_week),
            "reviewed": sum(1 for e in left_week if e.event == "in limbo -> reviewed"),
            "note": "Advisories newly published in watched repos, in ecosystems GitHub reviews, against advisories "
            "that left limbo in the same days. Both are floors: only watched repos are seen, some a few days late.",
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


def _at(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def dumps(obj: Any) -> str:
    return json.dumps(obj, indent=1, sort_keys=True, default=str) + "\n"


def repos_with_advisories(store: Store, generated_at: str) -> str:
    """Watched repos with at least one published repository advisory, one `owner/repo` per line.

    Repo names only: no advisory or CVE IDs. Other trackers that poll repos one by one can use it to
    find repos they don't watch yet (FINDINGS F-075).
    """
    with store.session() as s:
        repos = list(s.execute(select(Repo)).scalars())
    names = sorted({r.full_name.lower() for r in repos if r.advisory_count and r.poll_status in (200, 304)})
    head = (
        "# Repositories with at least one published GitHub repository security advisory, one owner/repo per line.\n"
        f"# From the limbo.watch tracker's watchlist of {len(repos):,} repositories; {len(names):,} listed.\n"
        f"# Generated {generated_at}, refreshed daily. Repos the tracker doesn't watch are missing.\n"
        "# Names as polled, lower case; a renamed repo may appear under its old name.\n"
        "# Facts only, no advisory or CVE IDs. Limbowatch (https://limbo.watch). The list includes repos chosen from\n"
        f"# ecosyste.ms package rankings, so it is licensed {WATCHLIST_LICENSE}.\n"
    )
    return head + "".join(f"{n}\n" for n in names)


def watchlist(store: Store, generated_at: str) -> dict[str, Any]:
    """Every watched repo with when the tracker last checked it, so the watcher polls only the rest.

    Repo names and times only (PHASE0_PLAN §13.9).
    """
    with store.session() as s:
        repos = list(s.execute(select(Repo)).scalars())
    checked = {r.full_name.lower(): r.last_polled_at for r in repos if r.last_polled_at and r.poll_status in (200, 304)}
    return {"generated_at": generated_at, "repos": dict(sorted(checked.items())), "license": WATCHLIST_LICENSE,
            "attribution": f"{ATTRIBUTION} Watchlist: {WATCHLIST_ATTRIBUTION}"}  # fmt: skip
