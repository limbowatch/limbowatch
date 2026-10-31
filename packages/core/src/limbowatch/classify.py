"""Classify an advisory from its facts. Pure: no I/O.

Facts are independent (repo advisory, review, OSV, CVE, NVD) and change in any order, so the
status is recomputed from scratch every time (PHASE0_PLAN §3).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from limbowatch.ecosystems import reviewable
from limbowatch.models import GITHUB_CNA, Assessment, CveLabel, Facts, RepoAdvisory, Status


def status(f: Facts) -> Status:
    if f.reviewed or f.in_osv:
        return Status.REVIEWED
    if f.repo_state == "withdrawn":
        return Status.WITHDRAWN
    if f.repo_state != "published":
        return Status.NOT_PUBLISHED
    if f.duplicate_of:
        return Status.DUPLICATE
    return Status.LIMBO


def cve_label(f: Facts) -> CveLabel:
    if f.cited_cve:
        if f.cited_cve_state == "PUBLISHED":
            return CveLabel.PUBLISHED_CITED
        if f.cited_cve_state == "RESERVED":
            return CveLabel.RESERVED
        return CveLabel.OTHER
    if f.uncited_cves:
        return CveLabel.PUBLISHED_UNCITED
    return CveLabel.NONE


def assess(adv: RepoAdvisory, f: Facts) -> Assessment:
    ecos = tuple(sorted({p.ecosystem for p in adv.packages} or {"other"}))
    return Assessment(
        ghsa_id=adv.ghsa_id,
        status=status(f),
        cve_label=cve_label(f),
        likely_permanent=not any(reviewable(e) for e in ecos),
        ecosystems=ecos,
    )


def facts_hash(f: Facts) -> str:
    return hashlib.sha256(json.dumps(f.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()


def transitions(old: Facts | None, new: Facts, cnas: Mapping[str, str | None] | None = None) -> list[str]:
    """Human-readable events between two fact snapshots (empty if nothing meaningful changed).

    `cnas` maps uncited CVE IDs to their CNA, so GitHub's own CVEs aren't called another CNA's (F-067)."""
    if old is None:
        return ["first seen"]
    ev = []
    if status(old) != status(new):
        ev.append(f"{status(old).value} -> {status(new).value}")
    if old.cited_cve != new.cited_cve:
        ev.append(f"cites {new.cited_cve or 'no CVE'} (was {old.cited_cve or 'none'})")
    elif old.cited_cve_state != new.cited_cve_state and new.cited_cve:
        ev.append(f"{new.cited_cve} {old.cited_cve_state or '?'} -> {new.cited_cve_state}")
    added = sorted(set(new.uncited_cves) - set(old.uncited_cves))
    github = [c for c in added if (cnas or {}).get(c) == GITHUB_CNA]
    if github:
        ev.append(f"new CVE from GitHub's CNA, not cited: {', '.join(github)}")
    if other := [c for c in added if c not in github]:
        ev.append(f"new CVE from another CNA: {', '.join(other)}")
    if not old.duplicate_of and new.duplicate_of:
        ev.append(f"duplicate of reviewed {', '.join(new.duplicate_of)}")
    return ev
