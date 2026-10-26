"""The limbo feed: advisories in limbo as OSV-schema records (https://ossf.github.io/osv-schema/).

Records keep the advisory's own GHSA ID, so consumers can de-duplicate against OSV and drop a
record the moment the real one arrives. Factual metadata only: no summary or details text
(FINDINGS F-059). Lifecycle facts go in `database_specific`.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime
from typing import Any

from limbowatch.ecosystems import info
from limbowatch.models import Status
from limbowatch.publish import ATTRIBUTION, Item
from limbowatch.versions import osv_ranges

SCHEMA_VERSION = "1.6.0"


def _iso(d: datetime | None) -> str | None:
    return d.isoformat().replace("+00:00", "Z") if d else None


def record(it: Item, modified: str) -> dict[str, Any]:
    adv, f, a = it.adv, it.facts, it.assessment
    affected = []
    for p in adv.packages:
        eco = info(p.ecosystem)
        if not p.name or eco.osv is None:
            continue
        entry: dict[str, Any] = {"package": {"ecosystem": eco.osv, "name": p.name}}
        conv = osv_ranges(p.ecosystem, p.vulnerable_version_range)
        if conv is not None:
            ranges, versions = conv
            if ranges:
                entry["ranges"] = ranges
            if versions:
                entry["versions"] = versions
        entry["database_specific"] = {
            "vulnerable_version_range": p.vulnerable_version_range,
            "patched_versions": p.patched_versions,
            "range_converted": conv is not None,
        }
        affected.append(entry)
    aliases = sorted({c for c in [adv.cve_id, *f.uncited_cves] if c})
    severity = []
    if adv.cvss_v4_vector:
        severity.append({"type": "CVSS_V4", "score": adv.cvss_v4_vector})
    if adv.cvss_v3_vector:
        severity.append({"type": "CVSS_V3", "score": adv.cvss_v3_vector})
    return {
        "schema_version": SCHEMA_VERSION,
        "id": adv.ghsa_id,
        "modified": modified,
        "published": _iso(adv.published_at),
        "aliases": aliases,
        "affected": affected,
        "severity": severity,
        "references": [{"type": "ADVISORY", "url": adv.html_url}],
        "database_specific": {
            "limbowatch": {
                "status": a.status.value,
                "repository": adv.repo,
                "severity": adv.severity,
                "cwe_ids": list(adv.cwe_ids),
                "cve": a.cve_label.value,
                "cited_cve": f.cited_cve,
                "cited_cve_state": f.cited_cve_state,
                "uncited_cves": list(f.uncited_cves),
                "in_osv": f.in_osv,
                "reviewed": f.reviewed,
                "nvd_status": f.nvd_status,
                "likely_permanent": a.likely_permanent,
                "first_seen_by_limbowatch": it.first_seen,
            },
            "attribution": ATTRIBUTION,
        },
    }


def build(items: list[Item], modified: str) -> tuple[list[dict[str, Any]], bytes]:
    """In-limbo records, plus an `all.zip` in the OSV bulk layout (one <ID>.json per record)."""
    recs = [
        record(i, modified) for i in sorted(items, key=lambda i: i.adv.ghsa_id) if i.assessment.status is Status.LIMBO
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for r in recs:
            zi = zipfile.ZipInfo(f"{r['id']}.json", date_time=(2026, 1, 1, 0, 0, 0))  # stable bytes for diffs
            z.writestr(zi, json.dumps(r, indent=1, sort_keys=True))
    return recs, buf.getvalue()
