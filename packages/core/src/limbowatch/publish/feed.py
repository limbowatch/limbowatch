"""The limbo feed: advisories in limbo as OSV-schema records (https://ossf.github.io/osv-schema/).

Records keep the advisory's own GHSA ID, so consumers can de-duplicate against OSV and drop a
record the moment the real one arrives. Factual metadata only: no summary or details text
(FINDINGS F-059). Lifecycle facts go in `database_specific`.
"""

from __future__ import annotations

import base64
import io
import json
import zipfile
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from limbowatch.ecosystems import OSV_ECOSYSTEMS, info, package_name
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
        eco, name = info(p.ecosystem), package_name(p.ecosystem, p.name)
        if name is None or eco.osv is None:
            continue
        entry: dict[str, Any] = {"package": {"ecosystem": eco.osv, "name": name.name}}
        if p.ecosystem == "go" and p.module:
            # OSV's Go form: the package names the module, whose versions the ranges are in; the path the advisory
            # names goes in `imports` when it's a package inside that module (F-113)
            entry["package"]["name"] = p.module
            if p.module != name.name:
                entry["ecosystem_specific"] = {"imports": [{"path": name.name}]}
        conv = osv_ranges(p.ecosystem, p.vulnerable_version_range, p.patched_versions)
        if conv is not None:
            ranges, versions = conv
            if ranges:
                entry["ranges"] = ranges
            if versions:
                entry["versions"] = versions
        entry["database_specific"] = (
            {
                "vulnerable_version_range": p.vulnerable_version_range,
                "patched_versions": p.patched_versions,
                "range_converted": conv is not None,
                "name_valid": name.valid,  # False: doesn't fit the ecosystem's naming, so it can't match (F-069)
            }
            | ({"name_as_entered": name.raw} if name.cleaned else {})
            | ({"go_module": p.module} if p.module else {})
        )
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
                "quality": _quality(affected),
            },
            "attribution": ATTRIBUTION,
        },
    }


def _quality(affected: list[dict[str, Any]]) -> dict[str, str]:
    """How far a consumer can trust the record's package data: names and ranges (F-069)."""
    ds = [a["database_specific"] for a in affected]
    if not ds:
        return {"names": "none", "ranges": "none"}
    names = (
        "invalid"
        if not all(d["name_valid"] for d in ds)
        else "cleaned"
        if any("name_as_entered" in d for d in ds)
        else "ok"
    )
    conv = [d["range_converted"] for d in ds]
    ranges = "converted" if all(conv) else "partly converted" if any(conv) else "as entered"
    return {"names": names, "ranges": ranges}


def build(items: list[Item], modified: str) -> tuple[list[dict[str, Any]], bytes]:
    """In-limbo records, plus an `all.zip` in the OSV bulk layout (one <ID>.json per record)."""
    recs = [
        record(i, modified) for i in sorted(items, key=lambda i: i.adv.ghsa_id) if i.assessment.status is Status.LIMBO
    ]
    return recs, _zip(recs)


def _zip(recs: Iterable[dict[str, Any]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for r in recs:
            zi = zipfile.ZipInfo(f"{r['id']}.json", date_time=(2026, 1, 1, 0, 0, 0))  # stable bytes for diffs
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, json.dumps(r, indent=1, sort_keys=True))
    return buf.getvalue()


def by_ecosystem(recs: list[dict[str, Any]]) -> dict[str, bytes]:
    """One `all.zip` per OSV ecosystem, as OSV serves them at `<Ecosystem>/all.zip` (F-073, F-074).

    A record with packages in two ecosystems goes in both. Every name in OSV_ECOSYSTEMS gets a zip.
    """
    names = sorted({*OSV_ECOSYSTEMS, *(a["package"]["ecosystem"] for r in recs for a in r["affected"])})
    return {e: _zip(r for r in recs if any(a["package"]["ecosystem"] == e for a in r["affected"])) for e in names}


def bundle(zips: dict[str, bytes]) -> bytes:
    """The per-ecosystem zips laid out as OSV-Scanner's cache, for `--offline-vulnerabilities --local-db-path`."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for e, data in sorted(zips.items()):
            z.writestr(zipfile.ZipInfo(f"osv-scalibr/{e}/all.zip", date_time=(2026, 1, 1, 0, 0, 0)), data)
    return buf.getvalue()


def _crc32c_table() -> list[int]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC32C = _crc32c_table()


def crc32c(data: bytes) -> int:
    """CRC-32C (Castagnoli), the checksum GCS sends and OSV-Scanner checks before reusing a cached zip."""
    c, t = 0xFFFFFFFF, _CRC32C
    for b in data:
        c = t[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def goog_hash(data: bytes) -> str:
    """The `X-Goog-Hash` header value OSV-Scanner expects on `HEAD <host>/<Ecosystem>/all.zip` (F-073)."""
    return "crc32c=" + base64.b64encode(crc32c(data).to_bytes(4, "big")).decode()
