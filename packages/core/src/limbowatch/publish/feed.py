"""The limbo feed: advisories in limbo as OSV-schema records (https://ossf.github.io/osv-schema/).

Records keep the advisory's own GHSA ID, so consumers can de-duplicate against OSV and drop a
record the moment the real one arrives. Factual metadata only: no summary or details text
(FINDINGS F-059). Lifecycle facts go in `database_specific`.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import zipfile
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from limbowatch.ecosystems import OFFLINE_ECOSYSTEMS, info, package_name
from limbowatch.models import AdvisoryPackage, Status
from limbowatch.publish import ATTRIBUTION, Item
from limbowatch.versions import UPSTREAM, osv_ranges

SCHEMA_VERSION = "1.6.0"


def _iso(d: datetime | None) -> str | None:
    return d.isoformat().replace("+00:00", "Z") if d else None


def record(it: Item, modified: str) -> dict[str, Any]:
    adv, f, a = it.adv, it.facts, it.assessment
    affected = []
    for p in adv.packages:
        eco, name = info(p.ecosystem), package_name(p.ecosystem, p.name)
        if name is None or eco.osv is None:
            affected.append(unpackaged(adv.repo, p, it.git))
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


def unpackaged(repo: str, p: AdvisoryPackage, git: dict[str, Any]) -> dict[str, Any]:
    """An advisory package OSV has no ecosystem for (C/C++, `other`, ...): package `GIT`, named by the repo URL, the
    versions as entered, and OSV GIT ranges on the repo where every version they name has a tag (`git`: version →
    [tag, commit] or None, from the tracker's `git ls-remote`; F-136, F-138). Consumers match it by repository.

    It has a `package` because watchers before 0.1.0a7 read `affected[].package` of every entry: an entry without one
    made them fail (F-140). As a `GIT` package they never match it, as before."""
    ds: dict[str, Any] = {
        "ecosystem_as_entered": p.ecosystem,
        "name_as_entered": p.name,
        "vulnerable_version_range": p.vulnerable_version_range,
        "patched_versions": p.patched_versions,
    }
    entry: dict[str, Any] = {"package": {"ecosystem": "GIT", "name": f"https://github.com/{repo}"}}
    ranges = git_ranges(repo, p, git)
    if ranges is not None:
        entry["ranges"] = ranges
        ds["tags"] = {v: git[v][0] for v in sorted(git_versions(p)) if git.get(v)}
    ds["range_converted"] = ranges is not None
    entry["database_specific"] = ds
    return entry


def is_unpackaged(entry: dict[str, Any]) -> bool:
    """An `affected` entry for an advisory package OSV has no ecosystem for (see `unpackaged`)."""
    return "package" not in entry or "ecosystem_as_entered" in (entry.get("database_specific") or {})


def git_versions(p: AdvisoryPackage) -> set[str]:
    """The versions an unpackaged advisory package's range and fix name, as OSV events need them."""
    conv = osv_ranges(UPSTREAM, p.vulnerable_version_range, p.patched_versions)
    if conv is None:
        return set()
    ranges, versions = conv
    return {v for r in ranges for ev in r["events"] for v in ev.values() if v != "0"} | set(versions)


def git_ranges(repo: str, p: AdvisoryPackage, git: dict[str, Any]) -> list[dict[str, Any]] | None:
    """OSV GIT ranges: the range's versions turned into the commits of their tags. None unless every one has a tag."""
    conv = osv_ranges(UPSTREAM, p.vulnerable_version_range, p.patched_versions)
    if conv is None:
        return None
    ranges, versions = conv
    if versions and not ranges:
        # Only exact versions ("3.26.0", fixed in 3.27.0): maintainers mostly mean "up to 3.26.0", so a single-commit
        # range would understate it, and "from the first commit" would overstate it; left as text (F-141)
        return None

    def commit(v: str) -> str | None:
        hit = git.get(v)
        return str(hit[1]) if hit and len(str(hit[1])) == 40 else None

    out = []
    for r in ranges:
        events = []
        for ev in r["events"]:
            ((kind, v),) = ev.items()
            c = "0" if v == "0" else commit(v)
            if c is None:
                return None
            events.append({kind: c})
        out.append({"type": "GIT", "repo": f"https://github.com/{repo}", "events": events})
    for v in versions:  # an exact version: affected from its commit up to and including it
        c = commit(v)
        if c is None:
            return None
        out.append({"type": "GIT", "repo": f"https://github.com/{repo}", "events": [{"introduced": c},
                                                                                    {"last_affected": c}]})  # fmt: skip
    return out or None


def _quality(affected: list[dict[str, Any]]) -> dict[str, str]:
    """How far a consumer can trust the record's package data: names and ranges (F-069). Entries without a package
    (matched by repository) count for ranges only."""
    allds = [a["database_specific"] for a in affected]
    ds = [a["database_specific"] for a in affected if not is_unpackaged(a)]
    if not allds:
        return {"names": "none", "ranges": "none"}
    names = (
        "none"
        if not ds
        else "invalid"
        if not all(d["name_valid"] for d in ds)
        else "cleaned"
        if any("name_as_entered" in d for d in ds)
        else "ok"
    )
    conv = [d["range_converted"] for d in allds]
    ranges = "converted" if all(conv) else "partly converted" if any(conv) else "as entered"
    return {"names": names, "ranges": ranges}


def build(
    items: list[Item], modified: str, previous: Mapping[str, tuple[str, str]] | None = None
) -> tuple[list[dict[str, Any]], bytes]:
    """In-limbo records, plus an `all.zip` in the OSV bulk layout (one <ID>.json per record).

    `modified` is when this build ran. A record that's the same as in `previous` (from `previous_modified`, the last
    published feed) keeps that feed's `modified`, so it says when the record last changed, as OSV defines it, and an
    unchanged record's file is byte for byte the same as yesterday's (F-174)."""
    recs = [
        record(i, modified) for i in sorted(items, key=lambda i: i.adv.ghsa_id) if i.assessment.status is Status.LIMBO
    ]
    now = datetime.fromisoformat(modified)
    for r in recs:
        if (p := (previous or {}).get(r["id"])) and p[0] == content_key(r) and datetime.fromisoformat(p[1]) <= now:
            r["modified"] = p[1]
    return recs, _zip(recs)


def content_key(rec: Mapping[str, Any]) -> str:
    """A record's digest without its `modified`: equal keys mean nothing a consumer reads has changed."""
    body = {k: v for k, v in rec.items() if k != "modified"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# A published record is a few KB; anything far larger isn't one of ours, so it's skipped rather than read.
_MAX_RECORD = 1 << 20
_TIMESTAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z")


def previous_modified(zipped: bytes) -> dict[str, tuple[str, str]]:
    """GHSA ID → (content_key, modified) for each record in a previously published `all.zip`.

    The file comes over the network, so it's only trusted this far: a record whose content matches today's lends it its
    timestamp, and only a well-formed one (`build` also refuses a timestamp later than the build). Entries that aren't
    valid records are skipped; a file that isn't a zip raises `zipfile.BadZipFile`."""
    out: dict[str, tuple[str, str]] = {}
    with zipfile.ZipFile(io.BytesIO(zipped)) as z:
        for zi in z.infolist():
            if zi.is_dir() or not zi.filename.endswith(".json") or zi.file_size > _MAX_RECORD:
                continue
            try:
                with z.open(zi) as f:
                    rec = json.loads(f.read(_MAX_RECORD + 1))
            except (ValueError, zipfile.BadZipFile, OSError):
                continue
            if not isinstance(rec, dict):
                continue
            rid, mod = rec.get("id"), rec.get("modified")
            if isinstance(rid, str) and isinstance(mod, str) and _TIMESTAMP.fullmatch(mod):
                out[rid] = (content_key(rec), mod)
    return out


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

    A record with packages in two ecosystems goes in both; an advisory package OSV has no ecosystem for is in GIT. Every
    name in OFFLINE_ECOSYSTEMS gets a zip.
    """

    def eco(a: dict[str, Any]) -> str | None:
        return a["package"]["ecosystem"] if "package" in a else None

    names = sorted({*OFFLINE_ECOSYSTEMS, *(e for r in recs for a in r["affected"] if (e := eco(a)))})
    return {e: _zip(r for r in recs if any(eco(a) == e for a in r["affected"])) for e in names}


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
