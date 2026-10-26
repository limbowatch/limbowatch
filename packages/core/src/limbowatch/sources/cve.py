"""CVE Services and the cvelistV5 delta log."""

from __future__ import annotations

import json
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from limbowatch.http import HttpClient
from limbowatch.models import CveInfo
from limbowatch.normalize import cve_record

CVE_API = "https://cveawg.mitre.org/api"
DELTA_LOG = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"


async def lookup(http: HttpClient, cve_id: str) -> CveInfo:
    """Published record if there is one, else the ID's state (RESERVED means reserved but public)."""
    r = await http.get(f"{CVE_API}/cve/{cve_id}")
    if r.ok and isinstance(r.body, dict):
        return cve_record(r.body)
    r = await http.get(f"{CVE_API}/cve-id/{cve_id}")
    state = r.body.get("state", "unknown") if r.ok and isinstance(r.body, dict) else "unknown"
    return CveInfo(cve_id=cve_id, state=state)


@dataclass
class DeltaEntry:
    fetch_time: str
    cve_id: str
    record_url: str


async def delta_since(http: HttpClient, cursor: str | None) -> list[DeltaEntry]:
    """New and updated CVE records after `cursor` (a deltaLog fetchTime), oldest first."""
    r = await http.get(DELTA_LOG)
    if not r.ok or not isinstance(r.body, list):
        return []
    out: list[DeltaEntry] = []
    for entry in r.body:
        ft = entry.get("fetchTime", "")
        if cursor and ft <= cursor:
            continue
        for kind in ("new", "updated"):
            for item in entry.get(kind) or []:
                out.append(DeltaEntry(ft, item["cveId"], item["githubLink"]))
    out.sort(key=lambda e: e.fetch_time)
    return out


async def record(http: HttpClient, url: str) -> CveInfo | None:
    r = await http.get(url)
    body: Any = r.body
    return cve_record(body) if r.ok and isinstance(body, dict) else None


def bulk_records(release_zip: Path, workdir: Path) -> Iterator[CveInfo]:
    """CVE records that reference a GHSA, from a cvelistV5 bulk release (`*_all_CVEs_at_midnight.zip.zip`).

    Used once to bootstrap; afterwards the delta log keeps the tracker current. The inner zip is
    extracted to `workdir` (seeking inside a compressed member would be very slow).
    """
    inner = workdir / "cves.zip"
    if not inner.exists():
        with zipfile.ZipFile(release_zip) as outer:
            outer.extract("cves.zip", workdir)
    with zipfile.ZipFile(inner) as z:
        for name in z.namelist():
            if not name.endswith(".json") or "/CVE-" not in name:
                continue
            raw = z.read(name)
            if b"ghsa-" not in raw.lower():
                continue
            info = cve_record(json.loads(raw))
            if info.ghsa_refs:
                yield info
