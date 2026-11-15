"""Advisories in limbo the watcher matches against: from the limbo feed, or polled from a repo just now.

Both become a `Candidate`: the advisory as normalized by the tracker, plus its CVE state.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from limbowatch.ecosystems import by_osv, package_name
from limbowatch.models import AdvisoryPackage, CveLabel, RepoAdvisory
from limbowatch.publish.feed import is_unpackaged
from limbowatch.versions import norm_name


@dataclass(frozen=True)
class Candidate:
    adv: RepoAdvisory
    cve: CveLabel
    cves: tuple[str, ...]
    source: str  # "feed" or "github"


def from_feed_record(r: dict[str, Any]) -> Candidate:
    lw = r.get("database_specific", {}).get("limbowatch", {})
    pkgs = []
    for a in r.get("affected") or []:
        ds = a.get("database_specific") or {}
        if is_unpackaged(a):  # no ecosystem OSV knows (C/C++, "other"): matched by repository (F-138, F-140)
            pkgs.append(
                AdvisoryPackage(
                    ecosystem=str(ds.get("ecosystem_as_entered") or "other"),
                    name=ds.get("name_as_entered"),
                    vulnerable_version_range=ds.get("vulnerable_version_range"),
                    patched_versions=ds.get("patched_versions"),
                )
            )
            continue
        eco = by_osv(a["package"]["ecosystem"])
        imports = [i.get("path") for i in (a.get("ecosystem_specific") or {}).get("imports") or [] if i.get("path")]
        pkgs.append(
            AdvisoryPackage(
                ecosystem=eco.ghsa if eco else a["package"]["ecosystem"],
                # Go: the advisory's own path is in `imports` when the package names its module (F-113)
                name=imports[0] if imports else ds.get("name_as_entered") or a["package"]["name"],
                vulnerable_version_range=ds.get("vulnerable_version_range"),
                patched_versions=ds.get("patched_versions"),
                module=ds.get("go_module"),
            )
        )
    url = next((x["url"] for x in r.get("references") or [] if x.get("type") == "ADVISORY"), "")
    published = r.get("published")
    adv = RepoAdvisory(
        ghsa_id=r["id"],
        repo=str(lw.get("repository") or "").lower(),
        state="published",
        severity=lw.get("severity"),
        cve_id=lw.get("cited_cve"),
        cwe_ids=tuple(lw.get("cwe_ids") or ()),
        packages=tuple(pkgs),
        published_at=datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None,
        html_url=url,
    )
    label = next((c for c in CveLabel if c.value == lw.get("cve")), CveLabel.NONE)
    return Candidate(adv, label, tuple(r.get("aliases") or ()), "feed")


# What the watcher will unpack from the feed. On 2026-11-14 it held 25,782 records, 50.1 MB unpacked, the largest
# 210 KB (FINDINGS F-192): these leave 20 times that or more, and stop a zip bomb before it fills a CI runner's memory.
MAX_RECORDS = 500_000
MAX_RECORD_BYTES = 5_000_000
MAX_UNPACKED_BYTES = 1_000_000_000


class FeedTooLarge(ValueError):
    """The feed's zip is far larger than any real feed: refused before unpacking."""


class FeedUnreadable(ValueError):
    """A record in the feed's zip couldn't be decoded (bad JSON, compression or fields)."""


def from_feed_zip(data: bytes) -> list[Candidate]:
    """Every record of the feed's `all.zip` (one `<GHSA>.json` per advisory in limbo).

    The zip's own listing is checked against the limits first, and each record is read at most to its limit (a
    record can't unpack to more than its listed size), so a tampered feed can't exhaust memory."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        records = [i for i in z.infolist() if i.filename.endswith(".json")]
        if len(records) > MAX_RECORDS:
            raise FeedTooLarge(f"the feed has {len(records):,} records; more than {MAX_RECORDS:,} isn't a real feed")
        if (total := sum(i.file_size for i in records)) > MAX_UNPACKED_BYTES:
            raise FeedTooLarge(f"the feed unpacks to {total:,} bytes; over {MAX_UNPACKED_BYTES:,} isn't a real feed")
        out = []
        for i in records:
            if i.file_size > MAX_RECORD_BYTES:
                raise FeedTooLarge(f"{i.filename} is {i.file_size:,} bytes; no real record is that big")
            try:
                with z.open(i) as f:
                    out.append(from_feed_record(json.loads(f.read(MAX_RECORD_BYTES + 1))))
            except Exception as e:  # anything a damaged record raises: named, then a clean exit 2 (F-193)
                raise FeedUnreadable(f"{i.filename}: {type(e).__name__}: {e}") from e
        return out


@dataclass
class Index:
    """Candidates by (ecosystem, normalized package name) and by source repo."""

    by_name: dict[tuple[str, str], list[Candidate]] = field(default_factory=lambda: defaultdict(list))
    by_repo: dict[str, list[Candidate]] = field(default_factory=lambda: defaultdict(list))
    ids: set[str] = field(default_factory=set)

    def add(self, c: Candidate) -> None:
        if c.adv.ghsa_id in self.ids:
            return
        self.ids.add(c.adv.ghsa_id)
        self.by_repo[c.adv.repo].append(c)
        for p in c.adv.packages:
            n = package_name(p.ecosystem, p.name)
            if n is not None and n.valid:
                self.by_name[(p.ecosystem, norm_name(p.ecosystem, n.name))].append(c)
