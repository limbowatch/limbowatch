"""Turn raw GitHub API objects into models. Pure: no I/O.

Only factual metadata survives normalization. Titles, descriptions, authors, publishers,
credits and collaborators are dropped here, so nothing downstream can store or publish them
(FINDINGS F-047, F-059).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from limbowatch.models import AdvisoryPackage, CveInfo, RepoAdvisory, ReviewedEntry

_REPO_FROM_URL = re.compile(r"/repos/([^/]+/[^/]+)/security-advisories/")
GHSA_RE = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}", re.I)
GH_REPO_RE = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", re.I)


def ts(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if d.tzinfo is None:
        from datetime import UTC

        d = d.replace(tzinfo=UTC)
    return d


_HTML_REPO = re.compile(r"^https://github\.com/([^/]+/[^/]+)/security/advisories/", re.I)


def canonical_repo(html_url: Any, polled_as: str) -> str:
    """The repo an advisory belongs to now. Renamed or transferred repos redirect, so a repo polled
    under an old name returns advisories whose URL carries the new name (FINDINGS F-060)."""
    m = _HTML_REPO.match(html_url or "") if isinstance(html_url, str) else None
    return (m.group(1) if m else polled_as).lower()


def repo_advisory(raw: dict[str, Any], repo: str) -> RepoAdvisory:
    cvss = raw.get("cvss_severities") or {}
    v3 = (cvss.get("cvss_v3") or {}) if isinstance(cvss, dict) else {}
    v4 = (cvss.get("cvss_v4") or {}) if isinstance(cvss, dict) else {}
    legacy = raw.get("cvss") or {}
    score = v4.get("score") or v3.get("score") or (legacy.get("score") if isinstance(legacy, dict) else None)
    pkgs = []
    for v in raw.get("vulnerabilities") or []:
        p = v.get("package") or {}
        pkgs.append(
            AdvisoryPackage(
                ecosystem=(p.get("ecosystem") or "other").lower(),
                name=p.get("name") or None,
                vulnerable_version_range=v.get("vulnerable_version_range") or None,
                patched_versions=v.get("patched_versions") or None,
            )
        )
    return RepoAdvisory(
        ghsa_id=raw["ghsa_id"],
        repo=canonical_repo(raw.get("html_url"), repo),
        state=raw.get("state") or "unknown",
        severity=raw.get("severity") or None,
        cve_id=raw.get("cve_id") or None,  # the API returns "" as well as null
        cvss_v3_vector=v3.get("vector_string") or None,
        cvss_v4_vector=v4.get("vector_string") or None,
        cvss_score=float(score) if score else None,
        cwe_ids=tuple(sorted(raw.get("cwe_ids") or [])),
        packages=tuple(pkgs),
        published_at=ts(raw.get("published_at")),
        updated_at=ts(raw.get("updated_at")),
        withdrawn_at=ts(raw.get("withdrawn_at")),
        html_url=raw.get("html_url") or f"https://github.com/{repo}/security/advisories/{raw['ghsa_id']}",
    )


def reviewed_entry(raw: dict[str, Any]) -> ReviewedEntry:
    m = _REPO_FROM_URL.search(raw.get("repository_advisory_url") or "")
    return ReviewedEntry(
        ghsa_id=raw["ghsa_id"],
        cve_id=raw.get("cve_id") or None,
        reviewed_at=ts(raw.get("github_reviewed_at") or raw.get("published_at")),
        origin_repo=m.group(1).lower() if m else None,
    )


def cve_record(raw: dict[str, Any]) -> CveInfo:
    """A CVE 5.x record (CVE Services `api/cve/{id}` or the CVE List)."""
    import json

    md = raw.get("cveMetadata") or {}
    cna = (raw.get("containers") or {}).get("cna") or {}
    text = json.dumps(cna)
    return CveInfo(
        cve_id=md.get("cveId", ""),
        state=md.get("state") or "unknown",
        published_at=ts(md.get("datePublished")),
        cna=md.get("assignerShortName"),
        ghsa_refs=tuple(sorted({g.upper() for g in GHSA_RE.findall(text)})),
        repo_refs=tuple(sorted({f"{o}/{r}".lower().removesuffix(".git") for o, r in GH_REPO_RE.findall(text)})),
    )
