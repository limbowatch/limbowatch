"""Typed domain models. Advisory models hold factual metadata only (FINDINGS F-047, F-059):
no titles, descriptions, authors, publishers or credits."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AdvisoryPackage(Frozen):
    ecosystem: str
    name: str | None
    vulnerable_version_range: str | None = None
    patched_versions: str | None = None


class RepoAdvisory(Frozen):
    """A published repository security advisory, normalized."""

    ghsa_id: str
    repo: str  # owner/name, lower-case
    state: str  # published | withdrawn | closed | ...
    severity: str | None = None
    cve_id: str | None = None
    cvss_v3_vector: str | None = None
    cvss_v4_vector: str | None = None
    cvss_score: float | None = None
    cwe_ids: tuple[str, ...] = ()
    packages: tuple[AdvisoryPackage, ...] = ()
    published_at: datetime | None = None
    updated_at: datetime | None = None
    withdrawn_at: datetime | None = None
    html_url: str


class ReviewedEntry(Frozen):
    """One GitHub-reviewed global advisory (from the reviewed list)."""

    ghsa_id: str
    cve_id: str | None
    reviewed_at: datetime | None
    origin_repo: str | None  # repo the advisory originated from, if any


class CveInfo(Frozen):
    cve_id: str
    state: str  # PUBLISHED | RESERVED | REJECTED | unknown
    published_at: datetime | None = None
    cna: str | None = None
    ghsa_refs: tuple[str, ...] = ()
    repo_refs: tuple[str, ...] = ()


class CveLabel(StrEnum):
    NONE = "no CVE anywhere"
    RESERVED = "CVE reserved (RBP)"
    PUBLISHED_CITED = "CVE published, cited"
    PUBLISHED_UNCITED = "CVE published by another CNA, not cited"
    OTHER = "CVE cited, other state"


class Status(StrEnum):
    LIMBO = "in limbo"
    REVIEWED = "reviewed"
    DUPLICATE = "duplicate of a reviewed advisory"
    WITHDRAWN = "withdrawn"
    NOT_PUBLISHED = "no longer published"


class Facts(Frozen):
    """Everything known about one advisory at one moment. Hashed for change detection."""

    ghsa_id: str
    repo: str
    repo_state: str
    reviewed: bool
    reviewed_at: datetime | None = None
    in_osv: bool | None = None
    cited_cve: str | None = None
    cited_cve_state: str | None = None
    cited_cve_cna: str | None = None
    uncited_cves: tuple[str, ...] = ()
    duplicate_of: tuple[str, ...] = ()  # reviewed GHSAs sharing the advisory's CVE
    nvd_status: str | None = None
    nvd_enriched: bool | None = None


class Assessment(Frozen):
    ghsa_id: str
    status: Status
    cve_label: CveLabel
    likely_permanent: bool
    ecosystems: tuple[str, ...] = Field(default_factory=tuple)
