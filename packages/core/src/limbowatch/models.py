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
    # Go: the module that contains this package path, per the Go module proxy (F-113). None: not resolved. Set by the
    # tracker when it publishes, never stored with the advisory.
    module: str | None = None


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
    link_rule: int = 0  # normalize.LINK_RULE the record was read with; 0: before F-120, or no record (cve-id only)


GITHUB_CNA = "GitHub_M"  # GitHub's CNA short name in CVE records


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


# --- the watcher's inventory (Phase 4) ---------------------------------------------------------


class Unchecked(StrEnum):
    """Why a dependency can't be checked. Every one is reported, never dropped (SPEC; FINDINGS F-078)."""

    NO_VERSION = "no resolved version"
    RANGE_ONLY = "only a version range is given"
    LOCAL = "local package"
    VCS = "installed from a Git repository or URL"
    PATH = "installed from a local path"
    UNKNOWN_ECOSYSTEM = "ecosystem not supported"
    LOCKFILE_UNREADABLE = "lockfile couldn't be read"
    NO_LOCKFILES = "no supported lockfile or manifest found"
    # A whole file's transitive dependencies (FINDINGS F-132): Maven has no lockfile, so only pom.xml's direct
    # dependencies are known unless OSV-Scanner resolves the rest; Gradle resolves at build time.
    TRANSITIVE = "transitive dependencies not resolved"
    NO_GRADLE_LOCKFILE = "Gradle build without a lockfile"
    NO_PURL = "SBOM component without a package URL"
    # Partly checked: matched against the limbo feed by name, but not against its source repo.
    # Upstream source dependencies (C/C++ and other code taken in by git or archive, PHASE0_PLAN §13.18, F-136).
    UPSTREAM_UNKNOWN = "upstream repository unknown"
    UPSTREAM_NO_REF = "upstream version or commit unknown"
    VENDORED = "vendored copy; its version is unknown"
    UPSTREAM_OFF_GITHUB = "upstream not on GitHub, where repository advisories are published"
    UPSTREAM_NO_CHECK = "upstream source not checked (--no-upstream-check)"
    NO_REPO = "source repository unknown; checked against the limbo feed by name only"
    REPO_NOT_POLLED = "source repository not checked (GitHub rate limit); checked against the limbo feed by name only"


class Dependency(Frozen):
    """One package at one version, as installed, with where it was declared."""

    ecosystem: str  # GHSA ecosystem key (npm, pip, go, ...)
    name: str
    version: str
    source: str  # lockfile, manifest or SBOM path, relative to the project root
    line: int = 1  # where to point an alert; 1 when the package can't be located in the file
    purl: str | None = None
    note: str | None = None  # e.g. why a package OSV-Scanner skipped is checked anyway


class UnresolvedDependency(Frozen):
    reason: Unchecked
    source: str
    name: str = ""  # empty when a whole file couldn't be read
    version: str = ""
    ecosystem: str = ""
    detail: str = ""
    line: int = 1


class UpstreamKind(StrEnum):
    """How a project takes in another project's source (PHASE0_PLAN §6 Tier 3; FINDINGS F-136)."""

    SUBMODULE = "git submodule"
    FETCHCONTENT = "CMake FetchContent"
    EXTERNALPROJECT = "CMake ExternalProject"
    CPM = "CMake CPM"
    BAZEL_MODULE = "Bazel module"
    BAZEL_ARCHIVE = "Bazel http_archive"
    BAZEL_GIT = "Bazel git_repository"
    VCPKG = "vcpkg port"
    CONAN = "Conan package"
    MESON_WRAP = "meson wrap"


class Upstream(Frozen):
    """Another project's source, taken in by git or archive rather than from a package registry.

    `repo` and `ref` say what the project builds from: a commit, or a tag; `version` is a declared package version
    (Bazel module, vcpkg port, Conan package) that a registry maps to a repo and tag. Whatever couldn't be found is
    None, with the reason in `detail`."""

    kind: UpstreamKind
    name: str  # as declared: the submodule path, the FetchContent/module/port/package name
    source: str  # the file that declares it, relative to the project root
    line: int = 1
    url: str | None = None  # the git or archive URL as declared, variables substituted
    host: str | None = None  # e.g. github.com
    repo: str | None = None  # path on the host, e.g. madler/zlib (lower-case on github.com)
    ref: str | None = None  # a commit or a tag
    ref_is_commit: bool = False
    version: str | None = None  # an exact version, or a minimum (">=1.2", vcpkg's "version>=")
    baseline: str | None = None  # vcpkg: the commit of microsoft/vcpkg whose port versions apply
    via: str = ""  # how repo and ref were found, when not from the declaration itself
    detail: str = ""  # what's missing, and why


class Inventory(Frozen):
    dependencies: tuple[Dependency, ...] = ()
    upstreams: tuple[Upstream, ...] = ()  # source taken in by git or archive (submodules, CMake, Bazel, vcpkg, ...)
    unresolved: tuple[UnresolvedDependency, ...] = ()
    sources: tuple[str, ...] = ()  # files read
    tool: str = ""  # e.g. "osv-scanner 2.7.0" or "cyclonedx"
    skipped: tuple[str, ...] = ()  # reports Limbowatch itself wrote (CycloneDX output), not dependency sources


class MatchKind(StrEnum):
    PACKAGE = "package and version"  # the advisory names this package, and the version is in its range
    REPOSITORY = "repository"  # the advisory's package name is unusable; it's from this package's source repo
    UPSTREAM = "upstream source"  # an advisory naming no registry package, about the repo a project builds from


class Finding(Frozen):
    """One dependency affected (or possibly affected) by one advisory in limbo."""

    key: str  # stable across runs and versions: ecosystem, package and advisory
    dependency: Dependency
    ghsa_id: str
    url: str
    repo: str
    severity: str | None = None
    cve: CveLabel = CveLabel.NONE
    cves: tuple[str, ...] = ()
    published_at: datetime | None = None
    affected: bool | None = True  # None: possibly; the range couldn't be evaluated exactly
    match: MatchKind = MatchKind.PACKAGE
    advisory_package: str = ""  # the package name as the advisory gives it
    vulnerable_range: str | None = None
    fixed: str | None = None
    evidence: str = ""
    source: str = "feed"  # "feed" (limbo.watch) or "github" (polled from the repo just now)
