"""Where org-wide mode finds projects: GitLab groups, Gitea/Forgejo orgs, plain git URLs (PHASE0_PLAN §7).

A source lists its projects; each project is then cloned shallowly and inventoried like a single scan.
Nothing listed is dropped: a project that isn't checked is returned with the reason (archived, empty,
excluded), and a source that can't be listed is an error, never an empty list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from fnmatch import fnmatchcase
from urllib.parse import urlsplit, urlunsplit


class HostKind(StrEnum):
    GITLAB = "gitlab"
    GITEA = "gitea"  # also Forgejo
    GIT = "git"  # any git URL: no API, so no issues


class Skip(StrEnum):
    """Why a listed project isn't checked. Each one is reported."""

    ARCHIVED = "archived (--include-archived checks it)"
    EMPTY = "empty repository"
    NO_REPOSITORY = "repository disabled"
    DELETION = "marked for deletion"
    EXCLUDED = "excluded (--exclude)"


@dataclass(frozen=True)
class Project:
    kind: HostKind
    base_url: str  # https://gitlab.example.com, without a trailing slash
    path: str  # group/sub/project, or owner/repo; for plain git, the URL's path
    clone_url: str
    web_url: str
    public: bool | None = None  # None: unknown (plain git)
    archived: bool = False

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).netloc

    @property
    def name(self) -> str:
        """How the project is shown and where its state lives: host/path."""
        return f"{self.host}/{self.path}"


@dataclass
class Listing:
    source: str  # as given, without credentials
    kind: HostKind
    projects: list[Project] = field(default_factory=list)
    skipped: list[tuple[Project, Skip]] = field(default_factory=list)
    error: str | None = None  # the source couldn't be listed (completely)


class SourceError(ValueError):
    pass


_SEGMENT = re.compile(r"^[\w.+-]+$")


def safe_path(path: str) -> str:
    """A project path that is safe to use under a state directory: segments of word characters, dots, plus
    and dashes, never "." or "..". Host APIs return such paths; anything else is refused, not rewritten."""
    parts = path.strip("/").split("/")
    if not parts or any(not _SEGMENT.match(p) or p in (".", "..") for p in parts):
        raise SourceError(f"unexpected project path {path!r}")
    return "/".join(parts)


def split_url(url: str, default_base: str | None = None) -> tuple[str, str]:
    """`https://host/a/b` → ("https://host", "a/b"); a bare path "a/b" takes `default_base`.

    Instances under a sub-path (https://host/gitlab/...) aren't supported: their base can't be told
    from the group path."""
    parts = urlsplit(url)
    if parts.scheme in ("http", "https") and parts.netloc:
        if parts.username or parts.password:
            raise SourceError(f"put credentials in LIMBOWATCH_SOURCE_TOKEN, not in the URL: {redact(url)}")
        return f"{parts.scheme}://{parts.netloc}", safe_path(parts.path.removeprefix("/groups/"))
    if parts.scheme or parts.netloc or not default_base:
        raise SourceError(f"want https://host/path or a path with a base URL, got {redact(url)!r}")
    return default_base.rstrip("/"), safe_path(url)


def redact(url: str) -> str:
    """The URL without user or password."""
    p = urlsplit(url)
    if not (p.username or p.password):
        return url
    host = p.hostname or ""
    return urlunsplit((p.scheme, host + (f":{p.port}" if p.port else ""), p.path, p.query, p.fragment))


def next_link(link: str | None, base_url: str) -> str | None:
    """The `rel="next"` URL of a Link header, if it's on the same host: the token goes with it."""
    for part in (link or "").split(","):
        url, _, rel = part.partition(";")
        if 'rel="next"' in rel:
            url = url.strip().strip("<>")
            if urlsplit(url).netloc != urlsplit(base_url).netloc:
                raise SourceError(f"pagination left {base_url}: {redact(url)}")
            return url
    return None


def excluded(project: Project, patterns: list[str]) -> bool:
    """`--exclude` globs match the project path (`group/*/legacy-*`) or host/path."""
    return any(fnmatchcase(project.path, p) or fnmatchcase(project.name, p) for p in patterns)


def git_project(url: str) -> Project:
    """A plain git URL (https only, so a token header can be scoped to its host)."""
    p = urlsplit(url)
    if p.scheme not in ("https", "http") or not p.netloc:
        raise SourceError(f"--git wants an https:// URL, got {redact(url)!r}")
    if p.username or p.password:
        raise SourceError(f"put credentials in LIMBOWATCH_SOURCE_TOKEN, not in the URL: {redact(url)}")
    path = safe_path(p.path.removesuffix("/").removesuffix(".git"))
    base = f"{p.scheme}://{p.netloc}"
    return Project(HostKind.GIT, base, path, url, f"{base}/{path}")
