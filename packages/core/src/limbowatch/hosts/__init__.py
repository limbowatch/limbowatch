"""Where org-wide mode finds projects: GitLab groups, Gitea/Forgejo orgs, GitHub orgs and users, plain git URLs
(PHASE0_PLAN §7).

A source lists its projects; each project is then cloned shallowly and inventoried like a single scan.
Nothing listed is dropped: a project that isn't checked is returned with the reason (archived, empty,
excluded), and a source that can't be listed is an error, never an empty list.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import StrEnum
from fnmatch import fnmatchcase
from urllib.parse import urlsplit, urlunsplit


class HostKind(StrEnum):
    GITLAB = "gitlab"
    GITEA = "gitea"  # also Forgejo
    GITHUB = "github"  # github.com or GitHub Enterprise Server
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
    note: str | None = None  # listed, but the listing may be partial (what the token can't see), and why


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
    """The `rel="next"` URL of a Link header, if it's on the same host with the same scheme: the token goes with it,
    so an https listing never follows an http:// page link (a proxy that hides https from the server sends those)."""
    for part in (link or "").split(","):
        url, _, rel = part.partition(";")
        if 'rel="next"' in rel:
            url = url.strip().strip("<>")
            n, b = urlsplit(url), urlsplit(base_url)
            if (n.scheme, n.netloc.lower()) != (b.scheme, b.netloc.lower()):
                raise SourceError(f"pagination left {base_url}: {redact(url)}")
            return url
    return None


def excluded(project: Project, patterns: list[str]) -> bool:
    """`--exclude` globs match the project path (`group/*/legacy-*`) or host/path."""
    return any(fnmatchcase(project.path, p) or fnmatchcase(project.name, p) for p in patterns)


def git_project(url: str) -> Project:
    """A plain git URL: https, or http (a token isn't sent over http unless allowed: `refuse_cleartext`)."""
    p = urlsplit(url)
    if p.scheme not in ("https", "http") or not p.netloc:
        raise SourceError(f"--git wants an https:// URL, got {redact(url)!r}")
    if p.username or p.password:
        raise SourceError(f"put credentials in LIMBOWATCH_SOURCE_TOKEN, not in the URL: {redact(url)}")
    path = safe_path(p.path.removesuffix("/").removesuffix(".git"))
    base = f"{p.scheme}://{p.netloc}"
    return Project(HostKind.GIT, base, path, url, f"{base}/{path}")


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def cleartext(url: str) -> bool:
    """Plain http to another machine: whatever is sent there, a token included, crosses the network readable."""
    try:
        p = urlsplit(url)
        host = p.hostname or ""
    except ValueError as e:  # http://[::1 and the like; not shown, since it can't be redacted
        raise SourceError("not a URL that can be read (a tracker or source URL)") from e
    return p.scheme == "http" and not _loopback(host)


def refuse_cleartext(urls: list[str], token_name: str, allow: bool) -> None:
    """A token is never sent over plain http to another machine unless the user allows it (--allow-insecure-http);
    this machine (localhost, 127.0.0.1, ::1) is fine. Raises SourceError naming the URLs."""
    if allow:
        return
    if bad := sorted({redact(u) for u in urls if cleartext(u)}):
        raise SourceError(
            f"{token_name} would be sent over plain http to {', '.join(bad)}, where anyone on the network can read it; "
            "use https, or --allow-insecure-http (LIMBOWATCH_ALLOW_INSECURE_HTTP=1) to send it anyway"
        )


def clone_url(base_url: str, given: object, path: str) -> str:
    """The clone URL a host's API gives, if it's on the host that was listed (same scheme and host); otherwise the
    one built from the base URL. The API's answer is never followed to another host or scheme (file://, ssh://)."""
    built = f"{base_url}/{path}.git"
    if not isinstance(given, str) or not given:
        return built
    g, b = urlsplit(given), urlsplit(base_url)
    return given if (g.scheme, g.netloc.lower()) == (b.scheme, b.netloc.lower()) else built
