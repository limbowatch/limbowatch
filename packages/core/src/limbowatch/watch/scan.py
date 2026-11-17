"""`scan()`: an inventory against the limbo feed and, for repos the tracker doesn't cover, their own advisories.

Nothing about the project is sent to limbo.watch: the feed and watchlist are downloaded whole
(PHASE0_PLAN §13.9). Package names go to deps.dev for mapping, and source repo names to GitHub.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import zipfile
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from limbowatch.http import HttpClient, ResponseTooLarge
from limbowatch.models import (
    Dependency,
    Finding,
    Inventory,
    Unchecked,
    UnresolvedDependency,
    Upstream,
    UpstreamKind,
)
from limbowatch.watch import feedtrust, mapping, upstream
from limbowatch.watch import upstream_check as upcheck
from limbowatch.watch.candidates import FeedTooLarge, FeedUnreadable, Index, from_feed_zip
from limbowatch.watch.match import match
from limbowatch.watch.registries import Registries

FEED_DEFAULT = "limbo.watch"  # --feed's default: the limbo feed, verified against its build attestation
NO_FEED = "none"  # --feed none: no feed; every dependency's source repo is read on GitHub instead
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class FeedSource:
    """Where the feed comes from: the limbo feed, or one built with `limbowatch publish --feed-only` and served from
    a URL or a directory (docs/OWN_FEED.md). Either way, `all.zip` and `watchlist.json` side by side."""

    base: str  # a URL ending in "/", or a local directory
    local: bool = False

    @property
    def limbo(self) -> bool:
        return self.base == LIMBO_BASE

    def _at(self, name: str) -> str:
        return str(Path(self.base) / name) if self.local else self.base + name

    @property
    def feed(self) -> str:
        return self._at("all.zip")

    @property
    def watchlist(self) -> str:
        return self._at("watchlist.json")

    @property
    def name(self) -> str:
        return "the limbo feed" if self.limbo else f"the feed at {self.base}"

    def cache(self, cache: Path | None) -> Path | None:
        """The limbo feed's cache is the cache directory itself, as before; another feed's is a folder of its own,
        so two feeds' files and verification records never mix."""
        if cache is None or self.limbo:
            return cache
        return cache / "feeds" / hashlib.sha256(self.base.encode()).hexdigest()[:16]


LIMBO_BASE = "https://limbo.watch/feed/"
LIMBO = FeedSource(LIMBO_BASE)
FEED_URL = LIMBO.feed
WATCHLIST_URL = LIMBO.watchlist


def feed_source(spec: str) -> FeedSource | None:
    """--feed: `limbo.watch`, `none` (None), an https URL of the folder that holds all.zip and watchlist.json (or of
    all.zip itself), or a local directory. Plain http only to this machine: anyone on the network could change a
    feed sent in the clear. ValueError says what's wrong."""
    if spec == FEED_DEFAULT:
        return LIMBO
    if spec == NO_FEED:
        return None
    if "://" not in spec:
        if not spec.strip():
            raise ValueError("--feed is empty")
        d = Path(spec).expanduser()
        return FeedSource(str((d.parent if d.name == "all.zip" else d).resolve()), local=True)
    try:
        parts = urlsplit(spec)
        host = parts.hostname or ""
    except ValueError as e:
        raise ValueError(f"--feed {spec!r} isn't a readable URL") from e
    if parts.scheme not in ("https", "http") or not host:
        raise ValueError(f"--feed wants an https:// URL or a directory, not {spec!r}")
    if parts.scheme == "http" and host not in LOOPBACK:
        raise ValueError(f"--feed {spec!r} is plain http: use https (http only to this machine)")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(f"--feed {spec!r}: no credentials, query or fragment in the URL")
    path = parts.path.removesuffix("all.zip")
    base = urlunsplit((parts.scheme, parts.netloc, path if path.endswith("/") else path + "/", "", ""))
    return LIMBO if base == LIMBO_BASE else FeedSource(base)


# Download caps (FINDINGS F-192): on 2026-11-14 the feed was 25 MB and the watchlist 3 MB.
FEED_MAX_BYTES = 500_000_000
WATCHLIST_MAX_BYTES = 100_000_000
VERIFY_MODES = ("auto", "require", "off")
MIX_RETRY_SECONDS = 5.0  # a pair from two builds is most likely a deploy in progress (F-196)
STALE_FEED = timedelta(days=3)  # the feed is rebuilt daily; older means it stopped updating, or was rolled back
# A tracker check older than this and the watcher checks the repo itself. The tracker re-checks quiet repos only
# every 30 days (and after releases, F-104), so a project's own dependencies get fresher checks here (F-071).
STALE = timedelta(days=10)


@dataclass
class ScanResult:
    inventory: Inventory
    findings: list[Finding] = field(default_factory=list)
    unresolved: list[UnresolvedDependency] = field(default_factory=list)  # the inventory's, plus partly checked
    upstreams: list[Upstream] = field(default_factory=list)  # with registry names resolved to repos and tags
    upstreams_checked: set[str] = field(default_factory=set)  # host/repo of upstream sources checked in full
    stats: dict[str, int] = field(default_factory=dict)
    unread: set[str] = field(default_factory=set)  # repos not polled (rate limit) or not read (an error) this run
    # With no feed (--feed none): the repos whose advisories were read this run. An earlier finding from any other
    # repo isn't known to be gone, so state keeps it. None: the feed covers the rest.
    read: set[str] | None = None


async def fetch(
    http: HttpClient, url: str, cache: Path | None, max_bytes: int = FEED_MAX_BYTES, stale: set[str] | None = None
) -> bytes:
    """Download `url`, reusing a cached copy while its ETag still matches. A response over `max_bytes` is refused.
    If the download fails and an older cached copy is used instead, `url` is added to `stale`."""
    body = etag = None
    if cache is not None:
        f, t = cache / Path(url).name, cache / (Path(url).name + ".etag")
        if f.exists() and t.exists():
            body, etag = f.read_bytes(), t.read_text().strip() or None
    try:
        r = await http.get(url, etag=etag, raw=True, max_bytes=max_bytes)
    except ResponseTooLarge as e:
        raise RuntimeError(f"{e}: far larger than the real feed, so it wasn't used") from e
    if r.status == 304 and body is not None:
        return body
    if not r.ok or not isinstance(r.body, bytes):
        if body is not None:
            if stale is not None:
                stale.add(url)
            return body  # stale but usable; the result says when the feed was generated
        raise RuntimeError(f"couldn't download {url}: HTTP {r.status}")
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        (cache / Path(url).name).write_bytes(r.body)
        (cache / (Path(url).name + ".etag")).write_text(r.etag or "")
    return r.body


async def load_feed(
    http: HttpClient,
    cache: Path | None,
    verify: str,
    warn: Callable[[str], None],
    now: datetime | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    source: FeedSource = LIMBO,
) -> tuple[bytes, dict[str, Any]]:
    """The feed's all.zip and watchlist, checked against their build attestation (`verify`: auto, require or off).
    GitHub must vouch for the two as files of the same build (FINDINGS F-192 to F-196).

    The two are handled as a pair: downloads are held in memory and written to the cache only once the pair passes,
    so the cache always holds a pair that went together. If a download fails, the cached pair stands in, both files,
    never one new file next to an old one.

    A mixed pair is what a scan sees during a deploy, for a moment, so it's downloaded again, fresh, after
    MIX_RETRY_SECONDS. If it's still mixed, a cached pair verified before is used, with a warning; otherwise it's
    refused. A pair GitHub doesn't vouch for is refused (RuntimeError) and the cache cleared. If GitHub can't be asked,
    `auto` warns and goes on, `require` refuses. A feed older than STALE_FEED is a warning in `auto` and refused in
    `require`: an old build's pair still verifies.

    Another `source` (a feed of your own, docs/OWN_FEED.md) has no attestation from this repository to check, so
    `verify` must be auto or off and only its age is checked; a directory is read as it is, without the cache."""
    if not source.limbo:
        if verify == "require":
            raise RuntimeError(f"--verify-feed require checks the limbo feed's attestation; {source.name} has none")
        verify = "off"
    if source.local:
        return _read_local(source, warn, now)
    cache = source.cache(cache)
    feed_url, wl_url = source.feed, source.watchlist
    files = ((feed_url, FEED_MAX_BYTES), (wl_url, WATCHLIST_MAX_BYTES))
    cached = {url: _cached(cache, url) for url, _ in files}
    got: dict[str, tuple[bytes, str | None, bool]] = {}
    result: feedtrust.Result | None = None
    for attempt in (1, 2):
        got = await _download_pair(http, files, cached, warn, conditional=attempt == 1)
        if verify == "off":
            break
        result = await feedtrust.verify(http, got[feed_url][0], got[wl_url][0], cache)
        if not (result.mixed and attempt == 1):
            break
        await sleep(MIX_RETRY_SECONDS)  # most likely mid-deploy: the other file is a moment away
    if result is not None and result.verdict is feedtrust.Verdict.REJECTED:
        old = cached[feed_url], cached[wl_url]
        if result.mixed and old[0] and old[1] and feedtrust.known_pair(cache, old[0][0], old[1][0]):
            warn("limbowatch: the limbo feed's files on limbo.watch come from different builds (it may be updating); "
                 "using the cached copy verified earlier")  # fmt: skip
            got = {u: (c[0], c[1], False) for u, c in cached.items() if c}
        else:
            if not result.mixed:
                for url, _ in files:
                    _forget(cache, url)
            raise RuntimeError(
                f"the limbo feed failed verification ({result.why}), so it wasn't used. "
                + ("It may be updating: try again in a few minutes. " if result.mixed else "")
                + "It may have been tampered with: SECURITY.md says how to report it. "
                "--verify-feed off skips this check."
            )
    if result is not None and result.verdict is feedtrust.Verdict.UNKNOWN:
        if verify == "require":
            raise RuntimeError(f"the limbo feed couldn't be verified ({result.why}); --verify-feed require")
        warn(f"limbowatch: couldn't verify the limbo feed ({result.why}); using it unverified")
    feed, watchlist = got[feed_url][0], got[wl_url][0]
    try:
        doc = json.loads(watchlist)
    except (ValueError, RecursionError) as e:
        for url, _ in files:
            _forget(cache, url)
        raise RuntimeError(f"{source.name}'s watchlist isn't readable JSON: {type(e).__name__}") from e
    doc = doc if isinstance(doc, dict) else {}
    _check_age(source, doc, verify, warn, now)
    for url, (body, etag, fresh) in got.items():
        if fresh:
            _store(cache, url, body, etag)
    return feed, doc


def _check_age(
    source: FeedSource, doc: dict[str, Any], verify: str, warn: Callable[[str], None], now: datetime | None
) -> None:
    generated = _parse_time(doc.get("generated_at"))
    if generated is not None and (now or datetime.now(UTC)) - generated > STALE_FEED:
        old_feed = (
            f"{source.name} is from {doc['generated_at']}, more than {STALE_FEED.days} days ago: newer advisories in "
            "limbo aren't in it"
        )
        if verify == "require":
            raise RuntimeError(f"{old_feed}; --verify-feed require")
        warn(f"limbowatch: {old_feed}")


def _read_local(source: FeedSource, warn: Callable[[str], None], now: datetime | None) -> tuple[bytes, dict[str, Any]]:
    """A feed in a directory: all.zip and watchlist.json, read with the download caps."""
    got = []
    for name, cap in ((source.feed, FEED_MAX_BYTES), (source.watchlist, WATCHLIST_MAX_BYTES)):
        f = Path(name)
        try:
            if f.stat().st_size > cap:
                raise RuntimeError(f"{f} is larger than {cap:,} bytes: far larger than a real feed, so it wasn't used")
            got.append(f.read_bytes())
        except OSError as e:
            raise RuntimeError(f"{source.name}: {f} can't be read ({type(e).__name__}); "
                               "`limbowatch publish --feed-only` writes it") from e  # fmt: skip
    try:
        doc = json.loads(got[1])
    except (ValueError, RecursionError) as e:
        raise RuntimeError(f"{source.name}'s watchlist isn't readable JSON: {type(e).__name__}") from e
    doc = doc if isinstance(doc, dict) else {}
    _check_age(source, doc, "off", warn, now)
    return got[0], doc


async def _download_pair(
    http: HttpClient,
    files: tuple[tuple[str, int], ...],
    cached: dict[str, tuple[bytes, str | None] | None],
    warn: Callable[[str], None],
    conditional: bool,
) -> dict[str, tuple[bytes, str | None, bool]]:
    """Both files, url -> (body, etag, downloaded now). If a download fails, the whole cached pair, or an error."""
    got: dict[str, tuple[bytes, str | None, bool]] = {}
    for url, cap in files:
        old = cached[url]
        try:
            r = await http.get(url, etag=old[1] if old and conditional else None, raw=True, max_bytes=cap)
        except ResponseTooLarge as e:
            raise RuntimeError(f"{e}: far larger than the real feed, so it wasn't used") from e
        if r.status == 304 and old is not None:
            got[url] = (old[0], old[1], False)
        elif r.ok and isinstance(r.body, bytes):
            got[url] = (r.body, r.etag, True)
        elif all(cached.values()):  # the last pair that went together, never a mix
            warn(f"limbowatch: couldn't download {url} (HTTP {r.status}); using the cached copy of the feed")
            return {u: (c[0], c[1], False) for u, c in cached.items() if c}
        else:
            raise RuntimeError(f"couldn't download {url}: HTTP {r.status}")
    return got


def _cached(cache: Path | None, url: str) -> tuple[bytes, str | None] | None:
    """The cached copy of `url` and its ETag, or None (best effort: an unreadable cache is no cache)."""
    if cache is None:
        return None
    f, t = cache / Path(url).name, cache / (Path(url).name + ".etag")
    try:
        if not (f.exists() and t.exists()):
            return None
        body, etag = f.read_bytes(), t.read_text(errors="replace").strip()
    except OSError:
        return None
    # a damaged ETag can't go in a header (httpx sends ASCII only): treat it as none, so the file is downloaded again
    return body, etag if etag and etag.isascii() and etag.isprintable() else None


def _store(cache: Path | None, url: str, body: bytes, etag: str | None) -> None:
    """Keep a verified download (best effort: a cache that can't be written costs a download next time)."""
    if cache is None:
        return
    with contextlib.suppress(OSError):
        cache.mkdir(parents=True, exist_ok=True)
        (cache / Path(url).name).write_bytes(body)
        (cache / (Path(url).name + ".etag")).write_text(etag or "")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        t = datetime.fromisoformat(value)
    except ValueError:
        return None
    return t if t.tzinfo is not None else None


def _forget(cache: Path | None, url: str) -> None:
    """Drop a cached file and its ETag (best effort), so a refused copy isn't reused on a 304."""
    if cache is None:
        return
    for p in (cache / Path(url).name, cache / (Path(url).name + ".etag")):
        with contextlib.suppress(OSError):
            p.unlink(missing_ok=True)


@dataclass
class Shared:
    """What every project in a run shares: the feed plus repos polled just now, and each dependency's source
    repo. Org-wide mode builds it once over all projects, so each upstream repo is mapped and polled once."""

    index: Index
    mapped: dict[tuple[str, str, str], mapping.Mapped] = field(default_factory=dict)
    on_watchlist: set[str] = field(default_factory=set)
    polled: set[str] = field(default_factory=set)
    not_polled: set[str] = field(default_factory=set)
    not_read: set[str] = field(default_factory=set)
    upstream_check: bool = True
    feedless: bool = False  # --feed none: only the repos polled now
    # each upstream source (submodule, CMake, Bazel, vcpkg, ...) → itself resolved, then what it pulls in
    upstreams: dict[Upstream, list[Upstream]] = field(default_factory=dict)
    checked: dict[Upstream, upcheck.Checked] = field(default_factory=dict)  # each resolved one's outcome


async def prepare(
    deps: list[Dependency],
    http: HttpClient,
    *,
    feed_zip: bytes | None,
    watchlist: dict[str, str],
    now: datetime,
    upstream_check: bool = True,
    upstreams: Sequence[Upstream] = (),
    git_cache: Path | None = None,
    osv_commits: bool = True,
) -> Shared:
    """`feed_zip` None (--feed none): no feed, so every dependency's source repo is polled, whatever the watchlist."""
    index = Index()
    if feed_zip is None:
        if not upstream_check:
            raise ValueError("with no feed, only the upstream check finds anything")
        watchlist = {}
    else:
        try:
            candidates = from_feed_zip(feed_zip)
        except (FeedTooLarge, FeedUnreadable, zipfile.BadZipFile) as e:  # a clean error (exit 2), not a traceback
            raise RuntimeError(f"the feed couldn't be read: {e}") from e
        for c in candidates:
            index.add(c)
    sh = Shared(index, upstream_check=upstream_check, feedless=feed_zip is None)
    if upstream_check:
        sh.upstreams = await Registries(http).resolve(upstreams)
        sh.mapped = await mapping.map_all(http, deps)
        sources = [r for rs in sh.upstreams.values() for r in rs]
        repos = {m.repo for m in sh.mapped.values() if m.repo}
        repos |= {u.repo for u in sources if u.host == "github.com" and u.repo}
        due = {r for r in repos if not _fresh(watchlist.get(r), now)}
        polled = await upstream.poll(http, due)
        for c in polled.candidates:
            index.add(c)
        sh.on_watchlist, sh.polled, sh.not_polled = repos - due, polled.polled, polled.not_polled
        sh.not_read = polled.not_read
        sh.checked = await upcheck.check(http, sources, index, not_polled=sh.not_polled, not_read=sh.not_read,
                                         git_cache=git_cache,
                                         osv_commits=osv_commits, aliases=polled.aliases)  # fmt: skip
    return sh


def assess(inv: Inventory, sh: Shared) -> ScanResult:
    """One project's findings against the shared feed, polls and mappings. No I/O."""
    res = ScanResult(inventory=inv, unresolved=list(inv.unresolved), unread=sh.not_polled | sh.not_read,
                     read=set(sh.polled) if sh.feedless else None)  # fmt: skip
    no_repo, not_polled, not_read = (
        (Unchecked.NO_REPO_NO_FEED, Unchecked.REPO_NOT_POLLED_NO_FEED, Unchecked.REPO_NOT_READ_NO_FEED)
        if sh.feedless
        else (Unchecked.NO_REPO, Unchecked.REPO_NOT_POLLED, Unchecked.REPO_NOT_READ)
    )
    deps = list(inv.dependencies)
    keys = {(d.ecosystem, d.name, d.version) for d in deps}
    mapped = {k: m for k, m in sh.mapped.items() if k in keys}
    if sh.upstream_check:
        repos = {m.repo for m in mapped.values() if m.repo}
        res.stats |= {
            "repos": len(repos),
            "repos_on_watchlist": len(repos & sh.on_watchlist),
            "repos_polled": len(repos & sh.polled),
        }
        for d in deps:
            m = mapped[(d.ecosystem, d.name, d.version)]
            if m.repo is None:
                res.unresolved.append(_partial(d, no_repo, m.method))
            elif m.repo in sh.not_polled:
                res.unresolved.append(_partial(d, not_polled, m.repo))
            elif m.repo in sh.not_read:
                res.unresolved.append(_partial(d, not_read, m.repo))
    index = sh.index
    go = [c for cs in index.by_repo.values() for c in cs if any(p.ecosystem == "go" for p in c.adv.packages)]
    per_repo: dict[str, set[tuple[str, str]]] = {}
    for (eco, name, _), m in mapped.items():
        if m.repo:
            per_repo.setdefault(m.repo, set()).add((eco, name))
    for d in deps:
        found = mapped.get((d.ecosystem, d.name, d.version))
        repo = found.repo if found else None
        n_pkgs = len(per_repo.get(repo, ())) if repo else 1
        res.findings += match(d, index, repo, go if d.ecosystem == "go" else None, n_pkgs)
    res.findings.sort(key=lambda f: (f.dependency.source, f.dependency.line, f.dependency.name, f.ghsa_id))
    seen: set[tuple[object, ...]] = set()
    for u in inv.upstreams:
        for r in sh.upstreams.get(u, [u]):
            # whole declarations, so two sources with one name in two files are both kept (F-141); a vcpkg port
            # pulled in by several ports is one dependency of the manifest (F-142)
            transitive = r.kind is UpstreamKind.VCPKG and "a dependency of" in r.via
            k = (r.kind.value, r.name, r.host, r.repo, r.ref, r.version, r.url, r.source,
                 None if transitive else r.line)  # fmt: skip
            if k not in seen:
                seen.add(k)
                res.upstreams.append(r)
                if not sh.upstream_check:
                    res.unresolved.append(upstream_unchecked(r, checking=False))
                    continue
                done = sh.checked.get(r) or upcheck.Checked(unchecked=upstream_unchecked(r))
                res.findings += done.findings
                if done.unchecked is not None:
                    res.unresolved.append(done.unchecked)
                elif r.repo:
                    res.upstreams_checked.add(f"{r.host}/{r.repo}")
    res.findings.sort(key=lambda f: (f.dependency.source, f.dependency.line, f.dependency.name, f.ghsa_id))
    res.stats |= {"dependencies": len(deps), "feed_advisories": len(index.ids), "findings": len(res.findings),
                  "upstreams": len(res.upstreams)}  # fmt: skip
    return res


def upstream_unchecked(u: Upstream, checking: bool = True) -> UnresolvedDependency:
    """An upstream source not checked: with `--no-upstream` (`checking` False), or because its repo or its version is
    unknown. Says how far it got."""
    where = f"{u.host}/{u.repo}" if u.repo else ""
    pin = u.ref or (f"version {u.version}" if u.version else "")
    known = f"{where} at {pin}" if where and pin else where
    if not checking:
        reason, detail = Unchecked.UPSTREAM_NO_CHECK, known or pin or u.detail
    elif u.repo is None:
        reason, detail = Unchecked.UPSTREAM_UNKNOWN, u.detail
    elif not u.ref:
        reason, detail = Unchecked.UPSTREAM_NO_REF, "; ".join(x for x in (known, u.detail) if x)
    else:
        reason, detail = Unchecked.UPSTREAM_NO_CHECK, known
    if u.via:
        detail = f"{detail} ({u.via})" if detail else u.via
    return UnresolvedDependency(reason=reason, source=u.source, name=u.name, version=u.ref or u.version or "",
                                ecosystem=u.kind.value, detail=detail, line=u.line)  # fmt: skip


async def scan(
    inv: Inventory,
    http: HttpClient,
    *,
    feed_zip: bytes | None,
    watchlist: dict[str, str],
    now: datetime,
    upstream_check: bool = True,
    git_cache: Path | None = None,
    osv_commits: bool = True,
) -> ScanResult:
    sh = await prepare(list(inv.dependencies), http, feed_zip=feed_zip, watchlist=watchlist, now=now,
                       upstream_check=upstream_check, upstreams=inv.upstreams, git_cache=git_cache,
                       osv_commits=osv_commits)  # fmt: skip
    return assess(inv, sh)


def _fresh(last: str | None, now: datetime) -> bool:
    if not last:
        return False
    return now - datetime.fromisoformat(last.replace("Z", "+00:00")) < STALE


def _partial(d: Dependency, reason: Unchecked, detail: str) -> UnresolvedDependency:
    return UnresolvedDependency(reason=reason, source=d.source, name=d.name, version=d.version, ecosystem=d.ecosystem,
                                detail=detail, line=d.line)  # fmt: skip


def watchlist_repos(data: bytes) -> dict[str, str]:
    return dict(json.loads(data).get("repos") or {})
