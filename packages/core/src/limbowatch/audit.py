"""A record of every network call a run makes (`--audit-log`, `--show-network`).

Whoever runs Limbowatch can see each host and URL it contacted, compare them with docs/WATCHER.md's Security and
data, and keep the record, without putting a logging proxy in front of it.

There are four ways out, and each is recorded where it starts:
- HTTP, in `limbowatch.http`: every attempt, retry and redirect hop, with its status or its error.
- git clones and fetches: of upstream repositories (`limbowatch.watch.gitgraph`), and of projects
  (`limbowatch.hosts.git`).
- `git ls-remote` (`limbowatch.sources.gitrefs`).
- OSV-Scanner's own pom.xml resolution (`limbowatch.inventory.osv_scanner`). Only OSV-Scanner sees those URLs, so
  that run is recorded with the hosts it can contact (FINDINGS F-132).

No secret is recorded. A URL's user name and password, and any query value whose name looks like a credential,
become "***". Of the request headers, only the name of one that carries a credential is kept.
"""

from __future__ import annotations

import json
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import IO, Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

Entry = dict[str, Any]
Sink = Callable[[Entry], None]

# OSV-Scanner's pom.xml resolver contacts these (docs/WATCHER.md#security-and-data, F-132)
MAVEN_RESOLVER_HOSTS = ("api.deps.dev", "repo.maven.apache.org", "repo1.maven.org")
CREDENTIAL_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "private-token", "job-token", "apikey", "x-api-key", "cookie"}
)
_SECRET_PARAMS = ("token", "key", "secret", "password", "passwd", "signature", "sig", "auth", "credential")

_lock = threading.Lock()  # git clones run in threads
_sinks: list[Sink] = []
_hosts: Counter[str] = Counter()
_via_osv_scanner: set[str] = set()


def active() -> bool:
    return bool(_sinks)


def redact(url: str) -> str:
    """The URL without a user name or password, and with credential-like query values as "***"."""
    try:
        p = urlsplit(url)
    except ValueError:
        return "(unreadable URL)"
    netloc = p.netloc
    if "@" in netloc:
        netloc = "***@" + netloc.rsplit("@", 1)[1]
    query = p.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        query = urlencode([(k, "***" if any(s in k.lower() for s in _SECRET_PARAMS) else v) for k, v in pairs])
    return urlunsplit((p.scheme, netloc, p.path, query, p.fragment))


def host_of(url: str) -> str:
    try:
        p = urlsplit(url)
    except ValueError:
        return ""
    return p.hostname or ("local" if p.scheme == "file" or not p.scheme else "")


def http(
    method: str,
    url: str,
    *,
    status: int | None = None,
    error: str | None = None,
    ms: float | None = None,
    credential: str | None = None,
    sent_bytes: int | None = None,
) -> None:
    """One HTTP request: its status, or the error that stopped it."""
    if _sinks:
        _emit("http", method=method.upper(), url=redact(url), host=host_of(url), status=status, error=error,
              ms=_ms(ms), credential=credential, sent_bytes=sent_bytes or None)  # fmt: skip


def git(op: str, url: str, *, exit_code: int | None = None, error: str | None = None, ms: float | None = None,
        credential: str | None = None) -> None:  # fmt: skip
    """One git command that talks to a remote: clone, fetch or ls-remote."""
    if _sinks:
        _emit("git", op=op, url=redact(url), host=host_of(url), exit=exit_code, error=error, ms=_ms(ms),
              credential=credential)  # fmt: skip


def osv_scanner(op: str, hosts: tuple[str, ...], *, exit_code: int | None = None, error: str | None = None,
                ms: float | None = None) -> None:  # fmt: skip
    """An OSV-Scanner run that goes online. Its URLs aren't visible here, only the hosts it can contact."""
    if _sinks:
        _emit("osv-scanner", op=op, hosts=list(hosts), exit=exit_code, error=error, ms=_ms(ms),
              note="requests made by OSV-Scanner itself; their URLs aren't visible to Limbowatch")  # fmt: skip


def summary() -> Entry:
    """Calls so far, by host."""
    with _lock:
        return _summary()


@contextmanager
def recording(*sinks: Sink, command: str = "") -> Iterator[None]:
    """Send every network call to `sinks` until the block ends, then a summary. One recording at a time."""
    from limbowatch import __version__

    with _lock:
        _sinks[:] = sinks
        _hosts.clear()
        _via_osv_scanner.clear()
    _emit("run", version=__version__, command=command or None)
    try:
        yield
    finally:
        with _lock:
            entry = _stamp("summary", _summary())
            try:
                for sink in _sinks:
                    sink(entry)
            finally:
                _sinks.clear()


class JsonLines:
    """Each entry as one JSON object per line, written out at once, so a run that crashes still leaves its record."""

    def __init__(self, stream: IO[str]) -> None:
        self.stream = stream

    def __call__(self, entry: Entry) -> None:
        self.stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self.stream.flush()


class Readable:
    """Each call as one line for a person (`--show-network`), and the hosts at the end."""

    def __init__(self, write: Callable[[str], None]) -> None:
        self.write = write

    def __call__(self, entry: Entry) -> None:
        if line := describe(entry):
            self.write(f"limbowatch: network: {line}")


def describe(e: Entry) -> str | None:
    kind = e["kind"]
    took = f"{e['ms'] / 1000:.1f} s" if e.get("ms", 0) >= 1000 else f"{e['ms']:g} ms" if "ms" in e else ""
    extra = ", ".join(x for x in (took, f"sent {e['credential']}" if e.get("credential") else "") if x)
    tail = f" ({extra})" if extra else ""
    if kind == "http":
        outcome = str(e["status"]) if "status" in e else e.get("error", "no response")
        return f"{e['method']} {e['url']} -> {outcome}{tail}"
    if kind == "git":
        outcome = e["error"] if "error" in e else f"exit {e.get('exit')}"
        return f"git {e['op']} {e['url']} -> {outcome}{tail}"
    if kind == "osv-scanner":
        outcome = e["error"] if "error" in e else f"exit {e.get('exit')}"
        return f"osv-scanner {e['op']}, which can contact {', '.join(e['hosts'])} -> {outcome}{tail}"
    if kind == "summary":
        if not e["calls"] and not e.get("via_osv_scanner"):
            return "no network calls"
        hosts = ", ".join(f"{h} ({n})" for h, n in e["hosts"].items())
        line = f"{e['calls']} call{'s' * (e['calls'] != 1)}" + (f" to {hosts}" if hosts else "")
        if via := e.get("via_osv_scanner"):
            line += f"; OSV-Scanner could contact {', '.join(via)}"
        return line
    return None


def _ms(ms: float | None) -> float | None:
    return None if ms is None else round(ms, 1)


def _stamp(kind: str, fields: Entry) -> Entry:
    now = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {"time": now, "kind": kind, **{k: v for k, v in fields.items() if v is not None}}


def _emit(kind: str, **fields: Any) -> None:
    entry = _stamp(kind, fields)
    with _lock:
        if kind in ("http", "git"):
            _hosts[entry.get("host") or "(unknown)"] += 1
        elif kind == "osv-scanner":
            _via_osv_scanner.update(entry["hosts"])
        for sink in _sinks:
            sink(entry)


def _summary() -> Entry:
    return {"calls": sum(_hosts.values()), "hosts": dict(sorted(_hosts.items(), key=lambda kv: (-kv[1], kv[0]))),
            "via_osv_scanner": sorted(_via_osv_scanner) or None}  # fmt: skip
