"""What the watcher saw last time, and what changed since (`scan --state`). Pure: no I/O.

Findings are keyed by ecosystem, package and advisory (`match.key`), so an upgrade that stays in the
affected range keeps the same finding (and the same issue). A finding that disappears is either
**visible**: the advisory reached OSV, so the project's usual scanner reports it now; or **fixed**:
the project no longer has an affected version (upgraded or removed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from limbowatch.models import Finding

STATE_VERSION = 1


class ChangeKind(StrEnum):
    NEW = "new"
    CHANGED = "changed"
    VISIBLE = "now visible to scanners"
    FIXED = "no longer affected"


@dataclass
class Change:
    key: str
    kind: ChangeKind
    ghsa_id: str
    package: str  # "ecosystem:name"
    details: list[str] = field(default_factory=list)
    entry: dict[str, Any] = field(default_factory=dict)  # the state entry (current, or the last one seen)


def entries(findings: list[Finding], now: str, old: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """One state entry per finding key, merging the lockfiles and versions it was found in."""
    prev = (old or {}).get("findings", {})
    out: dict[str, dict[str, Any]] = {}
    for f in findings:
        e = out.setdefault(
            f.key,
            {
                "ghsa_id": f.ghsa_id,
                "url": f.url,
                "repo": f.repo,  # the advisory's repo: kept as it was while that repo can't be read (`diff`)
                "ecosystem": f.dependency.ecosystem,
                "package": f.dependency.name,
                "severity": f.severity,
                "cve": f.cve.value,
                "cves": sorted(f.cves),
                "affected": f.affected,
                "versions": [],
                "locations": [],
                "first_seen": prev.get(f.key, {}).get("first_seen", now),
                "last_seen": now,
            },
        )
        if f.dependency.version not in e["versions"]:
            e["versions"].append(f.dependency.version)
        loc = f"{f.dependency.source}:{f.dependency.line}"
        if loc not in e["locations"]:
            e["locations"].append(loc)
        if f.affected is True:
            e["affected"] = True  # certain anywhere beats possible elsewhere
    for e in out.values():
        e["versions"].sort()
        e["locations"].sort()
    return out


def _unseen(old: dict[str, Any] | None, findings: list[Finding], unread: set[str]) -> dict[str, dict[str, Any]]:
    """Old findings not found now, except those whose advisory's repo couldn't be read or polled this run: those
    aren't known to be gone (an entry from before entries named their repo is taken as gone, as it always was)."""
    cur = {f.key for f in findings}
    prev: dict[str, dict[str, Any]] = (old or {}).get("findings", {})
    return {k: p for k, p in prev.items() if k not in cur and p.get("repo") not in unread}


def diff(
    old: dict[str, Any] | None, findings: list[Finding], now: str, visible: set[str], unread: set[str] | None = None
) -> tuple[dict[str, Any], list[Change]]:
    """The new state, and what changed. `visible`: advisory IDs of vanished findings that are in OSV now.
    `unread`: repos whose advisories couldn't be read or polled this run; their old findings are kept unchanged."""
    cur = entries(findings, now, old)
    prev: dict[str, dict[str, Any]] = (old or {}).get("findings", {})
    gone = _unseen(old, findings, unread or set())
    changes: list[Change] = []
    for key, e in cur.items():
        pkg = f"{e['ecosystem']}:{e['package']}"
        p = prev.get(key)
        if p is None:
            changes.append(Change(key, ChangeKind.NEW, e["ghsa_id"], pkg, entry=e))
            continue
        details = []
        if p.get("cve") != e["cve"] or p.get("cves") != e["cves"]:
            cves = ", ".join(e["cves"])
            details.append(f"CVE: {e['cve']}" + (f" ({cves})" if cves else ""))
        if p.get("severity") != e["severity"]:
            details.append(f"severity: {p.get('severity') or 'unknown'} → {e['severity'] or 'unknown'}")
        if p.get("affected") != e["affected"]:
            details.append("now certainly affected" if e["affected"] else "now only possibly affected")
        if p.get("versions") != e["versions"]:
            details.append(f"versions: {', '.join(p.get('versions', []))} → {', '.join(e['versions'])}")
        if details:
            changes.append(Change(key, ChangeKind.CHANGED, e["ghsa_id"], pkg, details, e))
    for key, p in prev.items():
        if key in cur:
            continue
        if key in gone:
            kind = ChangeKind.VISIBLE if p["ghsa_id"] in visible else ChangeKind.FIXED
            changes.append(Change(key, kind, p["ghsa_id"], f"{p['ecosystem']}:{p['package']}", entry=p))
        else:
            cur[key] = p  # not seen because its repo wasn't read: neither fixed nor visible, kept as it was
    state = {"version": STATE_VERSION, "scanned_at": now, "findings": cur}
    return state, sorted(changes, key=lambda c: (list(ChangeKind).index(c.kind), c.ghsa_id, c.package))


def vanished(old: dict[str, Any] | None, findings: list[Finding], unread: set[str] | None = None) -> set[str]:
    """Advisory IDs of findings in the old state that aren't found now (to check against OSV)."""
    return {p["ghsa_id"] for p in _unseen(old, findings, unread or set()).values()}
