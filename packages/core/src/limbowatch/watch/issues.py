"""Issue lifecycle: one issue per finding key, opened once, commented on as the advisory moves (SPEC).

- **New finding:** open an issue (confidential on GitLab). Never on a public tracker unless allowed.
- **Changed** (CVE assigned or published, severity, versions): comment.
- **Now visible to scanners** (the advisory reached OSV) while still affected: comment and label once;
  the issue stays open, because the project is still affected.
- **No longer affected** (upgraded, removed, or the advisory withdrawn): comment and close.
- **Found again** after closing: reopen.

`plan` is pure; `apply` performs it. Issue bodies carry facts and links only, no advisory text (F-059).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from limbowatch.versions import affected
from limbowatch.watch.output import ATTRIBUTION, SEVERITIES
from limbowatch.watch.state import Change, ChangeKind
from limbowatch.watch.trackers import LABEL, Issue, Tracker, marker

VISIBLE_LABEL = "limbowatch:visible"
POSSIBLE_LABEL = "limbowatch:possible"
VISIBLE_NOTE = (
    "This advisory is now in OSV, so scanners that read it (OSV-Scanner, and Dependabot once GitHub has "
    "reviewed it) report it from now on. The installed version is still affected, so this issue stays open "
    "until you upgrade."
)
FIXED_NOTE = (
    "No longer affected: the dependency was upgraded past the affected range or removed, or the advisory was "
    "withdrawn. Closing."
)


class Gone(StrEnum):
    """What happened to an open issue's finding that isn't found any more."""

    VISIBLE = "visible"  # in OSV now, and the installed version is still affected
    FIXED = "fixed"  # not affected any more (or the advisory is gone)


@dataclass
class Policy:
    min_severity: str = "low"  # open issues for findings at or above this; unscored findings always count
    allow_public: bool = False  # open issues where anyone can read them (public Gitea repos)


@dataclass
class Action:
    kind: str  # create, comment, close, reopen, label
    key: str
    title: str = ""
    body: str = ""
    labels: list[str] = field(default_factory=list)
    issue: Issue | None = None


def title(e: dict[str, Any]) -> str:
    sev = e.get("severity") or "unknown severity"
    return f"[limbo] {e['ghsa_id']}: {e['ecosystem']} {e['package']} {', '.join(e['versions'])} ({sev})"


def body(e: dict[str, Any], f: dict[str, Any]) -> str:
    """`e`: the state entry; `f`: one of its findings (as JSON), for range, fix and evidence."""
    cves = ", ".join(e.get("cves") or [])
    fix = f.get("fixed") or "not stated"
    rows = [
        ("Severity", e.get("severity") or "unknown"),
        ("CVE", e["cve"] + (f" ({cves})" if cves else "")),
        ("Affected versions", f"`{f.get('vulnerable_range') or 'not stated'}`"),
        ("Fixed in", f"`{fix}`"),
        ("Found in", ", ".join(f"`{loc}`" for loc in e["locations"])),
        ("Match", f.get("match", "")),
    ]
    certain = e.get("affected") is True
    lines = [
        f"**{e['ecosystem']} `{e['package']}` {', '.join(e['versions'])}** is "
        f"{'affected' if certain else 'possibly affected'} by [{e['ghsa_id']}]({e['url']}), a security advisory its "
        "maintainers published on GitHub that isn't in GitHub's reviewed Advisory Database or OSV yet. "
        "Scanners that read those databases don't report it.",
        "",
        "| | |",
        "|---|---|",
        *(f"| {k} | {v} |" for k, v in rows),
        "",
    ]
    if not certain and f.get("evidence"):
        lines += [f"Why only possibly: {f['evidence']}.", ""]
    todo = (
        f"**What to do:** read the advisory, then upgrade to a fixed version ({fix})."
        if f.get("fixed")
        else "**What to do:** read the advisory; it names no fixed version yet."
    )
    lines += [
        todo,
        "",
        "Limbowatch comments here when a CVE is assigned or the advisory reaches scanners, "
        "and closes this issue when the project is no longer affected.",
        "",
        f"_{ATTRIBUTION}_",
        "",
        marker(
            {
                "key": e["key"],
                "ghsa_id": e["ghsa_id"],
                "ecosystem": e["ecosystem"],
                "package": e["package"],
                "range": f.get("vulnerable_range"),
                "fixed": f.get("fixed"),
            }
        ),
    ]
    return "\n".join(lines)


def _wanted(e: dict[str, Any], p: Policy) -> bool:
    sev = (e.get("severity") or "").lower()
    return sev not in SEVERITIES or SEVERITIES.index(sev) <= SEVERITIES.index(p.min_severity)


def plan(
    current: dict[str, dict[str, Any]],
    findings: dict[str, dict[str, Any]],
    existing: dict[str, Issue],
    changes: list[Change],
    gone: dict[str, Gone],
    policy: Policy,
    public: bool,
) -> list[Action]:
    """`current`: state entries by key; `findings`: one finding (JSON) per key; `gone`: open issues whose
    finding isn't found now, with what happened to it."""
    acts: list[Action] = []
    changed = {c.key: c for c in changes if c.kind is ChangeKind.CHANGED}
    for key, e in sorted(current.items()):
        e = e | {"key": key}
        issue = existing.get(key)
        labels = [LABEL, "security", f"severity:{e.get('severity') or 'unknown'}"]
        if e.get("affected") is not True:
            labels.append(POSSIBLE_LABEL)
        if issue is None:
            if _wanted(e, policy) and (policy.allow_public or not public):
                acts.append(Action("create", key, title(e), body(e, findings[key]), labels))
        elif not issue.open:
            acts.append(Action("reopen", key, body=f"Found again in {', '.join(e['locations'])}.", issue=issue))
        elif key in changed:
            acts.append(Action("comment", key, body="Changed: " + "; ".join(changed[key].details) + ".", issue=issue))
    for key, what in sorted(gone.items()):
        issue = existing[key]
        if what is Gone.VISIBLE:
            if VISIBLE_LABEL not in issue.labels:
                acts.append(
                    Action(
                        "label",
                        key,
                        labels=[VISIBLE_LABEL],
                        issue=issue,
                        body=VISIBLE_NOTE,
                    )
                )
        else:
            acts.append(
                Action(
                    "close",
                    key,
                    issue=issue,
                    body=FIXED_NOTE,
                )
            )
    return acts


async def apply(tracker: Tracker, actions: list[Action]) -> list[str]:
    """Perform the plan; returns one line per action, for the log."""
    done = []
    for a in actions:
        if a.kind == "create":
            i = await tracker.create(a.title, a.body, a.labels)
            done.append(f"opened #{i.number}: {a.title}")
            continue
        assert a.issue is not None
        if a.kind == "reopen":
            await tracker.set_open(a.issue, True)
            await tracker.comment(a.issue, a.body)
        elif a.kind == "comment":
            await tracker.comment(a.issue, a.body)
        elif a.kind == "label":
            await tracker.comment(a.issue, a.body)
            await tracker.add_labels(a.issue, a.labels)
        elif a.kind == "close":
            await tracker.comment(a.issue, a.body)
            await tracker.set_open(a.issue, False)
        done.append(f"{a.kind} #{a.issue.number}")
    return done


def still_affected(meta: dict[str, Any], versions: list[str], osv_ids: list[set[str] | None]) -> bool | None:
    """Is any installed version still affected? From OSV when it has the advisory (`osv_ids` per version),
    else from the range recorded in the issue. None when it can't be told."""
    ghsa = meta.get("ghsa_id")
    if any(ids is not None and ghsa in ids for ids in osv_ids):
        return True
    if osv_ids and all(ids is not None for ids in osv_ids):
        return False
    verdicts = [affected(meta.get("ecosystem", ""), v, meta.get("range")) for v in versions]
    if any(v is True for v in verdicts):
        return True
    return False if verdicts and all(v is False for v in verdicts) else None
