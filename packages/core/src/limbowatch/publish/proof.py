"""What `limbowatch scan` reports for the proof repository's pinned packages, for the home page (FINDINGS F-201).

Pure: the feed's records go through the watcher's own matching (`watch.match`), so the number is what a scan of the
proof repository finds with the same feed, and the site needs no network to show it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

from limbowatch.ecosystems import by_osv
from limbowatch.models import Dependency
from limbowatch.versions import no_fix
from limbowatch.watch.candidates import Index, from_feed_record
from limbowatch.watch.match import match

PINS: list[dict[str, str]] = json.loads(files("limbowatch.publish").joinpath("proof.json").read_text())["pins"]
SERIOUS = ("critical", "high")


@dataclass(frozen=True)
class Proof:
    ids: frozenset[str]  # advisories in limbo that certainly affect a pinned version and name a fixed version
    serious: frozenset[str]  # the critical and high ones
    packages: int  # pinned packages with at least one

    @property
    def total(self) -> int:
        return len(self.ids)


def counts(records: Iterable[Mapping[str, Any]], pins: Sequence[Mapping[str, str]] = PINS) -> Proof:
    """Certain findings only: a "possibly affected" one (a range that can't be read, another Go major version) isn't
    counted, nor one without a fixed version."""
    index = Index()
    for r in records:
        index.add(from_feed_record(dict(r)))
    go = [c for cs in index.by_repo.values() for c in cs if any(p.ecosystem == "go" for p in c.adv.packages)]
    severity: dict[str, str] = {}
    hit: set[str] = set()
    for pin in pins:
        e = by_osv(pin["ecosystem"])
        if e is None:
            raise ValueError(f"unknown ecosystem: {pin['ecosystem']!r}")
        version = pin["version"].removeprefix("v") if e.ghsa == "go" else pin["version"]
        dep = Dependency(ecosystem=e.ghsa, name=pin["name"], version=version, source=pin["file"])
        for f in match(dep, index, pin["repo"].lower(), go if e.ghsa == "go" else None):
            if f.affected is True and not no_fix(f.fixed):
                severity[f.ghsa_id] = (f.severity or "").lower()
                hit.add(pin["name"])
    return Proof(
        ids=frozenset(severity),
        serious=frozenset(g for g, s in severity.items() if s in SERIOUS),
        packages=len(hit),
    )
