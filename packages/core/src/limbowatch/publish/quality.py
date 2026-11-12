"""Advisory fields scanners can't use, with the edit that would fix each (FINDINGS F-069).

Scanners compare package names exactly and skip affected ranges they can't read, so these
advisories stay invisible even after they reach a database. Only fields of packages in OSV
ecosystems are checked: those are the ones a scanner could match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from limbowatch.ecosystems import info, package_name
from limbowatch.models import Status
from limbowatch.publish import Item
from limbowatch.versions import alternatives, fixed_versions, no_fix, osv_ranges, per_line_bounds

_VER = r"v?\d[\w+-]*(?:\.[\w+-]+)*"  # a version with single dots, so "1.0..2.0" splits at ".."

NAME = "package name"
RANGE = "affected versions"

# What a valid name looks like, per GHSA ecosystem.
NAME_HINTS = {
    "npm": "the package name on npmjs.com, e.g. `lodash` or `@scope/name`",
    "pip": "the project name on PyPI, e.g. `requests`",
    "go": "the module path from go.mod, e.g. `github.com/owner/repo` or `github.com/owner/repo/v2`",
    "rust": "the crate name on crates.io",
    "maven": "`groupId:artifactId`, e.g. `org.example:library`",
    "nuget": "the package ID on nuget.org",
    "composer": "`vendor/package` as on Packagist, in lower case",
    "rubygems": "the gem name on rubygems.org",
    "erlang": "the package name on hex.pm",
    "actions": "the action's `owner/repo`",
    "pub": "the package name on pub.dev",
    "swift": "the package's Git URL without the scheme, e.g. `github.com/owner/repo`",
}


@dataclass(frozen=True)
class Problem:
    ghsa_id: str
    repo: str
    ecosystem: str  # OSV name
    field: str  # NAME or RANGE
    as_entered: str
    issue: str
    fix: str
    certain: bool  # the fix is mechanical (only for cleaned names)


def problems(items: list[Item]) -> list[Problem]:
    out: list[Problem] = []
    for it in items:
        if it.assessment.status is not Status.LIMBO:
            continue
        for p in it.adv.packages:
            eco = info(p.ecosystem)
            name = package_name(p.ecosystem, p.name)
            if eco.osv is None or name is None:
                continue
            base = (it.adv.ghsa_id, it.adv.repo, eco.osv)
            if not name.valid:
                hint = NAME_HINTS.get(p.ecosystem, "the package's name in its registry")
                out.append(Problem(*base, NAME, name.raw, f"Not a valid {eco.osv} package name", f"Use {hint}.", False))
            elif name.cleaned:
                fix = f"Change it to `{name.name}`."
                out.append(Problem(*base, NAME, name.raw, "Scanners compare names exactly", fix, True))
            if osv_ranges(p.ecosystem, p.vulnerable_version_range, p.patched_versions) is None:
                issue, fix = range_problem(p.ecosystem, p.vulnerable_version_range, p.patched_versions)
                out.append(Problem(*base, RANGE, p.vulnerable_version_range or "", issue, fix, False))
    return out


def range_problem(ghsa_ecosystem: str, rng: str | None, patched: str | None) -> tuple[str, str]:
    """Why a range can't be converted to OSV, and how to write it instead. Mirrors `osv_ranges`."""
    fixes = fixed_versions(patched) or []
    one_fix = fixes[0] if len(fixes) == 1 else None
    if not (rng or "").strip():
        return "No affected versions given", (
            f"Enter the range, e.g. `< {one_fix}`." if one_fix else "Enter the range, e.g. `< 1.2.3`."
        )
    assert rng is not None
    alts = alternatives(ghsa_ecosystem, rng)
    if alts is None:
        if m := re.search(rf"({_VER})\s*\.\.=?\s*({_VER})", rng):
            a, b = m.groups()
            return "Written as `A .. B`, which tools read differently", (
                f"Write `>= {a}, < {b}` if {b} is fixed, or `>= {a}, <= {b}` if {b} is affected."
            )
        return "Not a range scanners can read", (
            "Use constraints such as `>= 1.0.0, < 1.2.3`, one range per release line. "
            "If every version is affected and there's no fix yet, `>= 0`."
        )
    if per_line_bounds(ghsa_ecosystem, rng):  # read one per line, but the fixed versions don't confirm it (F-159)
        lines = " and ".join("`" + ", ".join(f"{op} {v}" for op, v in cons) + "`" for cons in alts)
        return "Several upper bounds in one range", (
            f"Add the package once per release line, each with its own range: {lines}, if those are your release "
            "lines, with each line's first fixed version in the fixed field."
        )
    for cons in alts:
        ops = [op for op, _ in cons]
        if ops == ["="]:
            continue
        if ">" in ops:
            return "Uses `>`, an exclusive lower bound OSV can't express", "Use `>=` with the first affected version."
        if "!=" in ops:
            return "Uses `!=`", "List the affected ranges instead of the exceptions."
        if "=" in ops:
            return "Mixes exact versions with bounds", "Give exact versions and ranges as separate entries."
        lows = [v for op, v in cons if op == ">="]
        highs = [v for op, v in cons if op in ("<", "<=")]
        if len(lows) > 1 or len(highs) > 1:
            side = "upper" if len(highs) > 1 else "lower"
            return f"Several {side} bounds in one range", (
                "Add the package once per release line, each with its own range, e.g. `>= 2.0.0, < 2.0.3`."
            )
        if not highs and not no_fix(patched):
            if len(fixes) > 1:
                return "No upper bound, and the fixed field lists several versions", (
                    "Add the package once per release line, each with `>= start, < fix`."
                )
            if one_fix:
                return f"No upper bound, and the fixed version ({one_fix}) doesn't close the range", (
                    "Check both fields: the fix should be inside the range's release line, "
                    f"and the range can end at it (`< {one_fix}`)."
                )
            return f"No upper bound, and the fixed field (“{patched}”) isn't a version", (
                "Put the first fixed version in the fixed field, or end the range with `< fix`."
            )
    return "Can't be converted exactly", "Use constraints such as `>= 1.0.0, < 1.2.3`, one range per release line."
