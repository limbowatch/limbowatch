"""Version-range handling for maintainer-entered advisory ranges. Pure: no I/O.

Maintainers type ranges by hand, so beyond canonical GHSA syntax ('>= 1.0, < 1.2.3') this accepts
npm style, hyphen ranges, '||' / ';' alternatives, Unicode comparison signs, common typos and a
few English forms (FINDINGS F-030, F-044). Anything else is unparseable and reported as such,
never guessed. Versions are compared with ecosystem comparators, never as strings.
"""

from __future__ import annotations

import re
from typing import Any

from univers.versions import (
    ComposerVersion,
    GolangVersion,
    MavenVersion,
    NugetVersion,
    PypiVersion,
    RubygemsVersion,
    SemverVersion,
)

Constraint = tuple[str, str]  # (operator, version)
Alternative = list[Constraint]  # AND-ed constraints

VERSION_CLASS: dict[str, Any] = {
    "npm": SemverVersion,
    "pip": PypiVersion,
    "go": GolangVersion,
    "rust": SemverVersion,
    "composer": ComposerVersion,
    "rubygems": RubygemsVersion,
    "maven": MavenVersion,
    "nuget": NugetVersion,
}
SEMVER_ECOSYSTEMS = {"npm", "go", "rust"}

_OP = r"(?:<=|>=|=<|=>|==|!=|<|>|=)"
_VER = r"v?\d[0-9A-Za-z.\-+_]*"
_TOKEN = re.compile(rf"({_OP})?\s*({_VER}|\*)")
_SEMVER = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")


def _caret_tilde(op: str, ver: str) -> Alternative | None:
    parts = re.match(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$", ver)
    if not parts:
        return None
    major, minor, patch = (int(x) if x else 0 for x in parts.groups()[:3])
    lo = ver.lstrip("v")
    if op == "~":
        return [(">=", lo), ("<", f"{major}.{minor + 1}.0")]
    if major > 0:
        return [(">=", lo), ("<", f"{major + 1}.0.0")]
    if minor > 0:
        return [(">=", lo), ("<", f"0.{minor + 1}.0")]
    return [(">=", lo), ("<", f"0.0.{patch + 1}")]


def parse_range(rng: str) -> list[Alternative] | None:
    """OR-ed alternatives of AND-ed constraints, or None if any part is left unparsed."""
    s = rng.strip().replace("≤", "<=").replace("≥", ">=")
    if not s:
        return None
    if re.fullmatch(r"(?i)(?:all|any)(?: versions)?", s):
        s = "*"
    s = re.sub(r"\s*&&?\s*", ", ", s)
    s = re.sub(rf"(?:>=\s*)?({_VER})\s+(?:to|through)\s+({_VER})", r"\1 - \2", s, flags=re.I)
    s = re.sub(rf"({_VER})\s+and\s+(?:earlier|below|lower|prior)\b", r"<= \1", s, flags=re.I)
    s = re.sub(rf"({_VER})\s+and\s+(?:later|above|higher|newer)\b", r">= \1", s, flags=re.I)
    alts: list[Alternative] = []
    for raw_alt in re.split(r"\s*(?:\|\||;)\s*", s):
        alt = re.sub(r"\s+and\s+", ",", raw_alt, flags=re.I).strip().rstrip(",")
        if not alt:
            continue
        alt = re.sub(rf"^({_VER})\s+(<=?)\s*({_VER})$", r">= \1, \2 \3", alt)  # "7.0.0 < 7.29.0"
        hy = re.fullmatch(rf"({_VER})\s+-\s+({_VER})", alt)
        if hy:
            alts.append([(">=", hy.group(1)), ("<=", hy.group(2))])
            continue
        cons: Alternative = []
        rest = alt
        for m in re.finditer(r"([\^~])\s*(" + _VER + ")", alt):
            ct = _caret_tilde(m.group(1), m.group(2))
            if ct is None:
                return None
            cons += ct
            rest = rest.replace(m.group(0), " ")
        for m in _TOKEN.finditer(rest):
            op, ver = m.group(1) or "=", m.group(2)
            op = {"=>": ">=", "=<": "<=", "==": "="}.get(op, op)
            if ver != "*":
                cons.append((op, ver))
        leftover = _TOKEN.sub("", rest).replace(",", "").strip()
        if leftover or (not cons and "*" not in alt):
            return None
        if len(cons) > 1 and all(op == "=" for op, _ in cons):
            alts += [[c] for c in cons]  # "1.0.1, 1.0.2": a list; no version equals two
            continue
        alts.append(cons)
    return alts


def _mk(cls: Any, ver: str) -> Any:
    if cls is GolangVersion:
        return cls(ver if ver.startswith("v") else "v" + ver)
    return cls(ver.lstrip("v"))


def _satisfiable(cls: Any, cons: Alternative) -> bool:
    lows = [_mk(cls, b) for op, b in cons if op in (">", ">=")]
    highs = [_mk(cls, b) for op, b in cons if op in ("<", "<=")]
    return not (lows and highs and max(lows) >= min(highs))


def alternatives(ghsa_ecosystem: str, rng: str | None) -> list[Alternative] | None:
    """Parsed alternatives, re-reading commas as OR when the AND reading is contradictory, or when it
    joins an exact version to a bound (FINDINGS F-085)."""
    cls = VERSION_CLASS.get(ghsa_ecosystem)
    if not rng:
        return None
    alts = parse_range(rng)
    if cls is None:
        return alts
    try:
        mixed = alts is not None and any(len(c) > 1 and any(op == "=" for op, _ in c) for c in alts)
        # "<= 3.0.10, 4.0.0": an exact version listed beside a bound is another alternative, not an AND
        if "," in rng and (alts is None or mixed or any(not _satisfiable(cls, c) for c in alts)):
            segs = [parse_range(seg) for seg in re.split(r"\s*[,;]\s*(?=[<>=~^]|\d|v\d)", rng)]
            alts = None if any(sg is None for sg in segs) else [c for sg in segs if sg for c in sg]
    except Exception:
        return None
    return alts


def affected(ghsa_ecosystem: str, version: str, rng: str | None) -> bool | None:
    """True/False if `version` is (not) in `rng`; None when it can't be evaluated."""
    cls = VERSION_CLASS.get(ghsa_ecosystem)
    alts = alternatives(ghsa_ecosystem, rng)
    if cls is None or alts is None or not version:
        return None
    try:
        v = _mk(cls, version)
        for cons in alts:
            ok = True
            for op, bound in cons:
                b = _mk(cls, bound)
                ok = v != b if op == "!=" else {"<": v < b, "<=": v <= b, ">": v > b, ">=": v >= b, "=": v == b}[op]
                if not ok:
                    break
            if ok:
                return True
        return False
    except Exception:
        return None


_NO_FIX = re.compile(
    r"(?i)\s*(?:none|n/?a|tbd|[-–—]|no fix|not (?:yet )?(?:fixed|patched)|unpatched|will not fix)\b.*|\s*"
)


def fixed_versions(patched: str | None) -> list[str] | None:
    """Plain versions from the maintainer's fixed-version field, or None if it isn't plain versions.

    Accepts "1.2.3", "1.2.3, 2.0.1", ">= 1.2.3" and ">= 1.2, >= 2.0" (also "=>" and "V1.2"). Text that
    reads as a range ("< 2.5.1") or words ("tbd") is None: its meaning isn't certain (FINDINGS F-069).
    """
    if not patched:
        return None
    text = re.sub(r"(?:>=|=>)\s*", "", patched.strip())
    parts = [("v" + x[1:]) if x[:1] == "V" else x for x in re.split(r"[\s,;]+", text) if x]
    if not parts or not all(re.fullmatch(_VER, x) for x in parts):
        return None
    return parts


def no_fix(patched: str | None) -> bool:
    """The fixed-version field says there's no fix (empty, "None", "N/A", "tbd", ...)."""
    return _NO_FIX.fullmatch(patched or "") is not None


def already_fixed(ghsa_ecosystem: str, version: str, patched: str | None) -> bool | None:
    """True if `version` is at or after the applicable fixed version (FINDINGS F-051).

    With several per-branch fixes, the fix on the same major.minor line applies. None when the
    fixed-version text can't be read as plain versions.
    """
    cls = VERSION_CLASS.get(ghsa_ecosystem)
    fixes = fixed_versions(patched)
    if cls is None or not fixes:
        return None

    def line(s: str) -> str:
        return ".".join(s.lstrip("v").split(".")[:2])

    try:
        v = _mk(cls, version)
        same = [f for f in fixes if line(f) == line(version)]
        if same:
            return bool(v >= _mk(cls, same[0]))
        if len(fixes) == 1:
            return bool(v >= _mk(cls, fixes[0]))
        return None
    except Exception:
        return None


def norm_name(ghsa_ecosystem: str, name: str) -> str:
    if ghsa_ecosystem == "pip":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ghsa_ecosystem in ("npm", "rust", "composer"):
        return name.lower()
    return name


def go_relation(advisory_path: str, module: str) -> str | None:
    """How a Go advisory path relates to a module: same / package_in_module / major_version_variant.

    A "/vN" suffix is a different module under Go's major-version rule (FINDINGS F-052).
    """
    if advisory_path == module:
        return "same"
    for longer, shorter in ((advisory_path, module), (module, advisory_path)):
        if longer.startswith(shorter + "/"):
            first = longer[len(shorter) + 1 :].split("/")[0]
            if re.fullmatch(r"v\d+", first):
                return "major_version_variant"
            return "package_in_module" if longer is advisory_path else None
    return None


def _fix_for(ghsa_ecosystem: str, low: str | None, patched: str | None) -> str | None:
    """The fixed version that closes an open-ended range starting at `low`, if it's unambiguous.

    Maintainers often enter ">= 4.29.0" as the affected range and put the fix only in the patched
    field. Without it, the OSV range would mark every later version, fixes included, as affected.
    """
    cls = VERSION_CLASS.get(ghsa_ecosystem)
    fixes = fixed_versions(patched)
    if cls is None or not fixes:
        return None
    if len(fixes) > 1 and low is not None:
        same = [f for f in fixes if f.lstrip("v").split(".")[:2] == low.lstrip("v").split(".")[:2]]
        fixes = same
    if len(fixes) != 1:
        return None
    try:
        if low is not None and not _mk(cls, fixes[0]) > _mk(cls, low):
            return None
    except Exception:
        return None
    return fixes[0]


def osv_ranges(
    ghsa_ecosystem: str, rng: str | None, patched: str | None = None
) -> tuple[list[dict[str, Any]], list[str]] | None:
    """Convert a maintainer range to OSV `ranges` (and enumerated `versions`), or None.

    Each alternative becomes one range with introduced / fixed / last_affected events. An
    alternative that's a single "= X" becomes an enumerated version. An alternative with no upper
    bound is closed by the patched version when that's unambiguous. Anything OSV can't express
    exactly (a strict lower bound, several bounds on one side) makes the whole range None, so the
    feed falls back to publishing the raw string. So does an open-ended alternative when the fixed
    field names something that isn't a usable fix: published, it would mark the fix as affected
    (FINDINGS F-069).
    """
    alts = alternatives(ghsa_ecosystem, rng)
    if not alts:
        return None
    semver = ghsa_ecosystem in SEMVER_ECOSYSTEMS
    ranges: list[dict[str, Any]] = []
    versions: list[str] = []

    def clean(v: str) -> str:
        return v.lstrip("v") if semver else v

    for cons in alts:
        ops = [op for op, _ in cons]
        if ops == ["="]:
            versions.append(cons[0][1])
            continue
        lows = [v for op, v in cons if op == ">="]
        highs = [(op, v) for op, v in cons if op in ("<", "<=")]
        if any(op in (">", "!=", "=") for op in ops) or len(lows) > 1 or len(highs) > 1:
            return None
        events: list[dict[str, str]] = [{"introduced": clean(lows[0]) if lows else "0"}]
        if highs:
            op, v = highs[0]
            events.append({"fixed" if op == "<" else "last_affected": clean(v)})
        elif fix := _fix_for(ghsa_ecosystem, lows[0] if lows else None, patched):
            events.append({"fixed": clean(fix)})
        elif not no_fix(patched):
            return None
        values = [clean(e) for ev in events for e in ev.values() if e != "0"]
        kind = "SEMVER" if semver and all(_SEMVER.fullmatch(x) for x in values) else "ECOSYSTEM"
        ranges.append({"type": kind, "events": events})
    return ranges, versions
