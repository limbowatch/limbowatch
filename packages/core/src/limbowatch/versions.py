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
    GolangVersion,
    MavenVersion,
    NugetVersion,
    PypiVersion,
    RubygemsVersion,
    SemverVersion,
)

Constraint = tuple[str, str]  # (operator, version)
Alternative = list[Constraint]  # AND-ed constraints

_COMPOSER = re.compile(
    r"v?(\d+(?:\.\d+){0,3})(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p|dev)(?:[._-]?(\d+))?)?", re.I
)
_STABILITY = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "rc": 3,
    None: 4,
    "stable": 4,
    "patch": 5,
    "pl": 5,
    "p": 5,
}


class ComposerVersion:
    """A Packagist version ordered the way Composer orders it: up to four numeric parts, then the stability
    (dev < alpha < beta < RC < stable < patch) and its number. univers reads a fourth part as semver build
    metadata, so "6.7.13.0 < 6.7.13.1" came out False, and so did "6.7.13.0 == 6.7.13.1" (FINDINGS F-123)."""

    __slots__ = ("key", "string")

    def __init__(self, string: str) -> None:
        m = _COMPOSER.fullmatch(string.strip())
        if m is None:
            raise ValueError(f"not a Composer version: {string!r}")
        nums = [int(x) for x in m.group(1).split(".")]
        stab = (m.group(2) or "").lower() or None
        self.string = string
        self.key = (*nums, *[0] * (4 - len(nums)), _STABILITY[stab], int(m.group(3) or 0))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ComposerVersion) and self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)

    def __lt__(self, other: ComposerVersion) -> bool:
        return self.key < other.key

    def __le__(self, other: ComposerVersion) -> bool:
        return self.key <= other.key

    def __gt__(self, other: ComposerVersion) -> bool:
        return self.key > other.key

    def __ge__(self, other: ComposerVersion) -> bool:
        return self.key >= other.key

    def __str__(self) -> str:
        return self.string

    def __repr__(self) -> str:
        return f"ComposerVersion({self.string!r})"


_PRE = {
    "dev": 0,
    "snapshot": 0,
    "pre": 1,
    "preview": 1,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "rc": 3,
    "cr": 3,
    "m": 1,
}
_UPSTREAM_TOKEN = re.compile(r"\d+|[a-z]+")


class UpstreamVersion:
    """A version of a C/C++ (or other unpackaged) upstream, as its tags and advisories write it (PHASE0_PLAN §13.18).

    Numbers compare as numbers and any number of parts is allowed; `1.0` equals `1.0.0`. A word starting a
    pre-release (`rc1`, `beta`, `alpha.2`, `dev`) sorts before the release; any other part after the release
    numbers is a later patch level: ImageMagick's `7.1.1-38` comes after `7.1.1` (FINDINGS F-136)."""

    __slots__ = ("key", "string")

    def __init__(self, string: str) -> None:
        s = string.strip().lower()
        s = s[1:] if s[:1] == "v" and s[1:2].isdigit() else s
        if not s or not s[0].isdigit():
            raise ValueError(f"not a version: {string!r}")
        key: list[tuple[int, int | str]] = []
        for tok in _UPSTREAM_TOKEN.findall(s):
            if tok.isdigit():
                key.append((2, int(tok)))
            elif tok in _PRE:
                key.append((0, _PRE[tok]))
            else:
                key.append((1, tok))  # p, patch, post, a build word: after the release
        n = next((i for i, k in enumerate(key) if k[0] != 2), len(key))
        release, rest = key[:n], key[n:]
        while len(release) > 1 and release[-1] == (2, 0):  # 1.0.0 == 1.0, also before "-rc1"
            release.pop()
        self.string, self.key = string, tuple(release + rest)

    def _cmp(self, other: UpstreamVersion) -> int:
        a, b = self.key, other.key
        for i in range(max(len(a), len(b))):
            x = a[i] if i < len(a) else (1, "")  # the end: after a pre-release, before a number or patch word
            y = b[i] if i < len(b) else (1, "")
            if x != y:
                return -1 if (x[0], str(x[1]).zfill(12)) < (y[0], str(y[1]).zfill(12)) else 1
        return 0

    def __eq__(self, other: object) -> bool:
        return isinstance(other, UpstreamVersion) and self._cmp(other) == 0

    def __hash__(self) -> int:
        return hash(self.key)

    def __lt__(self, other: UpstreamVersion) -> bool:
        return self._cmp(other) < 0

    def __le__(self, other: UpstreamVersion) -> bool:
        return self._cmp(other) <= 0

    def __gt__(self, other: UpstreamVersion) -> bool:
        return self._cmp(other) > 0

    def __ge__(self, other: UpstreamVersion) -> bool:
        return self._cmp(other) >= 0

    def __str__(self) -> str:
        return self.string

    def __repr__(self) -> str:
        return f"UpstreamVersion({self.string!r})"


UPSTREAM = "upstream"  # the VERSION_CLASS key for upstream sources' versions and their advisories' ranges
_TAG_VERSION = re.compile(r"\d+(?:[._-]\d+)*(?:[.-]?(?:a|b|rc|alpha|beta|pre|p|patch)\.?\d*)?", re.I)


def version_of_tag(tag: str) -> str | None:
    """The version a tag names: `v1.2.3` → 1.2.3, `curl-8_10_0` → 8.10.0, `release-22.1.8` → 22.1.8; a tag without
    digits names none."""
    runs = list(_TAG_VERSION.finditer(tag))
    m = runs[-1] if runs else None  # the last version-looking run: "openssl-3.0.15" → 3.0.15
    if m is None:
        return None
    v = m.group(0)
    if "." not in v and "_" in v:
        v = v.replace("_", ".")
    return v


def tag_for(version: str, tags: dict[str, str]) -> str | None:
    """The tag that names `version` among `tags` (name → commit): `X` or `vX`, else the one tag whose version reads
    the same (`bacnet-stack-1.6.0`, `release-22.1.8`, `curl-8_10_0`). None when there's none, or several disagree
    (FINDINGS F-136)."""
    v = version.strip()
    for t in (v, f"v{v}", v.removeprefix("v")):
        if t in tags:
            return t
    try:
        want = UpstreamVersion(v)
    except ValueError:
        return None
    hits = []
    for t in tags:
        tv = version_of_tag(t)
        try:
            if tv is not None and UpstreamVersion(tv) == want:
                hits.append(t)
        except ValueError:
            continue
    commits = {tags[t] for t in hits}
    return sorted(hits)[0] if hits and len(commits) == 1 else None


VERSION_CLASS: dict[str, Any] = {
    "npm": SemverVersion,
    "pip": PypiVersion,
    "go": GolangVersion,
    "rust": SemverVersion,
    "composer": ComposerVersion,
    "rubygems": RubygemsVersion,
    "maven": MavenVersion,
    "nuget": NugetVersion,
    # Hex, Pub and Swift package versions are semantic versions (Swift tags may carry a leading "v", stripped)
    "erlang": SemverVersion,
    "pub": SemverVersion,
    "swift": SemverVersion,
    UPSTREAM: UpstreamVersion,
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


_WILDCARD = re.compile(r"(?<![\w.])(>=|<=|=>|=<|==|>|<|=)?\s*(v?\d+(?:\.\d+)*)\.[*xX](?:\.[*xX])*(?![\w.])")


def _wildcard(m: re.Match[str]) -> str:
    """A wildcard: "2.16.*" is 2.16.0 up to 2.17.0; with an operator, the bound that operator means (F-123)."""
    op, base = m.group(1) or "=", m.group(2)
    v, nums = ("v" if base.startswith("v") else ""), base.lstrip("v").split(".")
    up = [*nums[:-1], str(int(nums[-1]) + 1)]
    pad = max(3 - len(nums) - 1, 0) * [".0"]  # three parts at least, so semver ecosystems can read them
    lo = v + ".".join(nums) + ".0" + "".join(pad)
    hi = v + ".".join(up) + ".0" + "".join(pad)
    return {">=": f">= {lo}", "=>": f">= {lo}", ">": f">= {hi}", "<": f"< {lo}", "<=": f"< {hi}", "=<": f"< {hi}"}.get(
        op, f">= {lo}, < {hi}"
    )


_SPAN = re.compile(r"(?<![\w.~^-])(v?(\d+(?:\.\d+){2,3}))-(v?(\d+(?:\.\d+){2,3}))(?![\w.-])")


def _span(m: re.Match[str]) -> str:
    """Two versions of three or four parts joined by a hyphen, the second higher, are a span the way "A - B" is.
    Anything else ("1.0.0-0.3.7", a numeric pre-release; Maven's "3.0-20251107.114628") is left as written."""
    lo, hi = [int(x) for x in m.group(2).split(".")], [int(x) for x in m.group(4).split(".")]
    return f"{m.group(1)} - {m.group(3)}" if hi > lo and hi[0] >= lo[0] else m.group(0)


def parse_range(rng: str) -> list[Alternative] | None:
    """OR-ed alternatives of AND-ed constraints, or None if any part is left unparsed."""
    s = rng.strip().replace("≤", "<=").replace("≥", ">=")
    if not s:
        return None
    s = _WILDCARD.sub(_wildcard, s)
    if re.fullmatch(r"(?i)(?:all|any)(?: versions)?", s):
        s = "*"
    s = re.sub(r"\s*&&?\s*", ", ", s)
    s = re.sub(rf"(?:>=\s*)?({_VER})\s+(?:to|through)\s+({_VER})", r"\1 - \2", s, flags=re.I)
    s = re.sub(rf"(?<![\w.~^])({_VER})\s*~\s*({_VER})", r"\1 - \2", s)  # "1.4.0~1.4.10": a span, not a tilde range
    s = _SPAN.sub(_span, s)  # "11.0.0-11.5.50": a span, not a pre-release (F-123)
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
    """False if no version can meet every bound. Equal inclusive bounds (">= 3.8.8, <= 3.8.8") are one version."""
    lows = [(_mk(cls, b), op == ">") for op, b in cons if op in (">", ">=")]
    highs = [(_mk(cls, b), op == "<") for op, b in cons if op in ("<", "<=")]
    if not (lows and highs):
        return True
    lo = max(v for v, _ in lows)
    hi = min(v for v, _ in highs)
    strict = any(x for v, x in lows if v == lo) or any(x for v, x in highs if v == hi)
    return lo < hi or (lo == hi and not strict)


def _pair_bounds(alts: list[Alternative]) -> list[Alternative]:
    """Comma-separated parts read as OR: a lone lower bound followed by a lone upper bound is one interval."""
    out: list[Alternative] = []
    i = 0
    while i < len(alts):
        a, b = alts[i], alts[i + 1] if i + 1 < len(alts) else None
        if b is not None and len(a) == 1 and len(b) == 1 and a[0][0] in (">", ">=") and b[0][0] in ("<", "<="):
            out.append([a[0], b[0]])
            i += 2
            continue
        out.append(a)
        i += 1
    return out


def _intervals(cons: Alternative) -> list[Alternative]:
    """A contradictory or mixed AND re-read as OR, in order: each lower bound opens an interval that the next
    upper bound closes, and an exact version or an upper bound with no lower bound before it stands alone.
    ">= 2.2.0, < 2.2.10, >= 2.3.0, < 2.3.7" is two intervals, not four bounds that together cover every version;
    "< 0.6.2, >= 0.7.0 < 0.7.2" is "< 0.6.2" or the interval (FINDINGS F-123)."""
    out: list[Alternative] = []
    cur: Alternative | None = None
    for op, v in cons:
        if op in (">", ">="):
            if cur:
                out.append(cur)
            cur = [(op, v)]
        elif op in ("<", "<="):
            if cur and all(o in (">", ">=", "!=") for o, _ in cur) and any(o in (">", ">=") for o, _ in cur):
                out.append([*cur, (op, v)])
                cur = None
            else:
                if cur:
                    out.append(cur)
                cur = None
                out.append([(op, v)])
        elif op == "!=" and cur is not None:
            cur.append((op, v))
        else:
            if cur:
                out.append(cur)
            cur = None
            out.append([(op, v)])
    if cur:
        out.append(cur)
    return out


def _covers_everything(cls: Any, alts: list[Alternative]) -> bool:
    """True if the alternatives together leave no version out (their intervals' union is unbounded both ways)."""
    zero = {"0", "0.0", "0.0.0", "v0", "v0.0.0"}
    spans: list[tuple[Any, bool, Any, bool]] = []
    for c in alts:
        if any(op == "!=" for op, _ in c):
            return False  # too unusual to judge; leave it as parsed
        if not c:
            return True
        lo = hi = None
        lo_in = hi_in = True
        for op, b in c:
            v = _mk(cls, b)
            if op == "=":
                lo, hi = v, v
            elif op in (">", ">="):
                if b not in zero and (lo is None or v > lo):
                    lo, lo_in = v, op == ">="
            elif hi is None or v < hi:
                hi, hi_in = v, op == "<="
        spans.append((lo, lo_in, hi, hi_in))
    starts = [(hi, hi_in) for lo, _, hi, hi_in in spans if lo is None]
    if not starts:
        return False
    if any(hi is None for hi, _ in starts):
        return True
    reach, reach_in = max(starts, key=lambda x: (x[0], x[1]))  # how far up the versions are covered from below
    bounded = [(lo, lo_in, hi, hi_in) for lo, lo_in, hi, hi_in in spans if lo is not None]
    for lo, lo_in, hi, hi_in in sorted(bounded, key=lambda s: s[0]):
        if lo < reach or (lo == reach and (lo_in or reach_in)):
            if hi is None:
                return True
            if hi > reach or (hi == reach and hi_in):
                reach, reach_in = hi, hi_in
    return False


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
            if any(sg is None for sg in segs):
                return None
            # each comma-separated part on its own; a part that still contradicts itself ("< 2.8.8 >= 2.9.0",
            # intervals without a comma between them) is read in order; then lone bounds pair up (F-123)
            parts = [
                part
                for sg in segs
                if sg
                for c in sg
                for part in (
                    _intervals(c) if (len(c) > 1 and any(op == "=" for op, _ in c)) or not _satisfiable(cls, c) else [c]
                )
            ]
            alts = _pair_bounds(parts)
            if not all(_satisfiable(cls, c) for c in alts) or _covers_everything(cls, alts):
                # still contradictory (">= 0.11.0, < 0.6.10"), or every version at once (">= 9.0.0, < 9.0.0
                # >= 8.0.0, < 8.0.11"): a maintainer's slip that can't be evaluated, not "none" or "all"
                return None
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


def applicable_fix(ghsa_ecosystem: str, version: str, patched: str | None) -> str | None:
    """The fixed version that applies to `version`: the one on its major.minor line when the advisory lists one
    per release line, else the only one. None when that isn't certain."""
    fixes = fixed_versions(patched)
    if not fixes:
        return None

    def line(s: str) -> str:
        return ".".join(s.lstrip("v").split(".")[:2])

    same = [f for f in fixes if line(f) == line(version)]
    if len(same) == 1:
        return same[0]
    return fixes[0] if len(fixes) == 1 else None


def highest(ghsa_ecosystem: str, versions: list[str]) -> str | None:
    """The highest of `versions` by the ecosystem's own ordering; None if they can't all be compared."""
    cls = VERSION_CLASS.get(ghsa_ecosystem)
    if cls is None or not versions:
        return None
    try:
        return max(versions, key=lambda v: _mk(cls, v))
    except Exception:
        return None


def norm_name(ghsa_ecosystem: str, name: str) -> str:
    if ghsa_ecosystem == "pip":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ghsa_ecosystem in ("npm", "rust", "composer"):
        return name.lower()
    return name


_DOTDOT_V = r"v?\d[\w+-]*(?:\.[\w+-]+)*"


def dotdot_readings(rng: str) -> tuple[str, str] | None:
    """Both readings of a Rust-style `A .. B`: B fixed, or B affected. Matching takes the answer only
    when they agree; the feed never guesses (F-069)."""
    m = re.fullmatch(rf"\s*({_DOTDOT_V})\s*\.\.=?\s*({_DOTDOT_V})\s*", rng)
    if not m:
        return None
    a, b = m.groups()
    return f">= {a}, < {b}", f">= {a}, <= {b}"


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
