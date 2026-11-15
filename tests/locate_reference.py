"""checks.locate before it indexed lockfiles (F-204): the unchanged reference for test_locate.py."""

from __future__ import annotations

import re


def locate(text: str, filename: str, name: str, version: str = "") -> int:
    """The 1-based line that declares `name` in a lockfile or manifest, or 1 if it can't be found.

    Code Quality and SARIF alerts need a line; OSV-Scanner doesn't report one (FINDINGS F-078, F-079).
    """
    lines = text.splitlines()
    patterns = []
    base = filename.rsplit("/", 1)[-1]
    if base.endswith(".xml") and name.count(":") == 1:  # Maven: groupId and artifactId on lines of their own (F-157)
        group, artifact = name.split(":")
        art = re.compile(rf"<artifactId>\s*{re.escape(artifact)}\s*</artifactId>")
        grp = re.compile(rf"<groupId>\s*{re.escape(group)}\s*</groupId>")

        def block(i: int) -> str:  # the <dependency> (or <plugin>, <parent>) element around line i
            start = next((j for j in range(i, 0, -1) if re.search(r"<(?:dependency|plugin|parent)\b", lines[j - 1])), i)
            end = next(
                (j for j in range(i, len(lines) + 1) if re.search(r"</(?:dependency|plugin|parent)>", lines[j - 1])), i
            )
            return "\n".join(lines[start - 1 : end])

        def excluded(i: int) -> bool:  # inside an <exclusion>: names a dependency that is left out
            for j in range(i, 0, -1):
                if "</exclusion>" in lines[j - 1] and j < i:
                    return False
                if re.search(r"<exclusion>|<(?:dependency|plugin|parent)\b", lines[j - 1]):
                    return "<exclusion>" in lines[j - 1]
            return False

        hits = [i for i, ln in enumerate(lines, 1) if art.search(ln) and not excluded(i)]
        hits = [i for i in hits if grp.search(block(i))]  # another group's artifact isn't this dependency
        if version and len(hits) > 1:
            hits = [i for i in hits if version in block(i)] or hits
        if hits:
            return hits[0]
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        patterns.append(re.compile(rf'"(?:[^"]*/)?node_modules/{re.escape(name)}"'))
    if base == "Cargo.lock":
        patterns.append(re.compile(rf'^name = "{re.escape(name)}"$'))
    if base.endswith(".txt"):
        patterns.append(re.compile(rf"^\s*{_pep503_pattern(name)}\s*(?:[\[=<>!~;@ ]|$)", re.I))
    patterns.append(re.compile(rf"(?<![\w./-]){re.escape(name)}(?![\w-])"))
    if "/" in name:  # e.g. a Git URL: the lockfile names the package by its last path segment
        tail = re.sub(r"\.git$", "", name.rstrip("/").rsplit("/", 1)[-1])
        patterns.append(
            re.compile(rf'"(?:[^"]*/)?node_modules/{re.escape(tail)}"|(?<![\w.-]){re.escape(tail)}(?![\w-])')
        )
    for pat in patterns:
        hits = [i for i, ln in enumerate(lines, 1) if pat.search(ln)]
        if not hits:
            continue
        if version and len(hits) > 1:
            near = [i for i in hits if any(version in ln for ln in lines[i - 1 : i + 3])]
            hits = near or hits
        return hits[0]
    return 1


def _pep503_pattern(name: str) -> str:
    return "[-_.]+".join(re.escape(part) for part in re.split(r"[-_.]+", name))
