"""An upstream repo's commit graph, from a commits-only clone (PHASE0_PLAN §13.18, FINDINGS F-136).

`git clone --bare --filter=tree:0` fetches every commit and tag but no trees or files: 0.4 MB for zlib, 22 MB for
gRPC, under 3 s each. With it, whether a pinned commit contains a fix release is `git merge-base --is-ancestor`,
exact, on any git host, with no API quota. Clones go to a cache directory when one is given, and are updated there.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
from pathlib import Path

CLONE_TIMEOUT = 300
_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": "", "GIT_CONFIG_NOSYSTEM": "1"}


class GitGraph:
    """Questions about one repository's history, answered from a local commits-only clone."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.tags = self._tags()

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", "-c", "safe.directory=*", "--git-dir", str(self.path), *args],
                              capture_output=True, text=True, timeout=120, env={**os.environ, **_ENV})  # fmt: skip

    def _tags(self) -> dict[str, str]:
        r = self._git("for-each-ref", "refs/tags", "--format=%(refname:strip=2) %(objectname) %(*objectname)")
        out = {}
        for line in r.stdout.splitlines():
            name, obj, *peeled = line.split(" ")
            out[name] = peeled[0] if peeled and peeled[0] else obj
        return out

    def commit(self, ref: str) -> str | None:
        """The commit a tag, branch or (abbreviated) commit hash names, if the clone has it."""
        if ref in self.tags:
            return self.tags[ref]
        r = self._git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
        sha = r.stdout.strip()
        return sha if r.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", sha) else None

    def contains(self, ancestor: str, descendant: str) -> bool | None:
        """Is `ancestor` in `descendant`'s history? None when git can't tell (a commit the clone lacks)."""
        r = self._git("merge-base", "--is-ancestor", ancestor, descendant)
        return {0: True, 1: False}.get(r.returncode)

    def tags_containing(self, commit: str) -> list[str]:
        """The tags whose history includes the commit (the commit's own tag too)."""
        r = self._git("tag", "--contains", commit)
        return r.stdout.split() if r.returncode == 0 else []

    def describe(self, commit: str) -> str | None:
        """The nearest tag in the commit's history."""
        r = self._git("describe", "--tags", "--abbrev=0", commit)
        return r.stdout.strip() or None if r.returncode == 0 else None


def _clone(url: str, dest: Path) -> GitGraph | None:
    env = {**os.environ, **_ENV}
    try:
        if (dest / "HEAD").exists():
            subprocess.run(["git", "-c", "safe.directory=*", "--git-dir", str(dest), "fetch", "--quiet", "--tags",
                            "--force", "origin", "+refs/heads/*:refs/heads/*"],
                           capture_output=True, timeout=CLONE_TIMEOUT, env=env)  # fmt: skip
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(["git", "-c", "credential.helper=", "clone", "--quiet", "--bare", "--filter=tree:0",
                                url, str(dest)], capture_output=True, timeout=CLONE_TIMEOUT, env=env)  # fmt: skip
            if r.returncode:
                return None
        return GitGraph(dest)
    except (OSError, subprocess.TimeoutExpired):
        return None


async def graphs(urls: dict[str, str], root: Path, jobs: int = 4) -> dict[str, GitGraph | None]:
    """A commits-only clone of each repo (key → clone URL) under `root`; None where cloning failed."""
    sem = asyncio.Semaphore(jobs)

    async def one(key: str, url: str) -> tuple[str, GitGraph | None]:
        async with sem:
            dest = root / (re.sub(r"[^\w.-]+", "__", key) + ".git")
            return key, await asyncio.to_thread(_clone, url, dest)

    return dict(await asyncio.gather(*(one(k, u) for k, u in sorted(urls.items()))))
