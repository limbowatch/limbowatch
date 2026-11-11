"""A git repository's tags and the commits they point at, by `git ls-remote` (PHASE0_PLAN §13.18, FINDINGS F-136).

`ls-remote` is git's own protocol, not GitHub's REST API, so it costs no API quota and works on any git host. Tags
are peeled: an annotated tag's own object isn't a commit (zlib's are annotated), so the `^{}` line's commit is used.
No credentials are sent; a private or missing repository gives None.
"""

from __future__ import annotations

import asyncio
import os

TIMEOUT = 60.0


async def tags(url: str, timeout: float = TIMEOUT) -> dict[str, str] | None:
    """Tag name → commit for the repository at `url`; None when it can't be listed."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": ""}
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "-c", "credential.helper=", "ls-remote", "--tags", url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=env,
        )  # fmt: skip
    except OSError:
        return None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        return None
    if proc.returncode:
        return None
    return parse(out.decode(errors="replace"))


def parse(listing: str) -> dict[str, str]:
    """`ls-remote --tags` output → tag name → commit, peeled where the listing has a `^{}` line."""
    plain: dict[str, str] = {}
    peeled: dict[str, str] = {}
    for line in listing.splitlines():
        sha, _, ref = line.partition("\t")
        if not ref.startswith("refs/tags/"):
            continue
        name = ref.removeprefix("refs/tags/")
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            plain[name] = sha
    return {n: peeled.get(n, s) for n, s in plain.items()}
