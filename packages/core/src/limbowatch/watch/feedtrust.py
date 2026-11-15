"""Are the downloaded feed files ones that limbowatch/limbowatch's site workflow built from main, in one build?
(FINDINGS F-191 to F-195)

Each build attests its feed files together (`actions/attest`, SLSA provenance signed through Sigstore): one signed
statement lists the SHA-256 of `all.zip`, `watchlist.json` and the rest. The watcher looks up `watchlist.json`'s
digest in GitHub's attestation API for this repository and accepts the pair only if a statement made by `.github/
workflows/site.yml` on `refs/heads/main` names that watchlist and also names the `all.zip` it downloaded. So a
feed swapped on limbo.watch, its host or Cloudflare is refused, and so is an older genuine `all.zip` served next to a
newer watchlist: only a run of that workflow in this repository can add an attestation, and the pair must come from
the same run.

It trusts GitHub's API, over TLS, to have checked the signature when the attestation was stored. `gh attestation verify`
also checks the Sigstore certificate and transparency log itself; WATCHER.md shows how.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from limbowatch.http import HttpClient

ATTESTATIONS = "https://api.github.com/repos/limbowatch/limbowatch/attestations/sha256:{digest}?per_page=100"
SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"
WORKFLOW = {
    "repository": "https://github.com/limbowatch/limbowatch",
    "path": ".github/workflows/site.yml",
    "ref": "refs/heads/main",
}
BUILDER = "https://github.com/limbowatch/limbowatch/.github/workflows/site.yml@refs/heads/main"
VERIFIED_FILE = "feed-verified.txt"  # "<all.zip digest>:<watchlist digest>" pairs already verified, in the cache
KEEP = 50


class Verdict(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"  # GitHub has spoken: no attestation from the site workflow on main names this file
    UNKNOWN = "unknown"  # GitHub couldn't be asked, or its answer couldn't be read


@dataclass(frozen=True)
class Result:
    verdict: Verdict
    why: str
    together: frozenset[str] = field(default_factory=frozenset)  # digests attested in the same build(s)
    mixed: bool = False  # REJECTED because the two files are genuine-looking but from different builds


def _dict(x: Any) -> dict[str, Any]:
    return x if isinstance(x, dict) else {}


def check(body: Any, digest: str) -> Result:
    """The verdict for GitHub's 200 answer about `digest` (pure: no requests).

    REJECTED only when the answer is clearly GitHub's and clearly says no: an empty list, or attestations that were
    read and none names this file from the site workflow on main. An answer that can't be read (an HTML page from a
    proxy, a format GitHub changed) is UNKNOWN, so a genuine feed is never refused for it (F-193). When VERIFIED,
    `together` holds every digest the matching statements list: the files built with this one."""
    attestations = body.get("attestations") if isinstance(body, dict) else None
    if not isinstance(attestations, list):
        return Result(Verdict.UNKNOWN, "GitHub's attestation API gave an answer that couldn't be read")
    if not attestations:
        return Result(Verdict.REJECTED, "GitHub lists no attestation for it")
    read, together = 0, set()
    for a in attestations:
        try:
            envelope = _dict(_dict(_dict(a).get("bundle")).get("dsseEnvelope"))
            statement = json.loads(base64.b64decode(envelope["payload"]))
        except (KeyError, TypeError, ValueError):
            continue
        if not isinstance(statement, dict):
            continue
        read += 1
        subjects = statement.get("subject")
        names = {
            d["sha256"]
            for s in (subjects if isinstance(subjects, list) else [])
            if isinstance(d := _dict(s).get("digest"), dict) and isinstance(d.get("sha256"), str)
        }
        predicate = _dict(statement.get("predicate"))
        workflow = _dict(_dict(predicate.get("buildDefinition")).get("externalParameters")).get("workflow")
        builder = _dict(_dict(predicate.get("runDetails")).get("builder")).get("id")
        if (
            statement.get("predicateType") == SLSA_PROVENANCE
            and digest in names
            and workflow == WORKFLOW
            and builder == BUILDER
        ):
            together |= names
    if together:
        return Result(Verdict.VERIFIED, "built by limbowatch/limbowatch's site workflow on main", frozenset(together))
    if not read:
        return Result(Verdict.UNKNOWN, "GitHub's attestation API listed attestations that couldn't be read")
    return Result(Verdict.REJECTED, "no attestation for it names limbowatch/limbowatch's site workflow on main")


def _known(cache: Path | None) -> set[str]:
    """Pairs verified before. The cache is a convenience: if it can't be read, nothing is known."""
    if cache is None:
        return set()
    try:
        return set((cache / VERIFIED_FILE).read_text(errors="replace").split())
    except OSError:
        return set()


def _remember(cache: Path | None, pair: str) -> None:
    """Best effort: a cache that can't be written (read-only, full) costs a lookup next time, never the scan."""
    if cache is None:
        return
    f = cache / VERIFIED_FILE
    with contextlib.suppress(OSError):
        lines = f.read_text(errors="replace").split() if f.exists() else []
        cache.mkdir(parents=True, exist_ok=True)
        f.write_text("\n".join([*lines[-(KEEP - 1) :], pair]) + "\n")


async def verify(http: HttpClient, feed: bytes, watchlist: bytes, cache: Path | None) -> Result:
    """Look the watchlist up in GitHub's attestation API and check that the same build's statement also lists
    `feed`. One request at most (a pair verified before isn't asked again), one attempt, a short timeout.

    The watchlist is unique to its build (it carries the build time), so its answer has that one build's statement,
    while a byte-identical all.zip can be attested by many builds (F-195). REJECTED when GitHub vouches for neither, or
    for the watchlist but not with this all.zip: a mix of builds, such as an older feed next to a newer watchlist."""
    zd, wd = hashlib.sha256(feed).hexdigest(), hashlib.sha256(watchlist).hexdigest()
    pair = f"{zd}:{wd}"
    if pair in _known(cache):
        return Result(Verdict.VERIFIED, "verified earlier")
    url = ATTESTATIONS.format(digest=wd)
    r = await http.get(url, patient=False)
    if r.status in (401, 403) and http.has_github_token:
        # an expired or narrow token can be refused where anyone may read a public repo's attestations. Not on a
        # 404: with a token that works, that's GitHub's definite "none", and a retry mustn't soften it (F-194)
        r = await http.get(url, patient=False, anonymous=True)
    if r.status == 404:
        return Result(Verdict.REJECTED, "GitHub has no attestation for it")
    if r.status != 200:
        why = "couldn't be reached" if r.status < 0 else f"answered {r.status}"
        return Result(Verdict.UNKNOWN, f"GitHub's attestation API {why}")
    result = check(r.body, wd)
    if result.verdict is not Verdict.VERIFIED:
        return result
    if zd not in result.together:
        return Result(Verdict.REJECTED, "its all.zip and watchlist.json come from different builds", mixed=True)
    _remember(cache, pair)
    return result
