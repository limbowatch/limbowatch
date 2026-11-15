"""Is a downloaded feed file one that limbowatch/limbowatch's site workflow built from main? (FINDINGS F-191, F-192)

Each build attests its feed files (`actions/attest`, SLSA provenance signed through Sigstore). The watcher looks up a
file's SHA-256 in GitHub's attestation API for this repository and accepts it only if a signed statement names that
digest and was made by `.github/workflows/site.yml` on `refs/heads/main`. So a feed swapped on limbo.watch, its host or
Cloudflare is refused: only a run of that workflow in this repository can add an attestation.

It trusts GitHub's API, over TLS, to have checked the signature when the attestation was stored. `gh attestation verify`
also checks the Sigstore certificate and transparency log itself; WATCHER.md shows how.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from limbowatch.http import HttpClient

ATTESTATIONS = "https://api.github.com/repos/limbowatch/limbowatch/attestations/sha256:{digest}"
SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"
WORKFLOW = {
    "repository": "https://github.com/limbowatch/limbowatch",
    "path": ".github/workflows/site.yml",
    "ref": "refs/heads/main",
}
BUILDER = "https://github.com/limbowatch/limbowatch/.github/workflows/site.yml@refs/heads/main"
VERIFIED_FILE = "feed-verified.txt"  # digests already verified, in the cache directory
KEEP = 50


class Verdict(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"  # GitHub has no attestation from the site workflow on main for this file
    UNKNOWN = "unknown"  # GitHub couldn't be asked (offline, rate-limited, an error)


def check(body: Any, digest: str) -> tuple[Verdict, str]:
    """The verdict for GitHub's 200 answer about `digest` (pure: no requests).

    REJECTED only when the answer is clearly GitHub's and clearly says no: an empty list, or attestations that were
    read and don't name this file from the site workflow on main. An answer that can't be read (an HTML page from a
    proxy, a format GitHub changed) is UNKNOWN, so a genuine feed is never refused for it (F-193)."""
    attestations = body.get("attestations") if isinstance(body, dict) else None
    if not isinstance(attestations, list):
        return Verdict.UNKNOWN, "GitHub's attestation API gave an answer that couldn't be read"
    if not attestations:
        return Verdict.REJECTED, "GitHub lists no attestation for it"
    read = 0
    for a in attestations:
        try:
            statement = json.loads(base64.b64decode(a["bundle"]["dsseEnvelope"]["payload"]))
        except (KeyError, TypeError, ValueError):
            continue
        if not isinstance(statement, dict):
            continue
        read += 1
        if statement.get("predicateType") != SLSA_PROVENANCE:
            continue
        subjects = statement.get("subject") or []
        if not any(isinstance(s, dict) and (s.get("digest") or {}).get("sha256") == digest for s in subjects):
            continue
        predicate = statement.get("predicate") or {}
        workflow = ((predicate.get("buildDefinition") or {}).get("externalParameters") or {}).get("workflow")
        builder = ((predicate.get("runDetails") or {}).get("builder") or {}).get("id")
        if workflow == WORKFLOW and builder == BUILDER:
            return Verdict.VERIFIED, "built by limbowatch/limbowatch's site workflow on main"
    if not read:
        return Verdict.UNKNOWN, "GitHub's attestation API listed attestations that couldn't be read"
    return Verdict.REJECTED, "no attestation for it names limbowatch/limbowatch's site workflow on main"


def _known(cache: Path | None) -> set[str]:
    """Digests verified before. The cache is a convenience: if it can't be read, nothing is known."""
    if cache is None:
        return set()
    try:
        return set((cache / VERIFIED_FILE).read_text(errors="replace").split())
    except OSError:
        return set()


def _remember(cache: Path | None, digest: str) -> None:
    """Best effort: a cache that can't be written (read-only, full) costs a lookup next time, never the scan."""
    if cache is None:
        return
    f = cache / VERIFIED_FILE
    with contextlib.suppress(OSError):
        lines = f.read_text(errors="replace").split() if f.exists() else []
        cache.mkdir(parents=True, exist_ok=True)
        f.write_text("\n".join([*lines[-(KEEP - 1) :], digest]) + "\n")


async def verify(http: HttpClient, data: bytes, cache: Path | None) -> tuple[Verdict, str]:
    """Look `data` up in GitHub's attestation API. A digest verified before (kept in the cache) isn't asked again, so
    a scan whose feed hasn't changed makes no request. One attempt with a short timeout: never waits or retries."""
    digest = hashlib.sha256(data).hexdigest()
    if digest in _known(cache):
        return Verdict.VERIFIED, "verified earlier"
    url = ATTESTATIONS.format(digest=digest)
    r = await http.get(url, patient=False)
    if r.status in (401, 403, 404) and http.has_github_token:
        # an expired or narrow token can be refused where anyone may read a public repo's attestations
        r = await http.get(url, patient=False, anonymous=True)
    if r.status == 404:
        return Verdict.REJECTED, "GitHub has no attestation for it"
    if r.status != 200:
        return Verdict.UNKNOWN, (
            "GitHub's attestation API couldn't be reached"
            if r.status < 0
            else f"GitHub's attestation API answered {r.status}"
        )
    verdict, why = check(r.body, digest)
    if verdict is Verdict.VERIFIED:
        _remember(cache, digest)
    return verdict, why
