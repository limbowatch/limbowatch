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
    """The verdict for GitHub's answer about `digest` (pure: no requests)."""
    attestations = body.get("attestations") if isinstance(body, dict) else None
    if not attestations:
        return Verdict.REJECTED, "GitHub has no attestation for it"
    for a in attestations:
        try:
            statement = json.loads(base64.b64decode(a["bundle"]["dsseEnvelope"]["payload"]))
        except (KeyError, TypeError, ValueError):
            continue
        if not isinstance(statement, dict) or statement.get("predicateType") != SLSA_PROVENANCE:
            continue
        subjects = statement.get("subject") or []
        if not any(isinstance(s, dict) and (s.get("digest") or {}).get("sha256") == digest for s in subjects):
            continue
        predicate = statement.get("predicate") or {}
        workflow = ((predicate.get("buildDefinition") or {}).get("externalParameters") or {}).get("workflow")
        builder = ((predicate.get("runDetails") or {}).get("builder") or {}).get("id")
        if workflow == WORKFLOW and builder == BUILDER:
            return Verdict.VERIFIED, "built by limbowatch/limbowatch's site workflow on main"
    return Verdict.REJECTED, "no attestation for it names limbowatch/limbowatch's site workflow on main"


async def verify(http: HttpClient, data: bytes, cache: Path | None) -> tuple[Verdict, str]:
    """Look `data` up in GitHub's attestation API. A digest verified before (kept in the cache) isn't asked again, so
    a scan whose feed hasn't changed makes no request. Never waits on a rate limit: that's UNKNOWN."""
    digest = hashlib.sha256(data).hexdigest()
    known = cache / VERIFIED_FILE if cache is not None else None
    if known is not None and known.exists() and digest in known.read_text().split():
        return Verdict.VERIFIED, "verified earlier"
    r = await http.get(ATTESTATIONS.format(digest=digest), patient=False)
    if r.status == 404:
        return Verdict.REJECTED, "GitHub has no attestation for it"
    if r.status != 200:
        return Verdict.UNKNOWN, (
            "GitHub's attestation API couldn't be reached"
            if r.status < 0
            else f"GitHub's attestation API answered {r.status}"
        )
    verdict, why = check(r.body, digest)
    if verdict is Verdict.VERIFIED and known is not None:
        lines = (known.read_text().split() if known.exists() else [])[-(KEEP - 1) :]
        known.parent.mkdir(parents=True, exist_ok=True)
        known.write_text("\n".join([*lines, digest]) + "\n")
    return verdict, why
