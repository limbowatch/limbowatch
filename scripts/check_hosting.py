"""Compare two hosts of the site path by path (docs/HOSTING_PLAN.md, step 4): today's nginx and the R2 setup.

    uv run python scripts/check_hosting.py [--old https://limbo.watch] [--new https://next.limbo.watch] [--sample 40]

For each path, both hosts must agree on the status, the body (SHA-256), the content type, CORS and the five security
headers, and on where a redirect goes (by path: nginx sends `http://`, the new setup `https://`). On the new host it
also checks what clients rely on: a 304 for the ETag it sent, a byte range, and for each `/osv/<Ecosystem>/all.zip`
an `X-Goog-Hash` equal to the CRC-32C of the body, which is what OSV-Scanner checks before reusing a cached zip
(FINDINGS F-073). Paths: the site's pages, every OSV zip, and a random sample of advisory pages and feed records.
Network; read-only. Exit 1 if anything differs.

Right after a deploy the two hosts can briefly serve different builds (the cluster syncs on its own schedule, and
Cloudflare caches for minutes), so a body difference is worth a second run before it's worth a look.
"""

from __future__ import annotations

import argparse
import hashlib
import random
import sys
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
from limbowatch.publish.feed import goog_hash

SECURITY = [
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "content-security-policy",
]
COMPARED = ["content-type", "access-control-allow-origin", *SECURITY]
PAGES = [
    "/",
    "/tracker/",
    "/tracker/?fix=yes",
    "/tracker",
    "/check/",
    "/scan/",
    "/feed/",
    "/methodology/",
    "/press/",
    "/compliance/",
    "/why/",
    "/quality/",
    "/nope-does-not-exist.html",
    "/robots.txt",
    "/sitemap.xml",
    "/metrics.json",
    "/favicon.svg",
    "/assets/site.css",
    "/press/limbo.csv",
    "/feed/all.zip",
    "/feed/index.json",
    "/feed/watchlist.json",
    "/feed/repos.txt",
    "/feed/limbo.atom",
    "/feed/critical.atom",
    "/tracker/data.json",
    "/check/index.json",
    "/osv/limbo-db.zip",
    "/osv/crc32c.map",
]


@dataclass
class Result:
    path: str
    problems: list[str] = field(default_factory=list)


def compare(path: str, old: httpx.Response, new: httpx.Response) -> list[str]:
    """What differs between the two hosts' answers for one path (pure: no requests)."""
    out: list[str] = []
    if old.status_code != new.status_code:
        out.append(f"status {old.status_code} vs {new.status_code}")
    if old.status_code == new.status_code == 200 and old.content != new.content:
        a, b = hashlib.sha256(old.content).hexdigest()[:12], hashlib.sha256(new.content).hexdigest()[:12]
        out.append(f"body {a} ({len(old.content)} B) vs {b} ({len(new.content)} B)")
    for h in COMPARED if old.status_code < 300 else SECURITY:
        if old.headers.get(h) != new.headers.get(h):
            out.append(f"{h}: {old.headers.get(h)!r} vs {new.headers.get(h)!r}")
    if old.is_redirect or new.is_redirect:
        lo, ln = urlsplit(old.headers.get("location", "")), urlsplit(new.headers.get("location", ""))
        if (lo.path, lo.query) != (ln.path, ln.query):
            out.append(f"location {old.headers.get('location')!r} vs {new.headers.get('location')!r}")
        if ln.scheme and ln.scheme != "https":
            out.append(f"redirect to {ln.scheme}://")
    return out


def client_checks(http: httpx.Client, base: str, path: str, got: httpx.Response) -> list[str]:
    """What watchers, OSV-Scanner and browsers rely on, on the new host."""
    out: list[str] = []
    if got.status_code != 200:
        return out
    etag = got.headers.get("etag")
    if path.endswith((".zip", ".json")) and etag:
        r = http.get(base + path, headers={"If-None-Match": etag})
        if r.status_code != 304:
            out.append(f"If-None-Match {etag} gave {r.status_code}, not 304")
    if path.endswith(".zip"):
        r = http.get(base + path, headers={"Range": "bytes=0-99"})
        if r.status_code != 206 or r.content != got.content[:100]:
            out.append(f"Range bytes=0-99 gave {r.status_code} with {len(r.content)} B")
    if path.startswith("/osv/") and path.endswith("/all.zip"):
        h = http.head(base + path).headers.get("x-goog-hash")
        if h != goog_hash(got.content):
            out.append(f"HEAD X-Goog-Hash {h!r}, body's CRC-32C is {goog_hash(got.content)!r}")
    return out


def paths(http: httpx.Client, base: str, sample: int, rng: random.Random) -> list[str]:
    ids = http.get(base + "/feed/index.json").json()["ids"]
    ecos = http.get(base + "/osv/ecosystems.txt").text.split()
    picked = rng.sample(ids, min(sample, len(ids)))
    return [
        *PAGES,
        *(f"/osv/{e}/all.zip" for e in ecos),
        *(f"/advisory/{g}/" for g in picked),
        *(f"/feed/{g}.json" for g in picked),
        f"/advisory/{picked[0]}" if picked else "/tracker",  # the slash redirect on a real page
    ]


def run(old: str, new: str, sample: int, seed: int, log: Any = print) -> int:
    rng = random.Random(seed)
    bad = 0
    with httpx.Client(timeout=120, follow_redirects=False, headers={"User-Agent": "limbowatch-check-hosting"}) as http:
        todo = paths(http, old, sample, rng)
        for p in todo:
            a, b = http.get(old + p), http.get(new + p)
            problems = compare(p, a, b) + client_checks(http, new, p, b)
            if problems:
                bad += 1
                log(f"DIFF {p}\n     " + "\n     ".join(problems))
        log(f"{len(todo)} paths, {bad} differ ({old} vs {new})")
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--old", default="https://limbo.watch")
    ap.add_argument("--new", default="https://next.limbo.watch")
    ap.add_argument("--sample", type=int, default=40, help="advisory pages and feed records to compare")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    return run(a.old.rstrip("/"), a.new.rstrip("/"), a.sample, a.seed)


if __name__ == "__main__":
    sys.exit(main())
