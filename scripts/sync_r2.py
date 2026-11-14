"""Upload the built site to the R2 bucket that serves limbo.watch (docs/HOSTING_PLAN.md, step 3).

    R2_ACCESS_KEY_ID=… R2_SECRET_ACCESS_KEY=… CF_ACCOUNT_ID=… R2_BUCKET=limbowatch-site \\
      python scripts/sync_r2.py deploy/site/public [--dry-run] [--force]

in a venv with deploy/cloudflare/requirements.txt (`uv pip install --require-hashes -r …`), as site.yml does.

R2 serves each file as stored, so each upload sets the `Content-Type` nginx would have sent and `Cache-Control:
max-age=300`. Only files whose MD5 differs from the bucket's ETag are uploaded (about 3,100 a day, FINDINGS F-178);
the feed zips, then `osv/crc32c.map`, go last, so the checksums never describe zips that aren't there yet. Files gone
from the build are deleted afterwards, but never more than 2% of the bucket: a broken build can't wipe the
site. Credentials come from the environment and are never printed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import sys
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

CACHE_CONTROL = "max-age=300"  # the data changes once a day (nginx: `expires 5m`)
MAX_DELETE = 0.02  # of the bucket's files…
MAX_DELETE_FLOOR = 10  # …but a few deletions are always allowed, for a small bucket
WORKERS = 32

# The types nginx sends for the site's files, as in deploy/worker/src/serve.js (tests check they agree)
TYPES = {
    "html": "text/html",
    "css": "text/css",
    "js": "application/javascript",
    "json": "application/json",
    "xml": "text/xml",
    "atom": "application/atom+xml",
    "txt": "text/plain",
    "csv": "text/csv; charset=utf-8",
    "svg": "image/svg+xml",
    "png": "image/png",
    "jpg": "image/jpeg",
    "webp": "image/webp",
    "ico": "image/x-icon",
    "zip": "application/zip",
}


def content_type(key: str) -> str:
    name = key.rsplit("/", 1)[-1]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return TYPES.get(ext, "application/octet-stream")


def last_rank(key: str) -> int:
    """Upload order: everything else (0), then the zips (1), then the checksums that describe them (2)."""
    if key == "osv/crc32c.map":
        return 2
    return 1 if key.endswith(".zip") else 0


@dataclass(frozen=True)
class Local:
    path: Path
    md5: str
    size: int


def scan(root: Path) -> dict[str, Local]:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            data = p.read_bytes()
            out[p.relative_to(root).as_posix()] = Local(p, hashlib.md5(data).hexdigest(), len(data))
    return out


class Bucket(Protocol):
    """The S3 calls used, as boto3's client makes them (and tests fake them)."""

    def list_objects_v2(self, **kw: Any) -> dict[str, Any]: ...
    def put_object(self, **kw: Any) -> dict[str, Any]: ...
    def delete_objects(self, **kw: Any) -> dict[str, Any]: ...


def remote_etags(s3: Bucket, bucket: str) -> dict[str, str]:
    """Key → ETag without quotes. A multipart upload's ETag (with `-`) never equals an MD5, so it's re-uploaded."""
    out: dict[str, str] = {}
    kw: dict[str, Any] = {"Bucket": bucket}
    while True:
        page = s3.list_objects_v2(**kw)
        for o in page.get("Contents", []):
            out[o["Key"]] = o["ETag"].strip('"')
        if not page.get("IsTruncated"):
            return out
        kw["ContinuationToken"] = page["NextContinuationToken"]


@dataclass(frozen=True)
class Plan:
    put: list[str]
    delete: list[str]
    unchanged: int


class TooManyDeletes(Exception):
    pass


def plan(local: dict[str, Local], remote: dict[str, str], *, force: bool = False) -> Plan:
    if not local:
        raise TooManyDeletes("the build is empty; refusing to sync it")
    put = sorted((k for k, f in local.items() if force or remote.get(k) != f.md5), key=lambda k: (last_rank(k), k))
    delete = sorted(k for k in remote if k not in local)
    if len(delete) > max(MAX_DELETE * len(remote), MAX_DELETE_FLOOR):
        raise TooManyDeletes(
            f"{len(delete)} of {len(remote)} files would be deleted (more than {MAX_DELETE:.0%}); "
            "is the build complete? Nothing was changed."
        )
    return Plan(put, delete, len(local) - len(put))


def apply(s3: Bucket, bucket: str, local: dict[str, Local], p: Plan, log: Callable[[str], None] = print) -> None:
    def upload(key: str) -> None:
        f = local[key]
        body = f.path.read_bytes()
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType=content_type(key),
            CacheControl=CACHE_CONTROL,
            ContentMD5=base64.b64encode(hashlib.md5(body).digest()).decode(),  # R2 rejects a corrupted upload
        )

    # each rank finishes before the next starts, so the zips land after the pages and the checksums after the zips
    for rank in (0, 1, 2):
        batch = [k for k in p.put if last_rank(k) == rank]
        with ThreadPoolExecutor(WORKERS) as pool:
            list(pool.map(upload, batch))
    for chunk in _chunks(p.delete, 1000):
        r = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": k} for k in chunk], "Quiet": True})
        if r.get("Errors"):
            raise RuntimeError(f"delete failed for {len(r['Errors'])} keys, e.g. {r['Errors'][0].get('Key')}")
    log(f"r2: {len(p.put)} uploaded, {len(p.delete)} deleted, {p.unchanged} unchanged")


def _chunks(items: list[str], n: int) -> Iterable[list[str]]:
    for i in range(0, len(items), n):
        yield items[i : i + n]


def client() -> Any:
    import boto3  # type: ignore[import-not-found]  # only here: the tests don't need it

    env = os.environ
    return boto3.client(
        "s3",
        endpoint_url=f"https://{env['CF_ACCOUNT_ID']}.r2.cloudflarestorage.com",
        aws_access_key_id=env["R2_ACCESS_KEY_ID"],
        aws_secret_access_key=env["R2_SECRET_ACCESS_KEY"],
        region_name="auto",
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("site", type=Path, help="the output of `limbowatch publish`")
    ap.add_argument("--dry-run", action="store_true", help="count what would change; change nothing")
    ap.add_argument("--force", action="store_true", help="upload every file (after a change to TYPES)")
    a = ap.parse_args(argv)
    bucket = os.environ["R2_BUCKET"]
    s3 = client()
    local = scan(a.site)
    try:
        p = plan(local, remote_etags(s3, bucket), force=a.force)
    except TooManyDeletes as e:
        print(f"r2: {e}", file=sys.stderr)
        return 1
    if a.dry_run:
        print(f"r2 (dry run): would upload {len(p.put)}, delete {len(p.delete)}; {p.unchanged} unchanged")
        return 0
    apply(s3, bucket, local, p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
