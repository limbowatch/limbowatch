"""scripts/sync_r2.py against an in-memory bucket: what it uploads, in which order, with which headers, and when it
refuses (docs/HOSTING_PLAN.md, step 3). No network, no boto3."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import re
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("sync_r2", ROOT / "scripts" / "sync_r2.py")
assert _spec and _spec.loader
sync = importlib.util.module_from_spec(_spec)
sys.modules["sync_r2"] = sync
_spec.loader.exec_module(sync)


class FakeBucket:
    def __init__(self, objects: dict[str, bytes] | None = None, page: int = 2) -> None:
        self.objects = dict(objects or {})
        self.meta: dict[str, dict[str, str]] = {}
        self.log: list[str] = []
        self.page = page

    def list_objects_v2(self, **kw: Any) -> dict[str, Any]:
        keys = sorted(self.objects)
        start = int(kw.get("ContinuationToken", 0))
        chunk = keys[start : start + self.page]
        out: dict[str, Any] = {
            "Contents": [{"Key": k, "ETag": f'"{hashlib.md5(self.objects[k]).hexdigest()}"'} for k in chunk]
        }
        if start + self.page < len(keys):
            out |= {"IsTruncated": True, "NextContinuationToken": str(start + self.page)}
        return out

    def put_object(self, **kw: Any) -> dict[str, Any]:
        assert kw["ContentMD5"] == base64.b64encode(hashlib.md5(kw["Body"]).digest()).decode()
        self.objects[kw["Key"]] = kw["Body"]
        self.meta[kw["Key"]] = {"ContentType": kw["ContentType"], "CacheControl": kw["CacheControl"]}
        self.log.append(kw["Key"])
        return {}

    def delete_objects(self, **kw: Any) -> dict[str, Any]:
        for o in kw["Delete"]["Objects"]:
            del self.objects[o["Key"]]
        return {}


def site(tmp: Path, files: dict[str, str]) -> Path:
    for k, v in files.items():
        (tmp / k).parent.mkdir(parents=True, exist_ok=True)
        (tmp / k).write_text(v)
    return tmp


FILES = {
    "index.html": "home",
    "tracker/index.html": "tracker",
    "press/limbo.csv": "a,b",
    "feed/all.zip": "zip",
    "feed/GHSA-a.json": "{}",
    "osv/PyPI/all.zip": "pypi",
    "osv/crc32c.map": "map",
}


def test_first_sync_uploads_everything_with_types_and_the_checksums_last(tmp_path: Path) -> None:
    root = site(tmp_path, FILES)
    b = FakeBucket()
    local = sync.scan(root)
    p = sync.plan(local, sync.remote_etags(b, "x"))
    out: list[str] = []
    sync.apply(b, "x", local, p, log=out.append)
    assert {k: v.decode() for k, v in b.objects.items()} == FILES
    assert b.log[-1] == "osv/crc32c.map"
    assert set(b.log[-3:-1]) == {"feed/all.zip", "osv/PyPI/all.zip"}
    assert b.meta["press/limbo.csv"] == {"ContentType": "text/csv; charset=utf-8", "CacheControl": "max-age=300"}
    assert b.meta["index.html"]["ContentType"] == "text/html"
    assert b.meta["osv/crc32c.map"]["ContentType"] == "application/octet-stream"
    assert out == ["r2: 7 uploaded, 0 deleted, 0 unchanged"]


def test_next_sync_uploads_only_what_changed_and_deletes_what_went(tmp_path: Path) -> None:
    root = site(tmp_path, FILES)
    b = FakeBucket({k: v.encode() for k, v in FILES.items()} | {"feed/GHSA-gone.json": b"{}"})
    (root / "tracker" / "index.html").write_text("tracker, updated")
    local = sync.scan(root)
    p = sync.plan(local, sync.remote_etags(b, "x"))
    assert p.put == ["tracker/index.html"] and p.delete == ["feed/GHSA-gone.json"] and p.unchanged == 6
    sync.apply(b, "x", local, p, log=lambda _: None)
    assert "feed/GHSA-gone.json" not in b.objects and b.objects["tracker/index.html"] == b"tracker, updated"
    assert sync.plan(local, sync.remote_etags(b, "x"), force=True).put == sorted(
        FILES, key=lambda k: (sync.last_rank(k), k)
    )


def test_refuses_to_delete_much_of_the_site(tmp_path: Path) -> None:
    remote = {f"advisory/GHSA-{i}/index.html": "x" for i in range(1000)}
    keep = lambda n: {k: sync.Local(Path(k), "x", 1) for k in list(remote)[n:]}  # noqa: E731
    with pytest.raises(sync.TooManyDeletes, match="21 of 1000 files would be deleted"):
        sync.plan(keep(21), remote)
    assert len(sync.plan(keep(20), remote).delete) == 20
    # a small bucket may always lose a few
    assert len(sync.plan(keep(10), dict(list(remote.items())[:12])).delete) == 10
    with pytest.raises(sync.TooManyDeletes, match="empty"):
        sync.plan({}, remote)


def test_a_multipart_etag_is_uploaded_again() -> None:
    local = {"feed/all.zip": sync.Local(Path("x"), hashlib.md5(b"z").hexdigest(), 1)}
    assert sync.plan(local, {"feed/all.zip": "abc-2"}).put == ["feed/all.zip"]


def test_types_match_the_worker() -> None:
    """The bucket serves most files and the Worker serves /osv/*; both must send nginx's types."""
    js = (ROOT / "deploy" / "worker" / "src" / "serve.js").read_text()
    block = js[js.index("const TYPES = {") : js.index("};", js.index("const TYPES = {"))]
    worker = dict(re.findall(r'^\s+(\w+): "([^"]+)"', block, re.M))
    assert worker == sync.TYPES
    assert sync.content_type("a.dir/noext") == "application/octet-stream"
    assert sync.content_type("FEED/ALL.ZIP") == "application/zip"


def test_main_dry_run_changes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    root = site(tmp_path / "site", FILES)
    b = FakeBucket({"feed/old.json": b"{}"})
    monkeypatch.setattr(sync, "client", lambda: b)
    monkeypatch.setenv("R2_BUCKET", "x")
    assert sync.main([str(root), "--dry-run"]) == 0
    assert capsys.readouterr().out.strip() == "r2 (dry run): would upload 7, delete 1; 0 unchanged"
    assert b.log == []
    assert sync.main([str(root)]) == 0
    assert set(b.objects) == set(FILES)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert sync.main([str(empty)]) == 1
    assert "refusing" in capsys.readouterr().err
