"""Shared helpers for the State of the Gap research pipeline.

- Disk-cached async HTTP with retries, Retry-After / X-RateLimit awareness.
- GitHub token from GITHUB_TOKEN or `gh auth token`; never printed or cached.
- Maintainer-entered version ranges, via limbowatch.versions (FINDINGS F-030, F-123).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

# Maintainer ranges are read by the tracker's own parser, so the research and limbo.watch agree on every range
# (FINDINGS F-123). The October snapshots were first produced with an earlier copy of it; stage 4 was rerun on
# 2026-11-10 from its cache.
from limbowatch.versions import VERSION_CLASS, affected, already_fixed  # noqa: F401  (re-exported for s4)

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache"
DATA = ROOT / "data"
SNAPSHOT = os.environ.get("SNAPSHOT_DATE", time.strftime("%Y-%m-%d"))
TIME_VARYING_HOSTS = ("api.github.com", "api.osv.dev", "cveawg.mitre.org", "services.nvd.nist.gov")
UA = "limbowatch-research (+https://github.com/limbowatch/limbowatch)"

# osv-scanner ecosystem name -> (GHSA ecosystem, deps.dev system, OSV ecosystem)
ECOSYSTEMS: dict[str, tuple[str, str | None, str]] = {
    "npm": ("npm", "npm", "npm"),
    "PyPI": ("pip", "pypi", "PyPI"),
    "Go": ("go", "go", "Go"),
    "crates.io": ("rust", "cargo", "crates.io"),
    "Packagist": ("composer", None, "Packagist"),
    "RubyGems": ("rubygems", "rubygems", "RubyGems"),
    "Maven": ("maven", "maven", "Maven"),
    "NuGet": ("nuget", "nuget", "NuGet"),
}


def log(*args: Any) -> None:
    print(*args, file=sys.stderr, flush=True)


def github_token() -> str | None:
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        return tok
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True)
        return out.stdout.strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=1, default=str, sort_keys=True))
    tmp.replace(path)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


class NotCached(SystemExit):
    """OFFLINE=1 and the response isn't in the snapshot's cache."""


class Http:
    """Async client with an on-disk response cache (body + status + selected headers)."""

    def __init__(self, concurrency: int = 16, refresh: bool | None = None) -> None:
        self.sem = asyncio.Semaphore(concurrency)
        self.refresh = os.environ.get("REFRESH") == "1" if refresh is None else refresh
        self.client = httpx.AsyncClient(timeout=60, follow_redirects=True, headers={"User-Agent": UA})
        self.token = github_token()
        self.stats: dict[str, int] = {}
        self._gh_lock = asyncio.Lock()

    async def close(self) -> None:
        await self.client.aclose()

    def _cache_path(self, method: str, url: str, body: Any) -> Path:
        # Time-varying sources are cached per snapshot so snapshots can't contaminate each other
        # (an Oct 22 refresh must never leak into an Oct 21 snapshot). deps.dev mappings are stable.
        key = hashlib.sha256(json.dumps([method, url, body], sort_keys=True).encode()).hexdigest()
        ns = SNAPSHOT if any(h in url for h in TIME_VARYING_HOSTS) else "shared"
        if os.environ.get("HTTP_CACHE_NS") == "flat":
            # the layout before per-snapshot caching: the 2026-10-22-offgithub snapshot was measured with it
            return CACHE / "http" / key[:2] / f"{key}.json"
        return CACHE / "http" / ns / key[:2] / f"{key}.json"

    async def request(self, method: str, url: str, json_body: Any = None, use_cache: bool = True) -> tuple[int, Any, dict[str, str]]:
        cp = self._cache_path(method, url, json_body)
        if use_cache and not self.refresh and cp.exists():
            c = load_json(cp)
            self.stats["cache_hit"] = self.stats.get("cache_hit", 0) + 1
            return c["status"], c["body"], c["headers"]
        if os.environ.get("OFFLINE") == "1":
            # OFFLINE=1: rerun a stage from its cache only. A miss would mix today's data into an old snapshot.
            raise NotCached(f"OFFLINE=1 and not cached: {method} {url[:120]}")
        headers: dict[str, str] = {}
        is_gh = url.startswith("https://api.github.com/")
        if is_gh:
            headers["Accept"] = "application/vnd.github+json"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
        if url.startswith("https://services.nvd.nist.gov/") and os.environ.get("NVD_API_KEY"):
            headers["apiKey"] = os.environ["NVD_API_KEY"]
        async with self.sem:
            for attempt in range(6):
                try:
                    r = await self.client.request(method, url, json=json_body, headers=headers)
                except httpx.HTTPError as e:
                    log(f"  retry {attempt + 1} {type(e).__name__} {url[:90]}")
                    await asyncio.sleep(min(60, 2**attempt))
                    continue
                if is_gh and r.status_code in (403, 429) and r.headers.get("x-ratelimit-remaining") == "0":
                    await self._wait_reset(r)
                    continue
                if r.status_code in (403, 429) and "retry-after" in r.headers:
                    await asyncio.sleep(int(r.headers["retry-after"]) + 1)
                    continue
                if r.status_code in (429, 500, 502, 503, 504):
                    await asyncio.sleep(min(60, 2 ** (attempt + 1)))
                    continue
                break
            else:
                self.stats["failed"] = self.stats.get("failed", 0) + 1
                return -1, None, {}
        self.stats[r.url.host] = self.stats.get(r.url.host, 0) + 1
        if is_gh and int(r.headers.get("x-ratelimit-remaining", "1000")) < 25:
            await self._wait_reset(r)
        try:
            body = r.json()
        except ValueError:
            body = r.text
        keep = {k: r.headers[k] for k in ("link", "etag", "x-ratelimit-remaining") if k in r.headers}
        if use_cache and r.status_code in (200, 404):
            save_json(cp, {"status": r.status_code, "body": body, "headers": keep, "fetched_at": time.time(), "url": url})
        return r.status_code, body, keep

    async def _wait_reset(self, r: httpx.Response) -> None:
        async with self._gh_lock:
            reset = int(r.headers.get("x-ratelimit-reset", time.time() + 60))
            wait = max(5, reset - int(time.time()) + 5)
            log(f"  GitHub rate limit low; sleeping {wait}s until reset")
            await asyncio.sleep(wait)

    async def get(self, url: str, use_cache: bool = True) -> tuple[int, Any, dict[str, str]]:
        return await self.request("GET", url, use_cache=use_cache)

    async def gh_paginate(self, url: str, max_pages: int = 100) -> list[Any]:
        out: list[Any] = []
        for _ in range(max_pages):
            status, body, headers = await self.get(url)
            if status != 200 or not isinstance(body, list):
                break
            out += body
            m = re.search(r'<([^>]+)>;\s*rel="next"', headers.get("link", ""))
            if not m:
                break
            url = m.group(1)
        return out


# ---------------------------------------------------------------- names


def norm_name(ghsa_ecosystem: str, name: str) -> str:
    if ghsa_ecosystem == "pip":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ghsa_ecosystem in ("npm", "rust", "composer"):
        return name.lower()
    return name


def go_relation(advisory_path: str, module: str) -> str | None:
    """How a Go advisory's package path relates to a dependency module (strict module semantics).

    "same" / "package_in_module" match. A "/vN" suffix is a different module (Go major-version
    rule): "major_version_variant" means the paths differ only by that, which maintainers often
    mislabel - reported as unknown, never as affected (F-052).
    """
    a, d = advisory_path, module
    if a == d:
        return "same"
    for longer, shorter in ((a, d), (d, a)):
        if longer.startswith(shorter + "/"):
            first = longer[len(shorter) + 1:].split("/")[0]
            if re.fullmatch(r"v\d+", first):
                return "major_version_variant"
            return "package_in_module" if longer is a else None  # nested module of a different path
    return None


def name_matches(ghsa_ecosystem: str, advisory_name: str, dep_name: str) -> bool | str:
    """True for a match; for Go, the go_relation() string; False otherwise."""
    a, d = norm_name(ghsa_ecosystem, advisory_name), norm_name(ghsa_ecosystem, dep_name)
    if ghsa_ecosystem == "go":
        return go_relation(a, d) or False
    return a == d


if __name__ == "__main__":  # quick self-check of the range parser
    cases = [
        ("npm", "1.5.0", ">= 1.0.0, < 1.2.3", False),
        ("npm", "1.1.0", ">= 1.0.0, < 1.2.3", True),
        ("npm", "6.0.0", ">=5.0.0-beta.0 <7.1.0", True),
        ("npm", "8.0.0-beta.1", "8.0.0-alpha.0 - 8.0.0-rc.5", True),
        ("npm", "1.20.0", "=>0.31.1", True),
        ("pip", "1.4.0", ">=1.3.3 and <= 1.4.1", True),
        ("pip", "1.7.4", "1.7.4", True),
        ("npm", "1.2.9", "^1.2.3", True),
        ("npm", "2.0.0", "^1.2.3", False),
        ("npm", "3.0.1", "<2.0.0 || >=3.0.0 <3.0.2", True),
        ("go", "v5.3.2", "<=5.4.0", True),
        ("pip", "0.0.29", ">= 0.0.1a9, < 0.0.84", True),
        ("pip", "12.3.0", "≤ 12.2.0", False),
        ("pip", "0.14.0", "0.15.0 and earlier", True),
        ("npm", "6.28.0", "< 6.24.0; 7.0.0 < 7.24.0", False),
        ("npm", "7.10.0", "< 6.24.0; 7.0.0 < 7.24.0", True),
        ("npm", "5.0.6", "<1.1.17, >= 2.0.0 < 2.1.3, >= 3.0.0 < 3.0.3, 4.0.0 - 5.0.7", True),
        ("npm", "3.5.0", "<1.1.17, >= 2.0.0 < 2.1.3, >= 3.0.0 < 3.0.3, 4.0.0 - 5.0.7", False),
        ("npm", "6.28.0", ">= 7.0.0, < 7.29.0; >= 8.0.0, < 8.9.0", False),
        ("pip", "2.13.4", "all", True),  # "all" means every version (the tracker's rule)
        ("npm", "1.5.4", "< 1.0.0, >= 1.5.5, < 1.6.10", False),  # F-123: commas as OR keep intervals whole
        ("go", "2.2.12", ">= 2.2.0, < 2.2.10, >= 2.3.0, < 2.3.7", False),
        ("npm", "3.8.8", ">= 3.8.8, <= 3.8.8", True),
        ("composer", "6.7.13.0", ">=6.7.0.0 <6.7.13.1", True),
        ("composer", "11.2.0", "<10.4.57, 11.0.0-11.5.50", True),
    ]
    bad = [(c, affected(*c[:3])) for c in cases if affected(*c[:3]) is not c[3]]
    fixes = [("rust", "0.11.19", "0.11.17", True), ("go", "v4.1.4", "v4.1.4", True), ("rust", "2.3.0", "<= 2.3.0", None),
             ("npm", "0.27.10", "0.24.52 0.25.25 0.26.9 0.27.12 0.28.22", False), ("npm", "0.27.13", "0.26.9 0.27.12", True),
             ("pip", "3.1.50", ">= 3.2.0", False), ("npm", "1.0.0", None, None)]
    bad += [(c, already_fixed(*c[:3])) for c in fixes if already_fixed(*c[:3]) is not c[3]]
    go = [("github.com/pelletier/go-toml/v2", "github.com/pelletier/go-toml", "major_version_variant"),
          ("github.com/dlclark/regexp2", "github.com/dlclark/regexp2/v2", "major_version_variant"),
          ("github.com/foo/bar/pkg/x", "github.com/foo/bar", "package_in_module"),
          ("github.com/foo/bar", "github.com/foo/bar", "same"), ("github.com/foo/bar", "github.com/foo/bar/sdk", None)]
    bad += [(c, go_relation(c[0], c[1])) for c in go if go_relation(c[0], c[1]) != c[2]]
    print("range parser self-check:", "OK" if not bad else f"FAIL {bad}")
