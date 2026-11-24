"""OSV.dev: is an advisory present (imported) yet? Per ID from the API, or all at once from the bucket's listing."""

from __future__ import annotations

import re

from limbowatch.http import HttpClient, ResponseTooLarge

API = "https://api.osv.dev/v1"
# Every OSV record, one `<modified>,<Ecosystem>/<ID>` line each: 166 MB, 2.9 million lines on 2026-11-24 (F-231)
LISTING = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
LISTING_MAX_BYTES = 1 << 30
# 38,049 GHSA IDs on 2026-11-24 (F-231). Fewer than this means a broken listing, and reading it would put advisories
# OSV has in limbo.
LISTING_MIN_GHSA = 20_000
_GHSA_LINE = re.compile(rb"/(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})$", re.M)


async def present(http: HttpClient, vuln_id: str) -> bool | None:
    r = await http.get(f"{API}/vulns/{vuln_id}")
    if r.status == 200:
        return True
    if r.status == 404:
        return False
    return None


async def ghsa_ids(http: HttpClient) -> set[str] | None:
    """Every GHSA ID OSV has, from the bucket's listing of all records: one download instead of a `present` request
    per advisory. It agreed with `present` on 408 of 408 sampled IDs and is at most an hour behind it (F-231). None
    when it can't be read or looks incomplete."""
    try:
        r = await http.get(LISTING, raw=True, max_bytes=LISTING_MAX_BYTES)
    except ResponseTooLarge:
        return None
    if not r.ok or not isinstance(r.body, bytes):
        return None
    ids = {m.decode() for m in _GHSA_LINE.findall(r.body)}
    return ids if len(ids) >= LISTING_MIN_GHSA else None


async def affecting(http: HttpClient, ecosystem: str, name: str, version: str) -> set[str] | None:
    """IDs and aliases of every OSV record that affects this package version, or None on error."""
    query = {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
    r = await http.get(f"{API}/query", json_body=query)
    if not r.ok or not isinstance(r.body, dict):
        return None
    return {i for v in r.body.get("vulns") or [] for i in [v.get("id", ""), *(v.get("aliases") or [])] if i}


async def by_commit(http: HttpClient, commits: list[str]) -> dict[str, set[str]] | None:
    """OSV IDs whose GIT ranges include each commit (`/v1/querybatch` with `{"commit": …}`; OSV evaluates the ranges
    on its side, F-136). None when OSV didn't answer."""
    out: dict[str, set[str]] = {}
    for i in range(0, len(commits), 1000):
        chunk = commits[i : i + 1000]
        r = await http.get(f"{API}/querybatch", json_body={"queries": [{"commit": c} for c in chunk]})
        if not r.ok or not isinstance(r.body, dict) or len(r.body.get("results") or []) != len(chunk):
            return None
        for c, res in zip(chunk, r.body["results"], strict=True):
            out[c] = {v["id"] for v in (res or {}).get("vulns") or [] if v.get("id")}
    return out
