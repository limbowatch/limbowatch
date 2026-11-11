"""OSV.dev: is an advisory present (imported) yet?"""

from __future__ import annotations

from limbowatch.http import HttpClient

API = "https://api.osv.dev/v1"


async def present(http: HttpClient, vuln_id: str) -> bool | None:
    r = await http.get(f"{API}/vulns/{vuln_id}")
    if r.status == 200:
        return True
    if r.status == 404:
        return False
    return None


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
