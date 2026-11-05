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
