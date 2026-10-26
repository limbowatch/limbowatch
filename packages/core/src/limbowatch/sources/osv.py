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
