"""NVD API 2.0: status and enrichment of a CVE. Paced inside HttpClient (5 req / 30 s without a key)."""

from __future__ import annotations

from dataclasses import dataclass

from limbowatch.http import HttpClient

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class NvdStatus:
    status: str  # vulnStatus as given (Received, Awaiting Analysis, Deferred, ...) or "absent"
    enriched: bool  # NIST Primary CVSS or CPE configurations present (FINDINGS F-005)


async def status(http: HttpClient, cve_id: str) -> NvdStatus | None:
    r = await http.get(f"{API}?cveId={cve_id}")
    if r.status not in (200, 404):
        return None
    vulns = r.body.get("vulnerabilities") if isinstance(r.body, dict) else None
    if not vulns:
        return NvdStatus("absent", False)
    cve = vulns[0]["cve"]
    primary = any(
        m.get("type") == "Primary" for k, ms in (cve.get("metrics") or {}).items() if k.startswith("cvss") for m in ms
    )
    return NvdStatus(cve.get("vulnStatus") or "unknown", primary or bool(cve.get("configurations")))
