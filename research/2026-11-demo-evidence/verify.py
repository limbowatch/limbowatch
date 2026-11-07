"""Re-check the demo's 16 findings against primary sources (research/2026-11-demo-evidence).

For each line of findings.txt (GHSA, upstream repo, OSV ecosystem, package, installed version):
  - the repository advisory: state, published/withdrawn dates, severity, cited CVE, ranges and fixes for the package
    (GET /repos/{repo}/security-advisories/{ghsa}, via `gh api`)
  - GitHub's reviewed database by ID (GET /advisories/{ghsa}) and by the cited CVE
  - OSV by ID (GET /v1/vulns/{ghsa}) and by package and version (POST /v1/query)
  - days since the maintainer published it

Writes evidence.json: facts only, no advisory text or personal data. Needs `gh` (logged in) and the network.

    python3 verify.py
"""

from __future__ import annotations

import datetime
import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent


def gh(path: str) -> Any:
    r = subprocess.run(["gh", "api", "-X", "GET", path], capture_output=True, text=True, check=False)
    return json.loads(r.stdout) if r.returncode == 0 else None


def osv(method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
    req = urllib.request.Request(f"https://api.osv.dev{path}", method=method,
                                 data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json"})  # fmt: skip
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, None


def main() -> None:
    now = datetime.datetime.now(datetime.UTC)
    rows = []
    for line in (HERE / "findings.txt").read_text().splitlines():
        ghsa, repo, eco, name, version = line.split()
        row: dict[str, Any] = {"ghsa": ghsa, "repo": repo, "ecosystem": eco, "package": name, "version": version}
        adv = gh(f"/repos/{repo}/security-advisories/{ghsa}")
        if adv is None:
            row["error"] = "repository advisory not readable"
            rows.append(row)
            continue
        vulns = [v for v in adv.get("vulnerabilities") or [] if (v.get("package") or {}).get("name") == name]
        published = datetime.datetime.fromisoformat(adv["published_at"].replace("Z", "+00:00"))
        cve = adv.get("cve_id")
        osv_id, _ = osv("GET", f"/v1/vulns/{ghsa}")
        _, q = osv("POST", "/v1/query", {"package": {"ecosystem": eco, "name": name}, "version": version})
        row |= {
            "state": adv.get("state"),
            "withdrawn_at": adv.get("withdrawn_at"),
            "published_at": adv["published_at"],
            "days_in_limbo": round((now - published).total_seconds() / 86400, 1),
            "severity": adv.get("severity"),
            "cve": cve,
            "ranges": [v.get("vulnerable_version_range") for v in vulns],
            "fixed": [v.get("patched_versions") for v in vulns],
            "github_reviewed_by_id": gh(f"/advisories/{ghsa}") is not None,
            "github_reviewed_by_cve": [a["ghsa_id"] for a in gh(f"/advisories?type=reviewed&cve_id={cve}") or []] if cve else [],
            "osv_by_id": osv_id,
            "osv_by_package_version": [v["id"] for v in (q or {}).get("vulns", [])],
        }
        rows.append(row)
    in_limbo = [r for r in rows if r.get("state") == "published" and not r.get("withdrawn_at")
                and not r.get("github_reviewed_by_id") and not r.get("github_reviewed_by_cve")
                and r.get("osv_by_id") == 404 and not r.get("osv_by_package_version")]  # fmt: skip
    doc = {"checked_at": now.isoformat(timespec="seconds"), "in_limbo": len(in_limbo), "total": len(rows), "findings": rows,
           "attribution": "GitHub repository security advisories and the GitHub Advisory Database (CC BY 4.0); OSV.dev"}  # fmt: skip
    (HERE / "evidence.json").write_text(json.dumps(doc, indent=1) + "\n")
    print(f"{len(in_limbo)} of {len(rows)} still in limbo at {doc['checked_at']}")


if __name__ == "__main__":
    main()
