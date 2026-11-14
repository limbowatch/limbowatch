"""Apply the zone rules in deploy/cloudflare/rules.json (docs/HOSTING_PLAN.md, step 3).

    CLOUDFLARE_API_TOKEN=… uv run python scripts/cf_rules.py --zone limbo.watch --host next.limbo.watch [--dry-run]
    … --host limbo.watch --host next.limbo.watch --www www.limbo.watch           # at the switch (step 5)

Run from a maintainer's machine, not CI: the token needs Zone Read, Transform Rules Edit, Single Redirect Edit,
Cache Rules Edit and Workers Routes Edit on the zone, and Account Rulesets Read. Only rules whose `ref` starts with
`limbowatch-` are managed; the zone's other rules are kept as they are. A phase is written only when its managed rules
differ, so a second run changes nothing. The Worker's routes are set to fail open. The token comes from the
environment and is never printed.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

API = "https://api.cloudflare.com/client/v4"
RULES = Path(__file__).resolve().parents[1] / "deploy" / "cloudflare" / "rules.json"
PREFIX = "limbowatch-"
WORKER = "limbowatch-site"  # deploy/worker/wrangler.jsonc
COMPARED = ("expression", "action", "action_parameters", "description", "enabled")
READ_ONLY = ("version", "last_updated")


def host_set(hosts: list[str]) -> str:
    return "{" + " ".join(json.dumps(h) for h in hosts) + "}"


def desired(spec: dict[str, Any], hosts: list[str], www: list[str]) -> dict[str, list[dict[str, Any]]]:
    """The managed rules per phase, with the hostnames filled in. The www rule is left out when there's no www host."""
    out: dict[str, list[dict[str, Any]]] = {}
    for phase, rules in spec.items():
        if phase.startswith("_"):
            continue
        out[phase] = []
        for r in rules:
            if "$WWW" in r["expression"] and not www:
                continue
            r = copy.deepcopy(r)
            r["expression"] = r["expression"].replace("$HOSTS", host_set(hosts)).replace("$WWW", host_set(www))
            r.setdefault("enabled", True)
            assert r["ref"].startswith(PREFIX), r["ref"]
            out[phase].append(r)
    return out


def merge(existing: list[dict[str, Any]], ours: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    """The phase's new rule list: the zone's own rules as they are, then ours. None when ours are already there."""
    theirs = [r for r in existing if not str(r.get("ref", "")).startswith(PREFIX)]
    current = [r for r in existing if str(r.get("ref", "")).startswith(PREFIX)]

    def key(r: dict[str, Any]) -> tuple[Any, ...]:
        return (r["ref"], *(json.dumps(r.get(f), sort_keys=True) for f in COMPARED))

    if [key(r) for r in current] == [key(r) for r in ours]:
        return None
    return [{k: v for k, v in r.items() if k not in READ_ONLY} for r in theirs] + ours


class Cloudflare:
    def __init__(self, token: str, client: httpx.Client | None = None) -> None:
        self.http = client or httpx.Client(timeout=30)
        self.headers = {"Authorization": f"Bearer {token}"}

    def _call(self, method: str, path: str, **kw: Any) -> Any:
        r = self.http.request(method, API + path, headers=self.headers, **kw)
        body = r.json()
        if not body.get("success"):
            raise RuntimeError(f"{method} {path}: HTTP {r.status_code}: {body.get('errors')}")
        return body["result"]

    def zone_id(self, name: str) -> str:
        zones = self._call("GET", "/zones", params={"name": name})
        if len(zones) != 1:
            raise RuntimeError(f"zone {name}: {len(zones)} found; does the token have Zone Read on it?")
        return str(zones[0]["id"])

    def phase_rules(self, zone: str, phase: str) -> list[dict[str, Any]]:
        r = self.http.get(f"{API}/zones/{zone}/rulesets/phases/{phase}/entrypoint", headers=self.headers)
        if r.status_code == 404:  # no rules in this phase yet
            return []
        body = r.json()
        if not body.get("success"):
            raise RuntimeError(f"GET {phase}: HTTP {r.status_code}: {body.get('errors')}")
        return list(body["result"].get("rules") or [])

    def put_phase(self, zone: str, phase: str, rules: list[dict[str, Any]]) -> None:
        self._call("PUT", f"/zones/{zone}/rulesets/phases/{phase}/entrypoint", json={"rules": rules})

    def routes(self, zone: str) -> list[dict[str, Any]]:
        return list(self._call("GET", f"/zones/{zone}/workers/routes"))

    def fail_open(self, zone: str, route: dict[str, Any]) -> None:
        body = {"pattern": route["pattern"], "script": route["script"], "request_limit_fail_open": True}
        self._call("PUT", f"/zones/{zone}/workers/routes/{route['id']}", json=body)


def run(cf: Cloudflare, zone_name: str, hosts: list[str], www: list[str], dry_run: bool, log: Any = print) -> int:
    spec = json.loads(RULES.read_text())
    zone = cf.zone_id(zone_name)
    changed = 0
    for phase, ours in desired(spec, hosts, www).items():
        existing = cf.phase_rules(zone, phase)
        new = merge(existing, ours)
        if new is None:
            log(f"{phase}: up to date")
            continue
        changed += 1
        refs = ", ".join(r["ref"] for r in ours) or "(none)"
        kept = len(new) - len(ours)
        log(f"{phase}: {'would set' if dry_run else 'set'} {refs}; {kept} other rule(s) kept")
        if not dry_run:
            cf.put_phase(zone, phase, new)
    # A route wrangler creates fails closed: past the free daily limit its requests would get error 1027. The
    # Worker's routes fail open instead, so R2 answers without X-Goog-Hash (F-183). The dashboard isn't needed.
    for r in cf.routes(zone):
        if r.get("script") != WORKER or r.get("request_limit_fail_open"):
            continue
        changed += 1
        log(f"route {r['pattern']}: {'would set' if dry_run else 'set'} fail open")
        if not dry_run:
            cf.fail_open(zone, r)
    return changed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--zone", required=True, help="the zone's name, e.g. limbo.watch")
    ap.add_argument("--host", action="append", required=True, help="a hostname served from R2; repeatable")
    ap.add_argument("--www", action="append", default=[], help="a www hostname that redirects to its apex")
    ap.add_argument("--dry-run", action="store_true", help="show what would change; change nothing")
    a = ap.parse_args(argv)
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        print("CLOUDFLARE_API_TOKEN is not set", file=sys.stderr)
        return 2
    bad = [w for w in a.www if not w.startswith("www.")]
    if bad:
        print(f"--www takes www hostnames: {bad}", file=sys.stderr)
        return 2
    run(Cloudflare(token), a.zone, a.host, a.www, a.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
