"""scripts/cf_rules.py and deploy/cloudflare/rules.json against a mocked Cloudflare API (docs/HOSTING_PLAN.md,
step 3): the zone's other rules are kept, a second run changes nothing, and the headers are nginx's. No network."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("cf_rules", ROOT / "scripts" / "cf_rules.py")
assert _spec and _spec.loader
cf_rules = importlib.util.module_from_spec(_spec)
sys.modules["cf_rules"] = cf_rules
_spec.loader.exec_module(cf_rules)

API = cf_rules.API
ZONE = "z0"
PHASES = [
    "http_request_dynamic_redirect",
    "http_request_transform",
    "http_response_headers_transform",
    "http_request_cache_settings",
]


def spec() -> dict[str, Any]:
    return json.loads(cf_rules.RULES.read_text())


def test_hostnames_are_filled_in_and_www_is_optional() -> None:
    d = cf_rules.desired(spec(), ["next.limbo.watch"], [])
    assert set(d) == set(PHASES)
    assert [r["ref"] for r in d["http_request_dynamic_redirect"]] == ["limbowatch-slash"]
    assert all("$" not in r["expression"] for rules in d.values() for r in rules)
    assert d["http_request_transform"][0]["expression"].startswith('http.host in {"next.limbo.watch"} and ')
    d = cf_rules.desired(spec(), ["limbo.watch", "next.limbo.watch"], ["www.limbo.watch"])
    www = d["http_request_dynamic_redirect"][0]
    assert www["ref"] == "limbowatch-www" and www["expression"] == 'http.host in {"www.limbo.watch"}'
    assert d["http_request_cache_settings"][0]["expression"] == 'http.host in {"limbo.watch" "next.limbo.watch"}'


def test_security_headers_are_the_workers_and_nginxs() -> None:
    """The zone sets them on what R2 serves, the Worker on /osv/*: the same values, as nginx sent them (F-179)."""
    js = (ROOT / "deploy" / "worker" / "src" / "serve.js").read_text()
    csp = "".join(re.findall(r'"([^"]*)"', js[js.index("const CSP =") : js.index(";\n", js.index("const CSP ="))]))
    block = js[js.index("export const SECURITY_HEADERS") : js.index("};", js.index("export const SECURITY_HEADERS"))]
    worker = dict(re.findall(r'^\s+"([\w-]+)": "([^"]+)"', block, re.M)) | {"Content-Security-Policy": csp}
    (sec,) = [r for r in spec()["http_response_headers_transform"] if r["ref"] == "limbowatch-security"]
    zone = {k: v["value"] for k, v in sec["action_parameters"]["headers"].items()}
    assert zone == worker


def test_merge_keeps_the_zones_own_rules_and_is_idempotent() -> None:
    ours = cf_rules.desired(spec(), ["next.limbo.watch"], [])["http_request_transform"]
    theirs = {"id": "t1", "ref": "someone-else", "expression": "true", "action": "rewrite", "version": "3"}
    new = cf_rules.merge([theirs], ours)
    assert new is not None
    assert new[0] == {k: v for k, v in theirs.items() if k != "version"} and new[1:] == ours
    # what the API returns after the write: ours with ids and versions added
    stored = [theirs] + [r | {"id": "x", "version": "1", "last_updated": "now"} for r in ours]
    assert cf_rules.merge(stored, ours) is None
    changed = [r | {"expression": "false"} for r in ours]
    assert cf_rules.merge([theirs, *changed], ours) == new


def apply(dry_run: bool = False, log: Any = print) -> int:
    cf = cf_rules.Cloudflare("t", httpx.Client())
    return int(cf_rules.run(cf, "limbo.watch", ["next.limbo.watch"], [], dry_run, log))


def mock(
    router: respx.MockRouter, existing: dict[str, list[dict[str, Any]]], routes: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    puts: dict[str, Any] = {}
    router.get(f"{API}/zones/{ZONE}/workers/routes").mock(
        return_value=httpx.Response(200, json={"success": True, "result": routes or []})
    )

    def put_route(request: httpx.Request) -> httpx.Response:
        puts[request.url.path.rsplit("/", 1)[-1]] = json.loads(request.content)
        return httpx.Response(200, json={"success": True, "result": {}})

    router.put(url__regex=rf"{API}/zones/{ZONE}/workers/routes/.+").mock(side_effect=put_route)
    router.get(f"{API}/zones", params={"name": "limbo.watch"}).mock(
        return_value=httpx.Response(200, json={"success": True, "result": [{"id": ZONE}]})
    )
    for phase in PHASES:
        url = f"{API}/zones/{ZONE}/rulesets/phases/{phase}/entrypoint"
        if phase in existing:
            router.get(url).mock(
                return_value=httpx.Response(200, json={"success": True, "result": {"rules": existing[phase]}})
            )
        else:
            router.get(url).mock(return_value=httpx.Response(404, json={"success": False, "errors": []}))

        def put(request: httpx.Request, phase: str = phase) -> httpx.Response:
            assert request.headers["Authorization"] == "Bearer t"
            puts[phase] = json.loads(request.content)["rules"]
            return httpx.Response(200, json={"success": True, "result": {}})

        router.put(url).mock(side_effect=put)
    return puts


def test_run_writes_each_phase_once_then_nothing() -> None:
    other = {"id": "o", "ref": "other", "expression": "true", "action": "set_cache_settings"}
    log: list[str] = []
    with respx.mock(assert_all_called=False) as router:
        puts = mock(router, {"http_request_cache_settings": [other]})
        n = apply(log=log.append)
    assert n == 4 and set(puts) == set(PHASES)
    assert puts["http_request_cache_settings"][0] == other
    assert "http_request_cache_settings: set limbowatch-cache; 1 other rule(s) kept" in log

    # the zone now has those rules: nothing to do
    with respx.mock(assert_all_called=False) as router:
        again = mock(router, puts)
        assert apply(log=log.append) == 0
    assert again == {}


def test_dry_run_and_errors(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    with respx.mock(assert_all_called=False) as router:
        puts = mock(router, {})
        assert apply(dry_run=True) == 4
    assert puts == {} and "would set limbowatch-index" in capsys.readouterr().out

    with respx.mock() as router:
        router.get(f"{API}/zones").mock(return_value=httpx.Response(200, json={"success": True, "result": []}))
        with pytest.raises(RuntimeError, match="0 found"):
            cf_rules.Cloudflare("t", httpx.Client()).zone_id("limbo.watch")
    with respx.mock() as router:
        router.get(f"{API}/zones").mock(
            return_value=httpx.Response(403, json={"success": False, "errors": [{"message": "no"}]})
        )
        with pytest.raises(RuntimeError, match="HTTP 403"):
            cf_rules.Cloudflare("t", httpx.Client()).zone_id("limbo.watch")

    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    assert cf_rules.main(["--zone", "limbo.watch", "--host", "next.limbo.watch"]) == 2
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "t")
    assert cf_rules.main(["--zone", "limbo.watch", "--host", "x", "--www", "limbo.watch"]) == 2


def test_the_workers_routes_fail_open() -> None:
    """wrangler creates a route that fails closed; past the free daily limit it would answer 1027 (F-183)."""
    routes = [
        {"id": "r1", "pattern": "limbo.watch/osv/*", "script": "limbowatch-site", "request_limit_fail_open": False},
        {"id": "r2", "pattern": "next.limbo.watch/osv/*", "script": "limbowatch-site", "request_limit_fail_open": True},
        {"id": "r3", "pattern": "limbo.watch/other/*", "script": "someone-else", "request_limit_fail_open": False},
    ]
    stored = {p: cf_rules.desired(spec(), ["next.limbo.watch"], [])[p] for p in PHASES}
    log: list[str] = []
    with respx.mock(assert_all_called=False) as router:
        puts = mock(router, stored, routes)
        assert apply(dry_run=True, log=log.append) == 1
        assert puts == {} and "route limbo.watch/osv/*: would set fail open" in log
        assert apply(log=log.append) == 1
    want = {"pattern": "limbo.watch/osv/*", "script": "limbowatch-site", "request_limit_fail_open": True}
    assert puts == {"r1": want}
