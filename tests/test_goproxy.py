"""Which module contains a Go package path, per the Go module proxy (F-113). Recorded-shape responses, no network."""

from typing import Any

import httpx
import respx
from limbowatch.http import HttpClient
from limbowatch.sources.goproxy import Resolver, escape, prefixes

P = "https://proxy.golang.org"


def test_prefixes_and_case_encoding() -> None:
    assert prefixes("go.opentelemetry.io/otel/sdk/log") == [
        "go.opentelemetry.io/otel/sdk/log",
        "go.opentelemetry.io/otel/sdk",
        "go.opentelemetry.io/otel",
    ]
    assert prefixes("example.com") == []
    assert escape("github.com/Azure/azure-sdk-for-go") == "github.com/!azure/azure-sdk-for-go"


async def test_resolver_walks_up_to_the_module(no_sleep: Any) -> None:
    with respx.mock(assert_all_mocked=True) as router:
        router.get(f"{P}/go.opentelemetry.io/otel/baggage/@v/list").mock(return_value=httpx.Response(404))
        otel = router.get(f"{P}/go.opentelemetry.io/otel/@v/list").mock(
            return_value=httpx.Response(200, text="v1.47.0\n")
        )
        router.get(f"{P}/go.opentelemetry.io/otel/propagation/@v/list").mock(return_value=httpx.Response(410))
        router.get(f"{P}/go.opentelemetry.io/otel/sdk/@v/list").mock(return_value=httpx.Response(200, text="v1.47.0\n"))
        router.get(f"{P}/example.com/untagged/@v/list").mock(return_value=httpx.Response(200, text=""))
        router.get(f"{P}/example.com/untagged/@latest").mock(
            return_value=httpx.Response(200, json={"Version": "v0.0.0-1"})
        )
        router.get(f"{P}/example.com/gone/pkg/@v/list").mock(return_value=httpx.Response(404))
        router.get(f"{P}/example.com/gone/@v/list").mock(return_value=httpx.Response(404))
        router.get(f"{P}/example.com/busy/@v/list").mock(return_value=httpx.Response(429))
        async with HttpClient(sleep=no_sleep) as http:
            r = Resolver(http)
            assert await r.module_of("go.opentelemetry.io/otel/baggage") == ("go.opentelemetry.io/otel", True)
            assert await r.module_of("go.opentelemetry.io/otel/propagation") == ("go.opentelemetry.io/otel", True)
            assert otel.call_count == 1  # each prefix is asked once
            assert await r.module_of("go.opentelemetry.io/otel/sdk") == ("go.opentelemetry.io/otel/sdk", True)
            assert await r.module_of("example.com/untagged") == ("example.com/untagged", True)
            assert await r.module_of("example.com/gone/pkg") == (None, True)  # no prefix is a module
            assert await r.module_of("example.com/busy") == (None, False)  # the proxy failed: don't record
