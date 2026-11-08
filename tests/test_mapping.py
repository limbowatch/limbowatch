"""Package -> source repo where deps.dev doesn't cover the ecosystem, and the Maven <scm> fallback (F-103)."""

from __future__ import annotations

from typing import Any

import httpx
import respx
from limbowatch.http import HttpClient
from limbowatch.models import Dependency
from limbowatch.versions import affected
from limbowatch.watch import mapping


def dep(eco: str, name: str, version: str = "1.0.0") -> Dependency:
    return Dependency(ecosystem=eco, name=name, version=version, source="lock")


async def test_composer_hex_pub_swift(no_sleep: Any) -> None:
    laravel = {"version": "v13.0.0", "source": {"url": "https://github.com/laravel/framework.git"}}
    phoenix = {"repository_url": "https://github.com/phoenixframework/phoenix"}
    http_pub = {"repository_url": "https://gitlab.com/x/http", "homepage": None}
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{mapping.PACKAGIST}/laravel/framework.json").mock(
            return_value=httpx.Response(200, json={"packages": {"laravel/framework": [laravel]}})
        )
        router.get(f"{mapping.ECOSYSTEMS}/hex.pm/packages/phoenix").mock(return_value=httpx.Response(200, json=phoenix))
        router.get(f"{mapping.ECOSYSTEMS}/pub.dev/packages/http").mock(return_value=httpx.Response(200, json=http_pub))
        async with HttpClient(sleep=no_sleep) as http:
            got = {d.ecosystem: await mapping.repo_of(http, d) for d in (
                dep("composer", "Laravel/Framework"), dep("erlang", "phoenix"), dep("pub", "http"),
                dep("swift", "github.com/apple/swift-nio"))}  # fmt: skip
    assert got["composer"] == mapping.Mapped("laravel/framework", "packagist.org metadata")
    assert got["erlang"] == mapping.Mapped("phoenixframework/phoenix", "ecosyste.ms (hex.pm)")
    assert got["pub"] == mapping.Mapped(None, "source repo on gitlab.com, not GitHub")  # reported, never dropped
    assert got["swift"] == mapping.Mapped("apple/swift-nio", "swift package URL")


async def test_maven_scm_from_the_parent_pom_when_deps_dev_has_none(no_sleep: Any) -> None:
    child = """<project><parent><groupId>io.netty</groupId><artifactId>netty-parent</artifactId>
               <version>4.1.115.Final</version></parent><artifactId>netty-codec-http</artifactId></project>"""
    parent = """<project><scm><url>https://github.com/netty/netty</url>
                <connection>scm:git:git://github.com/netty/netty.git</connection></scm></project>"""
    with respx.mock(assert_all_called=True) as router:
        router.get(url__startswith=mapping.DEPS_DEV).mock(
            return_value=httpx.Response(200, json={"relatedProjects": []})
        )
        router.get(f"{mapping.MAVEN_CENTRAL}/io/netty/netty-codec-http/4.1.115.Final/netty-codec-http-4.1.115.Final.pom").mock(
            return_value=httpx.Response(200, text=child))  # fmt: skip
        router.get(f"{mapping.MAVEN_CENTRAL}/io/netty/netty-parent/4.1.115.Final/netty-parent-4.1.115.Final.pom").mock(
            return_value=httpx.Response(200, text=parent))  # fmt: skip
        async with HttpClient(sleep=no_sleep) as http:
            got = await mapping.repo_of(http, dep("maven", "io.netty:netty-codec-http", "4.1.115.Final"))
    assert got == mapping.Mapped("netty/netty", "maven pom <scm>")


def test_pom_scm_reads_connections_and_ignores_entities() -> None:
    urls, parent = mapping.pom_scm(
        "<scm><connection>scm:git:git@github.com:FasterXML/jackson-databind.git</connection></scm>"
    )
    assert urls == ["https://github.com/FasterXML/jackson-databind.git"] and parent is None
    hostile = '<!DOCTYPE x [<!ENTITY a "aaaa">]><project><scm><url>&a;&a;</url></scm></project>'
    assert mapping.pom_scm(hostile) == (["&a;&a;"], None)  # matched as text: no entity is expanded
    _, unresolved = mapping.pom_scm(
        "<parent><groupId>g</groupId><artifactId>a</artifactId><version>${rev}</version></parent>"
    )
    assert unresolved is None  # a property we can't resolve: stop rather than guess


def test_hex_pub_swift_versions_are_compared_as_versions() -> None:
    assert affected("erlang", "1.7.10", "< 1.7.14") is True and affected("erlang", "1.7.14", "< 1.7.14") is False
    assert affected("pub", "1.2.0", ">= 1.0.0, < 1.10.0") is True  # 1.2 < 1.10, not as text
    assert affected("swift", "v2.65.0", "< 2.66.0") is True
