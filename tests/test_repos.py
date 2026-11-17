"""`limbowatch repos`: the GitHub source repositories of projects' dependencies, as a seed file for a focused feed
(docs/OWN_FEED.md, FINDINGS F-216)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import httpx
import respx
from limbowatch.http import HttpClient
from limbowatch.models import Dependency, Upstream, UpstreamKind
from limbowatch.store import Repo, Store
from limbowatch.tracker import Tracker, TrackerConfig
from limbowatch.watch import repos


def dep(eco: str, name: str, version: str) -> Dependency:
    return Dependency(ecosystem=eco, name=name, version=version, source="lockfile")


async def test_repos_of_dependencies_and_upstreams_with_the_rest_listed(tmp_path: Path, no_sleep: Any) -> None:
    deps = [
        dep("npm", "lodash", "4.17.20"),
        dep("npm", "lodash", "4.17.20"),  # the same package version twice: looked up once
        dep("go", "github.com/Dlclark/regexp2", "1.11.5"),  # from its path, no lookup
        dep("npm", "unmapped", "1.0.0"),
    ]
    ups = [
        Upstream(kind=UpstreamKind.SUBMODULE, name="zlib", source=".gitmodules", host="github.com", repo="madler/zlib"),
        Upstream(
            kind=UpstreamKind.SUBMODULE, name="eigen", source=".gitmodules", host="gitlab.com", repo="libeigen/eigen"
        ),
    ]
    with respx.mock(assert_all_mocked=True) as router:
        src = {"projectKey": {"id": "github.com/lodash/lodash"}, "relationProvenance": "UNVERIFIED_METADATA",
               "relationType": "SOURCE_REPO"}  # fmt: skip
        lodash = router.get(url__startswith="https://api.deps.dev/v3/systems/npm/packages/lodash/").mock(
            return_value=httpx.Response(200, json={"relatedProjects": [src]}))  # fmt: skip
        router.get(url__startswith="https://api.deps.dev/v3/systems/npm/packages/unmapped/").mock(
            return_value=httpx.Response(404, json={}))  # fmt: skip
        async with HttpClient(sleep=no_sleep) as http:
            found = await repos.find(http, deps, ups)
    assert lodash.call_count == 1
    assert found.repos == {"lodash/lodash", "dlclark/regexp2", "madler/zlib"}
    assert found.dependencies == 3 and found.upstreams == 2
    assert found.unmapped == [("npm unmapped 1.0.0", "deps.dev 404"),
                              ("git submodule eigen", "not on GitHub: gitlab.com/libeigen/eigen")]  # fmt: skip

    text = repos.seed_file(found, "acme/app", "2026-11-17T00:00:00Z")
    assert text.splitlines()[2:5] == ["dlclark/regexp2", "lodash/lodash", "madler/zlib"]
    assert "#   npm unmapped 1.0.0: deps.dev 404" in text
    seed = tmp_path / "seeds.txt"
    seed.write_text(text)
    store = Store()
    t = Tracker(store, cast(Any, None), TrackerConfig(seeds=[seed], only_seeds=True))
    t.load_seeds()  # the tracker reads it back: the three repos, none of the comments
    with store.session() as s:
        assert sorted(r.full_name for r in s.query(Repo)) == ["dlclark/regexp2", "lodash/lodash", "madler/zlib"]
