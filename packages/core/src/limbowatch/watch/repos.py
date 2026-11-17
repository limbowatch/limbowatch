"""The source repositories of a project's dependencies and upstream sources, as a tracker seed file: a feed focused on
your own dependencies (`limbowatch repos`, `limbowatch track --only-seeds`, docs/OWN_FEED.md).

Each dependency is mapped to its repo the way the scan does it (watch.mapping, watch.registries), so the feed watches
exactly the repos a scan would otherwise poll itself. Only GitHub repos can be watched (repository advisories are
GitHub's); every dependency that leads to none is listed in the file as a comment, never dropped.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from limbowatch.http import HttpClient
from limbowatch.models import Dependency, Upstream
from limbowatch.watch import mapping
from limbowatch.watch.registries import Registries


@dataclass
class SourceRepos:
    repos: set[str] = field(default_factory=set)  # owner/name on GitHub, lower case
    dependencies: int = 0  # distinct package versions looked up
    upstreams: int = 0  # distinct upstream sources
    # what leads to no GitHub repo: (what, why), e.g. ("npm left-pad 1.0.0", "deps.dev has no source repo")
    unmapped: list[tuple[str, str]] = field(default_factory=list)


async def find(http: HttpClient, deps: Sequence[Dependency], upstreams: Sequence[Upstream]) -> SourceRepos:
    out = SourceRepos()
    mapped = await mapping.map_all(http, list(deps))
    out.dependencies = len(mapped)
    for (eco, name, version), m in sorted(mapped.items()):
        if m.repo:
            out.repos.add(m.repo)
        else:
            out.unmapped.append((f"{eco} {name} {version}", m.method))
    resolved = await Registries(http).resolve(list(dict.fromkeys(upstreams)))
    sources = {r for rs in resolved.values() for r in rs}
    out.upstreams = len(sources)
    for u in sorted(sources, key=lambda u: (u.kind.value, u.name, u.host, u.repo or "")):
        if u.host == "github.com" and u.repo:
            out.repos.add(u.repo.lower())
        else:
            where = f"{u.host}/{u.repo}" if u.repo else (u.url or u.detail or "repository unknown")
            out.unmapped.append((f"{u.kind.value} {u.name}", f"not on GitHub: {where}" if u.repo else where))
    return out


def seed_file(found: SourceRepos, what: str, generated_at: str) -> str:
    """The seed file: a header, one owner/repo per line, then what has no GitHub repo, as comments."""
    lines = [
        f"# Source repositories of the dependencies of {what}, by `limbowatch repos` at {generated_at}.",
        f"# {len(found.repos):,} repositories from {found.dependencies:,} package versions and "
        f"{found.upstreams:,} upstream sources. Seed file for `limbowatch track --seed FILE --only-seeds`.",
        *sorted(found.repos),
    ]
    if found.unmapped:
        lines += ["", f"# No GitHub repository ({len(found.unmapped):,}); scans check these by name only:"]
        lines += [f"#   {thing}: {why}" for thing, why in found.unmapped]
    return "\n".join(lines) + "\n"
