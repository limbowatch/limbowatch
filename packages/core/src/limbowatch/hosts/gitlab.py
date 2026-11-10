"""A GitLab group's projects, subgroups included (REST API v4, FINDINGS F-129).

`GET /groups/:id/projects` with `include_subgroups=true` and `with_shared=false`: projects shared into the
group from elsewhere belong to other groups, and the API includes them by default. Archived projects are
listed and filtered here, so each one is reported as skipped. Pages follow the `Link: rel="next"` header.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from limbowatch.hosts import HostKind, Listing, Project, Skip, SourceError, next_link, safe_path
from limbowatch.http import HttpClient

PER_PAGE = 100
MAX_PAGES = 500  # 50,000 projects: far beyond any group, a guard against a pagination loop


async def list_group(
    http: HttpClient, base_url: str, group: str, token: str | None, include_archived: bool = False
) -> Listing:
    out = Listing(f"{base_url}/{group}", HostKind.GITLAB)
    try:
        return await _list(out, http, base_url, group, token, include_archived)
    except SourceError as e:  # a project path or next link that can't be trusted: this source only
        out.error = f"listing {out.source}: {e}"
        return out


async def _list(
    out: Listing, http: HttpClient, base_url: str, group: str, token: str | None, include_archived: bool
) -> Listing:
    auth = ("Authorization", f"Bearer {token}") if token else None
    url: str | None = f"{base_url}/api/v4/groups/{quote(group, safe='')}/projects"
    params: dict[str, Any] | None = {"include_subgroups": "true", "with_shared": "false", "per_page": PER_PAGE,
                                     "order_by": "id", "sort": "asc"}  # fmt: skip
    for _ in range(MAX_PAGES):
        if url is None:
            return out
        r = await http.request("GET", url, auth=auth, params=params)
        if r.status != 200 or not isinstance(r.body, list):
            detail = r.body.get("message") if isinstance(r.body, dict) else ""
            hint = " (a private group needs LIMBOWATCH_SOURCE_TOKEN with read_api)" if r.status in (401, 404) else ""
            out.error = f"listing {out.source}: HTTP {r.status} {detail or ''}".strip() + hint
            return out
        for p in r.body:
            _add(out, base_url, p, include_archived)
        url, params = next_link(r.link, base_url), None  # the next link carries every parameter
    out.error = f"listing {out.source}: stopped after {MAX_PAGES} pages"
    return out


def _add(out: Listing, base_url: str, p: dict[str, Any], include_archived: bool) -> None:
    proj = Project(
        HostKind.GITLAB,
        base_url,
        safe_path(str(p["path_with_namespace"])),
        str(p.get("http_url_to_repo") or f"{base_url}/{p['path_with_namespace']}.git"),
        str(p.get("web_url") or f"{base_url}/{p['path_with_namespace']}"),
        public=p.get("visibility") == "public",
        archived=bool(p.get("archived")),
    )
    if p.get("marked_for_deletion_on") or p.get("marked_for_deletion_at"):
        out.skipped.append((proj, Skip.DELETION))
    elif proj.archived and not include_archived:
        out.skipped.append((proj, Skip.ARCHIVED))
    elif p.get("repository_access_level") == "disabled":
        out.skipped.append((proj, Skip.NO_REPOSITORY))
    elif p.get("empty_repo"):
        out.skipped.append((proj, Skip.EMPTY))
    else:
        out.projects.append(proj)
