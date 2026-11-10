"""A Gitea or Forgejo organization's repositories, or a user's (API v1, FINDINGS F-129).

`GET /orgs/{org}/repos`, falling back to `GET /users/{name}/repos` when the name isn't an org. Pages hold
at most the instance's `max_response_items` (50 by default), and follow the `Link: rel="next"` header.
Mirrors and forks are checked like any repo: the org builds from them.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from limbowatch.hosts import HostKind, Listing, Project, Skip, SourceError, next_link, safe_path
from limbowatch.http import HttpClient

LIMIT = 50
MAX_PAGES = 1000


async def list_org(
    http: HttpClient, base_url: str, org: str, token: str | None, include_archived: bool = False
) -> Listing:
    out = Listing(f"{base_url}/{org}", HostKind.GITEA)
    try:
        return await _list(out, http, base_url, org, token, include_archived)
    except SourceError as e:  # a repo path or next link that can't be trusted: this source only
        out.error = f"listing {out.source}: {e}"
        return out


async def _list(
    out: Listing, http: HttpClient, base_url: str, org: str, token: str | None, include_archived: bool
) -> Listing:
    auth = ("Authorization", f"token {token}") if token else None
    for kind in ("orgs", "users"):
        url: str | None = f"{base_url}/api/v1/{kind}/{quote(org, safe='')}/repos"
        params: dict[str, Any] | None = {"limit": LIMIT, "page": 1}
        for page in range(MAX_PAGES):
            if url is None:
                return out
            r = await http.request("GET", url, auth=auth, params=params)
            if r.status == 404 and kind == "orgs" and page == 0:
                break  # not an org: try it as a user
            if r.status != 200 or not isinstance(r.body, list):
                detail = r.body.get("message") if isinstance(r.body, dict) else ""
                hint = (
                    " (a private org needs LIMBOWATCH_SOURCE_TOKEN with read access)"
                    if r.status in (401, 403, 404)
                    else ""
                )
                out.error = f"listing {out.source}: HTTP {r.status} {detail or ''}".strip() + hint
                return out
            for p in r.body:
                _add(out, base_url, p, include_archived)
            url, params = next_link(r.link, base_url), None
        else:
            out.error = f"listing {out.source}: stopped after {MAX_PAGES} pages"
            return out
    return out


def _add(out: Listing, base_url: str, p: dict[str, Any], include_archived: bool) -> None:
    path = safe_path(str(p["full_name"]))
    proj = Project(
        HostKind.GITEA,
        base_url,
        path,
        str(p.get("clone_url") or f"{base_url}/{path}.git"),
        str(p.get("html_url") or f"{base_url}/{path}"),
        public=not p.get("private", False) and not p.get("internal", False),
        archived=bool(p.get("archived")),
    )
    if proj.archived and not include_archived:
        out.skipped.append((proj, Skip.ARCHIVED))
    elif p.get("empty"):
        out.skipped.append((proj, Skip.EMPTY))
    else:
        out.projects.append(proj)
