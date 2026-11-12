"""A GitHub organization's repositories, or a user's (REST API, FINDINGS F-146, F-147).

`GET /orgs/{org}/repos?type=all`, falling back for a name that isn't an org to `GET /user/repos?affiliation=owner`
when the token is that user's, else to `GET /users/{name}/repos` (public repositories only, said in the listing's
note). Pages hold at most 100 and follow the `Link: rel="next"` header.

What a token can see is what gets listed, and GitHub answers a partial view without an error (F-147): the job's
`GITHUB_TOKEN` lists the public repositories and its own. The CLI says so when it runs with one.

Archived and disabled repositories are reported as not checked. GitHub has no reliable flag for an empty
repository (`size` stays 0 for small ones, F-147): an empty clone is found when it's cloned. Forks are checked
like any repository, as on Gitea; `--exclude` skips them.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlsplit

from limbowatch.hosts import HostKind, Listing, Project, Skip, SourceError, next_link, safe_path
from limbowatch.http import BudgetExhausted, HttpClient

PER_PAGE = 100
MAX_PAGES = 1000
PUBLIC_ONLY = "lists public repositories only: {name} is a user, and the token isn't theirs"
NO_REPO_SCOPE = "the token has no repo scope, so private repositories aren't listed"


def api_url(server_url: str, known: dict[str, str] | None = None) -> str:
    """The REST API base for a GitHub server URL: api.github.com for github.com, `/api/v3` on Enterprise
    Server. A URL that already is an API base is kept. `known` maps a server to its API as Actions gives them
    (GITHUB_SERVER_URL → GITHUB_API_URL), which also covers GHE.com, whose API host the docs read for this don't
    name (Q30)."""
    base = server_url.rstrip("/")
    for server, api in (known or {}).items():
        if server.rstrip("/") == base and api:
            return api.rstrip("/")
    host = urlsplit(base).hostname or ""
    if host in ("github.com", "www.github.com"):
        return "https://api.github.com"
    if host.startswith("api.") or base.endswith("/api/v3"):
        return base
    return base + "/api/v3"


def auth(token: str | None) -> tuple[str, str] | None:
    return ("Authorization", f"Bearer {token}") if token else None


async def list_org(
    http: HttpClient,
    base_url: str,
    org: str,
    token: str | None,
    include_archived: bool = False,
    api: str | None = None,
) -> Listing:
    out = Listing(f"{base_url}/{org}", HostKind.GITHUB)
    try:
        return await _list(out, http, base_url, org, token, include_archived, api or api_url(base_url))
    except SourceError as e:  # a repo path or next link that can't be trusted: this source only
        out.error = f"listing {out.source}: {e}"
        return out
    except BudgetExhausted:
        out.error = f"listing {out.source}: GitHub's rate limit is used up; try again after it resets"
        return out


async def _list(
    out: Listing, http: HttpClient, base_url: str, org: str, token: str | None, include_archived: bool, api: str
) -> Listing:
    name = quote(org, safe="")
    params: dict[str, Any] = {"type": "all", "per_page": PER_PAGE}
    r = await http.request("GET", f"{api}/orgs/{name}/repos", auth=auth(token), params=params, github=True)
    if r.status == 404:  # not an org: a user
        first, params = await _user_listing(out, http, api, org, token)
        r = await http.request("GET", first, auth=auth(token), params=params, github=True)
    if r.scopes is not None and "repo" not in {x.strip() for x in r.scopes.split(",")} and not out.note:
        out.note = NO_REPO_SCOPE  # a classic token says its scopes; GitHub lists what it can see, quietly (F-147)
    for _ in range(MAX_PAGES):
        if r.status != 200 or not isinstance(r.body, list):
            detail = r.body.get("message") if isinstance(r.body, dict) else ""
            hint = (
                " (a private org needs LIMBOWATCH_SOURCE_TOKEN with read access)" if r.status in (401, 403, 404) else ""
            )
            out.error = f"listing {out.source}: HTTP {r.status} {detail or ''}".strip() + hint
            return out
        for p in r.body:
            _add(out, base_url, p, include_archived)
        url = next_link(r.link, api)
        if url is None:
            return out
        r = await http.request("GET", url, auth=auth(token), github=True)
    out.error = f"listing {out.source}: stopped after {MAX_PAGES} pages"
    return out


async def _user_listing(
    out: Listing, http: HttpClient, api: str, user: str, token: str | None
) -> tuple[str, dict[str, Any]]:
    """The user's own repositories, private ones included, when the token is theirs; else their public ones."""
    if token:
        me = await http.request("GET", f"{api}/user", auth=auth(token), github=True)
        login = me.body.get("login") if me.status == 200 and isinstance(me.body, dict) else None
        if isinstance(login, str) and login.lower() == user.lower():
            return f"{api}/user/repos", {"affiliation": "owner", "per_page": PER_PAGE}
    out.note = PUBLIC_ONLY.format(name=user)
    return f"{api}/users/{quote(user, safe='')}/repos", {"type": "owner", "per_page": PER_PAGE}


def _add(out: Listing, base_url: str, p: dict[str, Any], include_archived: bool) -> None:
    path = safe_path(str(p["full_name"]))
    visibility = p.get("visibility") or ("private" if p.get("private") is True else "public")
    proj = Project(
        HostKind.GITHUB,
        base_url,
        path,
        str(p.get("clone_url") or f"{base_url}/{path}.git"),
        str(p.get("html_url") or f"{base_url}/{path}"),
        public=visibility == "public",  # internal (Enterprise) counts as private, as on Gitea
        archived=bool(p.get("archived")),
    )
    if proj.archived and not include_archived:
        out.skipped.append((proj, Skip.ARCHIVED))
    elif p.get("disabled"):
        out.skipped.append((proj, Skip.NO_REPOSITORY))
    else:
        out.projects.append(proj)
