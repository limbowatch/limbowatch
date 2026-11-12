"""Issue trackers the watcher opens and updates issues in: GitLab, Gitea/Forgejo and GitHub (FINDINGS F-079,
F-080, F-145, F-147).

Issues are found again by the `limbowatch` label and a marker in the body, never by search (Gitea's
search lags, F-080). GitLab issues are confidential by default; Gitea and GitHub have no confidential issues,
so callers check `public` before opening any there.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import quote

from limbowatch.http import HttpClient

LABEL = "limbowatch"
_MARKER = re.compile(r"<!-- limbowatch (\{.*?\}) -->")


@dataclass
class Issue:
    number: int
    open: bool
    labels: set[str]
    meta: dict[str, Any] = field(default_factory=dict)  # key, ghsa_id, ecosystem, package (from the marker)

    @property
    def key(self) -> str:
        return str(self.meta.get("key", ""))


def marker(meta: dict[str, Any]) -> str:
    return f"<!-- limbowatch {json.dumps(meta, sort_keys=True, separators=(',', ':'))} -->"


def read_marker(body: str | None) -> dict[str, Any] | None:
    m = _MARKER.search(body or "")
    if not m:
        return None
    try:
        meta = json.loads(m.group(1))
    except ValueError:
        return None
    return meta if isinstance(meta, dict) and meta.get("key") else None


class TrackerError(RuntimeError):
    pass


class Tracker(Protocol):
    name: str
    public: bool  # anyone can read issues here

    async def prepare(self) -> None: ...
    async def issues(self) -> dict[str, Issue]: ...
    async def create(self, title: str, body: str, labels: list[str]) -> Issue: ...
    async def comment(self, issue: Issue, body: str) -> None: ...
    async def set_open(self, issue: Issue, is_open: bool) -> None: ...
    async def add_labels(self, issue: Issue, labels: list[str]) -> None: ...


def _check(r: Any, what: str) -> Any:
    if r.status not in (200, 201, 204):
        detail = r.body.get("message") if isinstance(r.body, dict) else str(r.body)[:200]
        raise TrackerError(f"{what}: HTTP {r.status} {detail or ''}".strip())
    return r.body


class GitLab:
    """GitLab REST API v4. `project` is an ID or a path like `group/project`; the token needs `api` scope."""

    name = "GitLab"

    def __init__(
        self,
        http: HttpClient,
        project: str,
        token: str,
        base_url: str = "https://gitlab.com",
        confidential: bool = True,
    ) -> None:
        self.http, self.confidential = http, confidential
        self.api = f"{base_url.rstrip('/')}/api/v4/projects/{quote(project, safe='')}"
        # Bearer takes personal, project and group access tokens and OAuth tokens (glab's login);
        # PRIVATE-TOKEN rejects OAuth tokens with 401 (FINDINGS F-087).
        self._auth = ("Authorization", f"Bearer {token}")
        self.public = False

    async def _req(self, method: str, path: str, what: str, **kw: Any) -> Any:
        return _check(await self.http.request(method, self.api + path, auth=self._auth, **kw), what)

    async def prepare(self) -> None:
        proj = await self._req("GET", "", "read project")
        self.public = proj.get("visibility") == "public" and not self.confidential

    async def issues(self) -> dict[str, Issue]:
        out: dict[str, Issue] = {}
        page = 1
        while True:
            params = {"labels": LABEL, "state": "all", "per_page": 100, "page": page}
            batch = await self._req("GET", "/issues", "list issues", params=params)
            for i in batch:
                if meta := read_marker(i.get("description")):
                    out[meta["key"]] = Issue(i["iid"], i["state"] == "opened", set(i.get("labels") or []), meta)
            if len(batch) < 100:
                return out
            page += 1

    async def create(self, title: str, body: str, labels: list[str]) -> Issue:
        data = {"title": title, "description": body, "labels": ",".join(labels), "confidential": self.confidential}
        i = await self._req("POST", "/issues", "create issue", json_body=data)
        return Issue(i["iid"], True, set(i.get("labels") or labels), read_marker(body) or {})

    async def comment(self, issue: Issue, body: str) -> None:
        await self._req("POST", f"/issues/{issue.number}/notes", "comment", json_body={"body": body})

    async def set_open(self, issue: Issue, is_open: bool) -> None:
        await self._req(
            "PUT",
            f"/issues/{issue.number}",
            "update issue",
            json_body={"state_event": "reopen" if is_open else "close"},
        )
        issue.open = is_open

    async def add_labels(self, issue: Issue, labels: list[str]) -> None:
        await self._req("PUT", f"/issues/{issue.number}", "label issue", json_body={"add_labels": ",".join(labels)})
        issue.labels |= set(labels)


class Gitea:
    """Gitea or Forgejo API v1. `repo` is `owner/name`; the token needs issue write access."""

    name = "Gitea"

    def __init__(self, http: HttpClient, repo: str, token: str, base_url: str) -> None:
        self.http = http
        self.api = f"{base_url.rstrip('/')}/api/v1/repos/{repo}"
        self._auth = ("Authorization", f"token {token}")
        self.public = True  # until prepare() says otherwise
        self._label_ids: dict[str, int] = {}

    async def _req(self, method: str, path: str, what: str, **kw: Any) -> Any:
        return _check(await self.http.request(method, self.api + path, auth=self._auth, **kw), what)

    async def prepare(self) -> None:
        repo = await self._req("GET", "", "read repo")
        self.public = not repo.get("private", False) and not repo.get("internal", False)
        page = 1
        while True:
            batch = await self._req("GET", "/labels", "list labels", params={"page": page, "limit": 50})
            self._label_ids |= {lb["name"]: lb["id"] for lb in batch}
            if len(batch) < 50:
                break
            page += 1

    async def _labels(self, names: list[str]) -> list[int]:
        for n in names:
            if n not in self._label_ids:  # labels must exist before an issue can carry them (F-080)
                lb = await self._req("POST", "/labels", "create label", json_body={"name": n, "color": "#f4a62a"})
                self._label_ids[n] = lb["id"]
        return [self._label_ids[n] for n in names]

    async def issues(self) -> dict[str, Issue]:
        out: dict[str, Issue] = {}
        page = 1
        while True:
            params = {"state": "all", "type": "issues", "labels": LABEL, "page": page, "limit": 50}
            batch = await self._req("GET", "/issues", "list issues", params=params)
            for i in batch:
                if meta := read_marker(i.get("body")):
                    labels = {lb["name"] for lb in i.get("labels") or []}
                    out[meta["key"]] = Issue(i["number"], i["state"] == "open", labels, meta)
            if len(batch) < 50:
                return out
            page += 1

    async def create(self, title: str, body: str, labels: list[str]) -> Issue:
        i = await self._req(
            "POST",
            "/issues",
            "create issue",
            json_body={"title": title, "body": body, "labels": await self._labels(labels)},
        )
        return Issue(i["number"], True, set(labels), read_marker(body) or {})

    async def comment(self, issue: Issue, body: str) -> None:
        await self._req("POST", f"/issues/{issue.number}/comments", "comment", json_body={"body": body})

    async def set_open(self, issue: Issue, is_open: bool) -> None:
        await self._req(
            "PATCH", f"/issues/{issue.number}", "update issue", json_body={"state": "open" if is_open else "closed"}
        )
        issue.open = is_open

    async def add_labels(self, issue: Issue, labels: list[str]) -> None:
        await self._req(
            "POST", f"/issues/{issue.number}/labels", "label issue", json_body={"labels": await self._labels(labels)}
        )
        issue.labels |= set(labels)


class GitHub:
    """GitHub REST API: github.com, or Enterprise Server through its `/api/v3` base. `repo` is `owner/name`; the
    token needs Issues write (the job's `GITHUB_TOKEN` with `permissions: issues: write` will do, F-147).

    The issue list includes pull requests (skipped) and lags a new issue by a few seconds (F-147); a label
    that doesn't exist yet is created with the issue. A label GitHub drops (a token without push access,
    F-145) would make every later run open the issue again, so a new issue without the `limbowatch` label
    stops the run.
    """

    name = "GitHub"

    def __init__(self, http: HttpClient, repo: str, token: str, api_url: str = "https://api.github.com") -> None:
        self.http, self.repo = http, repo
        self.api = f"{api_url.rstrip('/')}/repos/{repo}"
        self._auth = ("Authorization", f"Bearer {token}")
        self.public = True  # until prepare() says otherwise

    async def _req(self, method: str, path: str, what: str, **kw: Any) -> Any:
        return _check(await self.http.request(method, self.api + path, auth=self._auth, github=True, **kw), what)

    async def prepare(self) -> None:
        repo = await self._req("GET", "", "read repo")
        if repo.get("has_issues") is False:  # listing would still answer 200; creating gives 410 (F-147)
            raise TrackerError(f"issues are disabled in {self.repo}")
        visibility = repo.get("visibility") or ("private" if repo.get("private", True) else "public")
        self.public = visibility == "public"  # internal (Enterprise) counts as private

    async def issues(self) -> dict[str, Issue]:
        out: dict[str, Issue] = {}
        page = 1
        while True:
            params = {"labels": LABEL, "state": "all", "per_page": 100, "page": page}
            batch = await self._req("GET", "/issues", "list issues", params=params)
            for i in batch:
                if "pull_request" in i:
                    continue
                if meta := read_marker(i.get("body")):
                    labels = {lb["name"] for lb in i.get("labels") or []}
                    out[meta["key"]] = Issue(i["number"], i["state"] == "open", labels, meta)
            if len(batch) < 100:
                return out
            page += 1

    async def create(self, title: str, body: str, labels: list[str]) -> Issue:
        i = await self._req("POST", "/issues", "create issue", json_body={"title": title, "body": body,
                                                                           "labels": labels})  # fmt: skip
        got = {lb["name"] for lb in i.get("labels") or []}
        if LABEL not in got:
            raise TrackerError(
                f"GitHub opened #{i['number']} without the {LABEL!r} label (the token can't set labels: it needs "
                "Issues write); stopping, because later runs find issues by that label and would open it again"
            )
        return Issue(i["number"], True, got, read_marker(body) or {})

    async def comment(self, issue: Issue, body: str) -> None:
        await self._req("POST", f"/issues/{issue.number}/comments", "comment", json_body={"body": body})

    async def set_open(self, issue: Issue, is_open: bool) -> None:
        data = {"state": "open", "state_reason": "reopened"} if is_open else {"state": "closed",
                                                                              "state_reason": "completed"}  # fmt: skip
        await self._req("PATCH", f"/issues/{issue.number}", "update issue", json_body=data)
        issue.open = is_open

    async def add_labels(self, issue: Issue, labels: list[str]) -> None:
        await self._req("POST", f"/issues/{issue.number}/labels", "label issue", json_body={"labels": labels})
        issue.labels |= set(labels)
