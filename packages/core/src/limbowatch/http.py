"""The only module that builds HTTP requests.

- Per-host concurrency limits, retries with exponential backoff, Retry-After.
- GitHub primary and secondary rate limits; a request budget for the run (304s are free and
  don't count, FINDINGS F-058).
- Conditional requests: ETags are only valid for the token that obtained them (the response
  varies by Authorization), so the client exposes a token fingerprint to store alongside them.
- The token is never logged, printed or returned.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from limbowatch import __version__

log = logging.getLogger(__name__)
USER_AGENT = f"limbowatch/{__version__} (+https://limbo.watch)"
GITHUB_API = "api.github.com"
HOST_CONCURRENCY = {
    GITHUB_API: 8,
    "api.osv.dev": 16,
    "cveawg.mitre.org": 16,
    "services.nvd.nist.gov": 1,
    "raw.githubusercontent.com": 8,
}


class BudgetExhausted(Exception):
    """The run's GitHub request budget (or the primary rate limit) is used up."""


class DeadlineReached(Exception):
    """The run's wall-clock deadline has passed."""


@dataclass
class Response:
    status: int
    body: Any
    etag: str | None = None
    link: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == 200


@dataclass
class Stats:
    requests: dict[str, int] = field(default_factory=dict)
    github_counted: int = 0
    github_not_modified: int = 0
    failures: int = 0


class HttpClient:
    def __init__(
        self,
        github_token: str | None = None,
        *,
        github_budget: int | None = None,
        deadline: float | None = None,
        nvd_api_key: str | None = None,
        max_rate_limit_wait: float = 900.0,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Any = asyncio.sleep,
    ) -> None:
        self._token = github_token
        self.token_fingerprint = hashlib.sha256(github_token.encode()).hexdigest()[:16] if github_token else "anonymous"
        self.github_budget = github_budget
        self.deadline = deadline
        self._nvd_key = nvd_api_key
        self._nvd_spacing = 0.7 if nvd_api_key else 6.5
        self._nvd_last = 0.0
        self._max_wait = max_rate_limit_wait
        self._sleep = sleep
        self._sems = {h: asyncio.Semaphore(n) for h, n in HOST_CONCURRENCY.items()}
        self._default_sem = asyncio.Semaphore(8)
        self._nvd_lock = asyncio.Lock()
        self.stats = Stats()
        self._client = httpx.AsyncClient(
            timeout=60, follow_redirects=True, headers={"User-Agent": USER_AGENT}, transport=transport
        )

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    def budget_left(self) -> int | None:
        return None if self.github_budget is None else self.github_budget - self.stats.github_counted

    def _check_deadline(self) -> None:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise DeadlineReached

    async def get(self, url: str, *, etag: str | None = None, json_body: Any = None) -> Response:
        """GET (or POST with `json_body`). Returns status 304 with no body when `etag` still matches."""
        self._check_deadline()
        host = urlsplit(url).hostname or ""
        is_gh = host == GITHUB_API
        if is_gh and (left := self.budget_left()) is not None and left <= 0:
            raise BudgetExhausted
        headers: dict[str, str] = {}
        if is_gh:
            headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            if etag:
                headers["If-None-Match"] = etag
        if host == "services.nvd.nist.gov":
            if self._nvd_key:
                headers["apiKey"] = self._nvd_key
            async with self._nvd_lock:  # NVD: one request per spacing interval
                wait = self._nvd_last + self._nvd_spacing - time.monotonic()
                if wait > 0:
                    await self._sleep(wait)
                self._nvd_last = time.monotonic()
        sem = self._sems.get(host, self._default_sem)
        async with sem:
            r = await self._send(url, headers, json_body, is_gh)
        self.stats.requests[host] = self.stats.requests.get(host, 0) + 1
        if r is None:
            self.stats.failures += 1
            return Response(-1, None)
        if is_gh:
            if r.status_code == 304:
                self.stats.github_not_modified += 1
            else:
                self.stats.github_counted += 1
        if r.status_code == 304:
            return Response(304, None, etag=etag)
        try:
            body: Any = r.json()
        except ValueError:
            body = r.text
        return Response(r.status_code, body, etag=r.headers.get("etag"), link=r.headers.get("link"))

    async def _send(self, url: str, headers: dict[str, str], json_body: Any, is_gh: bool) -> httpx.Response | None:
        for attempt in range(6):
            self._check_deadline()
            try:
                if json_body is None:
                    r = await self._client.get(url, headers=headers)
                else:
                    r = await self._client.post(url, headers=headers, json=json_body)
            except httpx.HTTPError as e:
                log.warning("http error", extra={"url": url, "error": type(e).__name__, "attempt": attempt})
                await self._sleep(min(60, 2**attempt))
                continue
            if is_gh and r.status_code in (403, 429):
                if r.headers.get("x-ratelimit-remaining") == "0":
                    await self._wait_for_reset(r)
                    continue
                if "retry-after" in r.headers or "secondary rate limit" in r.text.lower():
                    await self._sleep(int(r.headers.get("retry-after", 60)) + 1)
                    continue
            if r.status_code in (429, 500, 502, 503, 504):
                await self._sleep(min(60, int(r.headers.get("retry-after", 2 ** (attempt + 1)))))
                continue
            if is_gh and int(r.headers.get("x-ratelimit-remaining", "1000")) < 20:
                await self._wait_for_reset(r)
            return r
        return None

    async def _wait_for_reset(self, r: httpx.Response) -> None:
        wait = max(5.0, float(r.headers.get("x-ratelimit-reset", time.time() + 60)) - time.time() + 5)
        if wait > self._max_wait:
            raise BudgetExhausted
        log.info("github rate limit low; waiting", extra={"seconds": round(wait)})
        await self._sleep(wait)
