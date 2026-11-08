"""The Go module proxy (https://proxy.golang.org): which module contains a Go package path (F-113).

A Go advisory may name a module (`github.com/aws/aws-sdk-go-v2/service/kinesis`, a module of its own) or a package
inside one (`go.opentelemetry.io/otel/baggage`, in `go.opentelemetry.io/otel`). The path alone doesn't say which, and
matching a separate module to its parent compares the wrong version line. The proxy knows: the module is the longest
prefix of the path it serves (`<prefix>/@v/list` lists versions, or `<prefix>/@latest` answers), and it answers 404 or
410 for a prefix that isn't a module.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from limbowatch.http import HttpClient

PROXY = "https://proxy.golang.org"


def escape(path: str) -> str:
    """The proxy's case encoding: each upper-case letter becomes '!' and its lower-case form."""
    return "".join(f"!{c.lower()}" if c.isupper() else c for c in path)


def prefixes(path: str) -> list[str]:
    """`a.com/b/c` → [`a.com/b/c`, `a.com/b`]: the path and its parents, longest first, never a bare host."""
    parts = path.strip("/").split("/")
    return ["/".join(parts[:n]) for n in range(len(parts), 1, -1)]


@dataclass
class Resolver:
    """Resolves paths, asking the proxy about each prefix at most once."""

    http: HttpClient
    known: dict[str, bool | None] = field(default_factory=dict)  # prefix → is a module; None: the proxy failed
    requests: int = 0

    async def _is_module(self, prefix: str) -> bool | None:
        if prefix not in self.known:
            base = f"{PROXY}/{escape(prefix)}/@"
            r = await self.http.get(base + "v/list")
            self.requests += 1
            if r.status == 200 and isinstance(r.body, str) and r.body.strip():
                verdict: bool | None = True
            elif r.status == 200:  # a module with no tagged versions still answers @latest
                r = await self.http.get(base + "latest")
                self.requests += 1
                verdict = True if r.status == 200 else False if r.status in (400, 404, 410) else None
            else:
                verdict = False if r.status in (400, 404, 410) else None  # 400: not a valid module path
            self.known[prefix] = verdict
        return self.known[prefix]

    async def module_of(self, path: str) -> tuple[str | None, bool]:
        """(module, complete): the longest prefix the proxy serves as a module, or None if none is; complete is
        False when the proxy failed before an answer, so the result shouldn't be recorded."""
        for prefix in prefixes(path):
            verdict = await self._is_module(prefix)
            if verdict is None:
                return None, False
            if verdict:
                return prefix, True
        return None, True
