"""Registry names to upstream repos and tags: Bazel modules, vcpkg ports, Conan packages (PHASE0_PLAN §13.18,
FINDINGS F-136).

- **Bazel Central Registry:** a module version's `source.json` names the archive (or git commit) it builds from,
  e.g. `https://github.com/madler/zlib/releases/download/v1.3.1/...` → madler/zlib at tag v1.3.1.
- **vcpkg:** the project's baseline (a commit of microsoft/vcpkg) gives each port's version
  (`versions/baseline.json`), and the port's `portfile.cmake` at that commit names the repo and the tag or commit
  (`vcpkg_from_github(REPO madler/zlib REF v${VERSION})`). Ports' own dependencies (default features included,
  host tools not) are added, so the project's whole vcpkg graph is listed.
- **Conan:** the ConanCenter remote's recipe gives the source URL of each version (`conandata.yml`); the recipe
  repo itself (conan-io/conan-center-index) is never taken for the upstream (FINDINGS Q7).

Files come from bcr.bazel.build, raw.githubusercontent.com (outside GitHub's API rate limit, F-013) and
center2.conan.io. A name that
can't be mapped keeps its declaration and says why; it's never dropped.
"""

from __future__ import annotations

import asyncio
import io
import json
import re
import tarfile
from collections.abc import Sequence
from typing import Any

from limbowatch.http import HttpClient
from limbowatch.inventory import upstream as up
from limbowatch.models import Upstream, UpstreamKind
from limbowatch.versions import UpstreamVersion

BCR = "https://bcr.bazel.build/modules"
RAW = "https://raw.githubusercontent.com"
VCPKG = "microsoft/vcpkg"
CONAN_REMOTE = "https://center2.conan.io/v2/conans"  # ConanCenter's Conan 2 remote
MAX_VCPKG_PORTS = 500  # a project's whole vcpkg graph; more is a runaway


def _same(a: str, b: str) -> bool:
    """The same version (1.3 and 1.3.0 are); unreadable versions only when spelled the same."""
    try:
        return UpstreamVersion(a) == UpstreamVersion(b)
    except ValueError:
        return a == b


def _newer(a: str, b: str) -> bool:
    """Is version a after b? Unreadable versions aren't."""
    try:
        return UpstreamVersion(a) > UpstreamVersion(b)
    except ValueError:
        return False


def yaml_block(text: str, top: str, key: str) -> str | None:
    """The lines under `top:` → `key:` in a plain YAML file (conandata.yml, config.yml), without a YAML parser."""
    lines = text.splitlines()
    try:
        i = next(n for n, ln in enumerate(lines) if re.match(rf"^{re.escape(top)}:\s*$", ln))
    except StopIteration:
        return None
    pat = re.compile(rf"^(\s+)[\"']?{re.escape(key)}[\"']?:\s*$")
    for n in range(i + 1, len(lines)):
        ln = lines[n]
        if ln.strip() and not ln.startswith((" ", "\t")):
            return None  # left the top-level block
        if m := pat.match(ln):
            indent, body = len(m.group(1)), []
            for ln2 in lines[n + 1 :]:
                if ln2.strip() and len(ln2) - len(ln2.lstrip()) <= indent:
                    break
                body.append(ln2)
            return "\n".join(body)
    return None


def _urls(text: str) -> list[str]:
    return re.findall(r"(?:https?|ftp)://[^\s\"'\]]+", text)


class Registries:
    """Resolves registry-named upstreams, each name and version once per run (org-wide mode shares it)."""

    def __init__(self, http: HttpClient) -> None:
        self.http = http
        self._text: dict[str, asyncio.Task[str | None]] = {}

    async def text(self, url: str) -> str | None:
        if url not in self._text:
            self._text[url] = asyncio.ensure_future(self._get(url))
        return await self._text[url]

    async def _get(self, url: str) -> str | None:
        r = await self.http.get(url, raw=True)
        return r.body.decode(errors="replace") if r.ok and isinstance(r.body, bytes) else None

    async def doc(self, url: str) -> Any:
        t = await self.text(url)
        try:
            return json.loads(t) if t else None
        except ValueError:
            return None

    async def resolve(self, ups: Sequence[Upstream]) -> dict[Upstream, list[Upstream]]:
        """Each upstream → itself resolved, followed by what it pulls in (vcpkg ports' dependencies)."""
        keys = list(dict.fromkeys(ups))
        done = await asyncio.gather(*(self._one(u) for u in keys))
        return dict(zip(keys, done, strict=True))

    async def _one(self, u: Upstream) -> list[Upstream]:
        if u.repo or u.detail:
            return [u]  # declared by URL, or already known to be unmappable
        if u.kind is UpstreamKind.BAZEL_MODULE and u.version:
            return [await self.bazel(u)]
        if u.kind is UpstreamKind.VCPKG and u.baseline:
            return await self.vcpkg_graph(u)
        if u.kind is UpstreamKind.CONAN and u.version:
            return [await self.conan(u)]
        return [u]

    # --- Bazel ------------------------------------------------------------------------------------------------------

    async def bazel(self, u: Upstream) -> Upstream:
        src = await self.doc(f"{BCR}/{u.name}/{u.version}/source.json")
        if not isinstance(src, dict):
            return u.model_copy(update={"detail": f"{u.name} {u.version} isn't in the Bazel Central Registry"})
        if src.get("type") == "git_repository":
            loc, commit = up.locate(str(src.get("remote") or "")), src.get("commit") or src.get("tag")
            return u.model_copy(
                update={
                    "url": src.get("remote"),
                    "host": loc.host,
                    "repo": loc.repo,
                    "ref": commit,
                    "ref_is_commit": up.is_commit(commit),
                    "via": "Bazel Central Registry",
                }
            )
        urls = [src["url"]] if isinstance(src.get("url"), str) else list(src.get("mirror_urls") or [])
        url, loc = up.pick_url(urls + list(src.get("mirror_urls") or []))
        if loc.repo is None:
            meta = await self.doc(f"{BCR}/{u.name}/metadata.json")
            repos = [r for r in (meta or {}).get("repository") or [] if isinstance(r, str)]
            gh = next((r.split(":", 1)[1] for r in repos if r.startswith("github:")), None)
            if gh:
                return u.model_copy(
                    update={
                        "url": url or None,
                        "host": "github.com",
                        "repo": gh.lower(),
                        "via": "Bazel Central Registry metadata",
                        "detail": f"the source archive ({url}) names no tag",
                    }
                )
            return u.model_copy(update={"url": url or None, "detail": f"the source archive ({url}) isn't on a forge"})
        detail = "" if loc.ref else f"the source archive ({url}) names no tag"
        return u.model_copy(
            update={
                "url": url,
                "host": loc.host,
                "repo": loc.repo,
                "ref": loc.ref,
                "ref_is_commit": up.is_commit(loc.ref),
                "via": "Bazel Central Registry",
                "detail": detail,
            }
        )

    # --- vcpkg ------------------------------------------------------------------------------------------------------

    async def _baseline(self, sha: str) -> dict[str, Any]:
        doc = await self.doc(f"{RAW}/{VCPKG}/{sha}/versions/baseline.json")
        return (doc or {}).get("default") or {} if isinstance(doc, dict) else {}

    async def vcpkg_graph(self, root: Upstream) -> list[Upstream]:
        sha = root.baseline or ""
        base = await self._baseline(sha)
        if not base:
            return [root.model_copy(update={"detail": f"vcpkg baseline {sha} couldn't be read"})]
        out = [await self.vcpkg_port(root, base)]
        seen = {root.name}
        queue = [root.name]
        truncated = False
        while queue:
            name = queue.pop(0)
            if name not in base:
                continue  # no such port at the baseline (reported on it): nothing to follow
            manifest = await self.doc(f"{RAW}/{VCPKG}/{sha}/ports/{name}/vcpkg.json")
            for dep in _port_deps(manifest):
                if dep in seen:
                    continue
                if len(seen) >= MAX_VCPKG_PORTS:
                    truncated = True  # a port left out: said on the root below
                    continue
                seen.add(dep)
                child = root.model_copy(
                    update={"name": dep, "version": dict(root.overrides).get(dep), "via": f"a dependency of {name}"}
                )  # an override applies to it too
                out.append(await self.vcpkg_port(child, base))
                queue.append(dep)
        if truncated:  # stopped at MAX_VCPKG_PORTS: say so on the root, never drop silently
            why = f"its dependency graph has more than {MAX_VCPKG_PORTS} ports; the rest weren't listed"
            out[0] = out[0].model_copy(update={"detail": "; ".join(x for x in (out[0].detail, why) if x)})
        return out

    async def vcpkg_port(self, u: Upstream, base: dict[str, Any]) -> Upstream:
        sha, entry = u.baseline or "", base.get(u.name)
        if not isinstance(entry, dict) or "baseline" not in entry:
            return u.model_copy(update={"detail": f"no port {u.name} in vcpkg at {sha[:12]}"})
        at_baseline = str(entry["baseline"])
        version = at_baseline
        if u.version and u.version.startswith(">="):
            minimum = u.version[2:]
            version = minimum if _newer(minimum, at_baseline) else at_baseline
        elif u.version:
            version = u.version  # an override
        pf = await self.text(f"{RAW}/{VCPKG}/{sha}/ports/{u.name}/portfile.cmake")
        via = (u.via + "; " if u.via else "") + f"vcpkg port at {sha[:12]}"
        if pf is None:
            return u.model_copy(
                update={"version": version, "via": via, "detail": "the port's portfile couldn't be read"}
            )
        loc, ref, url = up.portfile_source(pf, version)
        if loc.repo is None:
            return u.model_copy(
                update={
                    "version": version,
                    "via": via,
                    "url": url or None,
                    "detail": "the port downloads from a site, not a repository"
                    if url
                    else "the port builds from no download (a meta or system port)",
                }
            )
        detail = ""
        if ref and not _same(version, at_baseline) and "${VERSION}" not in up.ref_template(pf):
            ref, detail = None, f"the port at the baseline builds {at_baseline}; the source of {version} isn't known"
        return u.model_copy(
            update={
                "version": version,
                "via": via,
                "url": url,
                "host": loc.host,
                "repo": loc.repo,
                "ref": ref,
                "ref_is_commit": up.is_commit(ref),
                "detail": detail or ("" if ref else "the port's tag couldn't be worked out"),
            }
        )

    # --- Conan ------------------------------------------------------------------------------------------------------

    async def conan(self, u: Upstream) -> Upstream:
        """The recipe's `conandata.yml` from the ConanCenter remote (in its latest revision's `conan_export.tgz`),
        which serves every version; conan-center-index on GitHub keeps only current ones (F-137)."""
        base = f"{CONAN_REMOTE}/{u.name}/{u.version}/_/_"
        latest = await self.doc(f"{base}/latest")
        rev = latest.get("revision") if isinstance(latest, dict) else None
        if not rev:
            return u.model_copy(update={"detail": f"{u.name} {u.version} isn't on ConanCenter"})
        r = await self.http.get(f"{base}/revisions/{rev}/files/conan_export.tgz", raw=True)
        data = _conandata(r.body) if r.ok and isinstance(r.body, bytes) else None
        urls = _urls(yaml_block(data or "", "sources", u.version or "") or "")
        url, loc = up.pick_url(urls)
        via = "ConanCenter recipe"
        if loc.repo is None:
            what = (
                f"ConanCenter downloads it from {up.locate(url).host or url}, not a repository"
                if url
                else "ConanCenter's recipe names no source URL"
            )
            return u.model_copy(update={"url": url or None, "via": via, "detail": what})
        return u.model_copy(
            update={
                "url": url,
                "host": loc.host,
                "repo": loc.repo,
                "ref": loc.ref,
                "ref_is_commit": up.is_commit(loc.ref),
                "via": via,
                "detail": "" if loc.ref else f"the source archive ({url}) names no tag",
            }
        )


def _conandata(tgz: bytes) -> str | None:
    """conandata.yml from a recipe's export archive, read in memory (nothing is written to disk)."""
    try:
        with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as tar:
            m = tar.getmember("conandata.yml")
            f = tar.extractfile(m) if m.isfile() and m.size <= 1_000_000 else None
            return f.read().decode(errors="replace") if f else None
    except (tarfile.TarError, KeyError, OSError, EOFError):
        return None


def _port_deps(manifest: Any) -> list[str]:
    """A port's dependencies: plain ones and its default features', not host tools or vcpkg's helper ports."""
    if not isinstance(manifest, dict):
        return []
    deps: list[Any] = list(manifest.get("dependencies") or [])
    feats = manifest.get("features") or {}
    for f in manifest.get("default-features") or []:
        name = f if isinstance(f, str) else (f or {}).get("name")
        if isinstance(feats, dict) and isinstance(feats.get(name), dict):
            deps += feats[name].get("dependencies") or []
    out = []
    for d in deps:
        if isinstance(d, dict) and d.get("host"):
            continue
        name = d if isinstance(d, str) else (d or {}).get("name")
        if isinstance(name, str) and not name.startswith("vcpkg-"):
            out.append(name)
    return list(dict.fromkeys(out))
