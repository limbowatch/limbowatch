"""`limbowatch scan` checks a project against advisories in limbo; `limbowatch inventory` lists what a project
depends on and what can't be checked; `limbowatch track`, `publish` and `report` run the live tracker."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from collections.abc import Collection
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

import typer
from limbowatch import hosts
from limbowatch.ecosystems import info
from limbowatch.hosts import gitea as gitea_host
from limbowatch.hosts import github as github_host
from limbowatch.hosts import gitlab as gitlab_host
from limbowatch.http import BudgetExhausted, HttpClient
from limbowatch.inventory import osv_scanner, sbom
from limbowatch.inventory import upstream as upstream_inventory
from limbowatch.models import Inventory, Unchecked
from limbowatch.publish import all_events, dumps, items, metrics, repos_with_advisories, watchlist
from limbowatch.publish import feed as feed_mod
from limbowatch.publish import report as report_mod
from limbowatch.publish import site as site_mod
from limbowatch.sources import osv as osv_source
from limbowatch.sources.releases import read_maven_packages
from limbowatch.store import Store
from limbowatch.tracker import Tracker, TrackerConfig, import_cve_list
from limbowatch.versions import UPSTREAM, norm_name
from limbowatch.watch import issues as watch_issues
from limbowatch.watch import org as org_mod
from limbowatch.watch import org_output, output, trackers
from limbowatch.watch import scan as watch_scan
from limbowatch.watch import state as watch_state

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Find dependencies affected by security advisories in limbo: published by maintainers on GitHub, not yet "
    "in the databases scanners read. https://limbo.watch",
)


def _version(value: bool) -> None:
    if value:
        from limbowatch import __version__

        typer.echo(f"limbowatch {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        bool | None, typer.Option("--version", callback=_version, is_eager=True, help="Show the version and exit.")
    ] = None,
) -> None:
    """Find dependencies affected by security advisories in limbo. https://limbo.watch"""


def _color(mode: str) -> tuple[bool, bool]:
    """(colour, links) for the terminal table. auto: colour on a terminal and in GitHub Actions and GitLab CI,
    whose logs render it; NO_COLOR turns it off and FORCE_COLOR on. Links (OSC 8) only on a real terminal."""
    tty = sys.stdout.isatty()
    if mode == "never" or (mode == "auto" and os.environ.get("NO_COLOR")):
        return False, False
    ci = bool(os.environ.get("GITHUB_ACTIONS") or os.environ.get("GITLAB_CI") or os.environ.get("FORCE_COLOR"))
    on = mode == "always" or tty or ci
    return on, on and tty and not os.environ.get("CI")


StateDir = Annotated[Path, typer.Option(help="Directory of JSONL state files (read, then rewritten).")]


def _token() -> str | None:
    tok = os.environ.get("LIMBOWATCH_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if tok:
        return tok
    try:
        return (
            subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip() or None
        )
    except (OSError, subprocess.CalledProcessError):
        return None


def _load(state: Path) -> Store:
    store = Store()
    if state.exists():
        store.import_jsonl(state)
    return store


@app.command()
def track(
    state: StateDir = Path("tracker/state"),
    seed: Annotated[list[Path] | None, typer.Option(help="Seed file(s): one owner/repo per line.")] = None,
    budget: Annotated[int, typer.Option(help="Max GitHub requests this run (304s are free).")] = 4000,
    minutes: Annotated[float, typer.Option(help="Wall-clock limit for the run.")] = 50,
    max_new: Annotated[
        int | None, typer.Option(help="First-time polls per run, so a large seed list can't starve due re-checks.")
    ] = None,
    releases: Annotated[
        bool, typer.Option(help="Check a repo after its package releases (docs/RELEASE_CHECKS.md).")
    ] = True,
    release_min_dependents: Annotated[
        int, typer.Option(help="Watch a released package's repo if this many repositories depend on it; 0: never.")
    ] = 100,
    maven_packages: Annotated[
        Path | None, typer.Option(help="Maven packages to poll for releases: group:artifact owner/repo per line.")
    ] = None,
    nvd: Annotated[bool, typer.Option(help="Look up NVD status for published CVEs.")] = True,
    max_nvd: Annotated[int, typer.Option(help="NVD lookups per run.")] = 150,
    cve_list: Annotated[
        Path | None, typer.Option(help="Bootstrap from a cvelistV5 bulk release (*_all_CVEs_at_midnight.zip.zip).")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run the tracker once: sync reviews and CVEs, poll repos within the budget, record changes."""
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING, format="%(levelname)s %(name)s %(message)s")
    store = _load(state)
    maven = read_maven_packages(maven_packages.read_text()) if maven_packages else {}
    cfg = TrackerConfig(seeds=seed or [], nvd=nvd, max_nvd=max_nvd, checkpoint=lambda: store.export_jsonl(state),
                        max_new=max_new, releases=releases,
                        release_min_dependents=release_min_dependents or None, maven_packages=maven)  # fmt: skip

    if cve_list is not None:
        with tempfile.TemporaryDirectory() as tmp:
            n = import_cve_list(store, cve_list, Path(tmp))
        typer.echo(f"imported {n:,} CVE records that reference a GHSA from {cve_list.name}")

    async def go() -> dict[str, object]:
        async with HttpClient(
            _token(),
            github_budget=budget,
            deadline=time.monotonic() + minutes * 60,
            nvd_api_key=os.environ.get("NVD_API_KEY"),
        ) as http:
            return (await Tracker(store, http, cfg).run()).__dict__

    try:
        report = asyncio.run(go())
    finally:
        store.export_jsonl(state)  # keep progress even if the run fails
    events = report.pop("events")
    typer.echo(json.dumps(report, indent=1, default=str))
    for e in events[:40]:  # type: ignore[index]
        typer.echo(f"  {e}")


@app.command()
def publish(
    state: StateDir = Path("tracker/state"),
    out: Annotated[Path, typer.Option(help="Output directory for the site and feed.")] = Path("tracker/site"),
    assets: Annotated[Path, typer.Option(help="Brand assets to copy (favicon, avatar).")] = Path("brand/assets"),
    screenshots: Annotated[Path, typer.Option(help="Screenshots for the scan page (PNG).")] = Path("docs/screenshots"),
    top_packages: Annotated[
        Path, typer.Option(help="Top packages per ecosystem (make_top_packages.py), for coverage per ecosystem.")
    ] = Path("tracker/seeds/top-packages.json"),
    analytics_id: Annotated[
        str | None,
        typer.Option(
            envvar="LIMBOWATCH_GA_ID", help="GA4 measurement ID (G-…); adds Google Analytics behind a consent banner."
        ),
    ] = None,
) -> None:
    """Write the site, feed (all.zip, index.json, one JSON per record) and metrics.json from the state."""
    store = _load(state)
    now = datetime.now(UTC)
    all_items = items(store)
    m = metrics(store, now, json.loads(top_packages.read_text()) if top_packages.exists() else None)
    modified = m["generated_at"]
    records, zipped = feed_mod.build(all_items, modified)
    (out / "feed").mkdir(parents=True, exist_ok=True)
    (out / "feed" / "all.zip").write_bytes(zipped)
    (out / "feed" / "index.json").write_text(
        dumps(
            {
                "generated_at": modified,
                "count": len(records),
                "ids": [r["id"] for r in records],
                "attribution": m["attribution"],
            }
        )
    )
    # The same records per ecosystem, in OSV's download layout, for OSV-Scanner (FINDINGS F-073, F-074).
    # nginx sends each zip's CRC-32C as X-Goog-Hash, from the map written here (deploy/site/nginx.conf).
    zips = feed_mod.by_ecosystem(records)
    hashes = []
    for eco, data in zips.items():
        (out / "osv" / eco).mkdir(parents=True, exist_ok=True)
        (out / "osv" / eco / "all.zip").write_bytes(data)
        hashes.append(f'"/osv/{eco}/all.zip" "{feed_mod.goog_hash(data)}";\n')
    (out / "osv" / "ecosystems.txt").write_text("".join(f"{e}\n" for e in zips))
    (out / "osv" / "crc32c.map").write_text("".join(hashes))
    (out / "osv" / "limbo-db.zip").write_bytes(feed_mod.bundle(zips))
    (out / "feed" / "repos.txt").write_text(repos_with_advisories(store, modified))
    (out / "feed" / "watchlist.json").write_text(json.dumps(watchlist(store, modified), separators=(",", ":")))
    (out / "metrics.json").write_text(dumps(m))
    for r in records:
        (out / "feed" / f"{r['id']}.json").write_text(dumps(r))
    # the feed page shows a real record: the newest pending one with a machine-readable range
    pending = {i.adv.ghsa_id: i for i in all_items if not i.assessment.likely_permanent}
    with_ranges = [r for r in records if r["id"] in pending and any("ranges" in a for a in r["affected"])]
    sample = max(with_ranges, key=lambda r: r.get("published") or "", default=None)
    for path, text in site_mod.build(
        all_items, m, now, events=all_events(store), sample=sample, analytics_id=analytics_id or None
    ).items():
        (out / path).parent.mkdir(parents=True, exist_ok=True)
        (out / path).write_text(text)
    for name, target in (
        ("favicon.svg", "favicon.svg"),
        ("avatar-500.png", "avatar-500.png"),
        ("social-preview-1280x640.png", "assets/social.png"),  # og:image on every page
        ("wordmark-on-dark.png", "press/kit/wordmark-on-dark.png"),
        ("wordmark-on-light.png", "press/kit/wordmark-on-light.png"),
        ("mark-on-light.svg", "press/kit/mark.svg"),
        ("avatar-1024.png", "press/kit/avatar.png"),
        ("contact.png", "assets/contact.png"),  # the press email as an image (brand/make_contact.py)
    ):
        if (assets / name).exists():
            (out / target).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(assets / name, out / target)
    for shot in sorted(screenshots.glob("*.png")) if screenshots.is_dir() else []:
        (out / "assets/screens").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(shot, out / "assets/screens" / shot.name)
    typer.echo(f"published {len(records)} advisories in limbo to {out}")


@app.command()
def report(
    state: StateDir = Path("tracker/state"),
    out: Annotated[Path, typer.Option(help="Directory for reports (YYYY-MM-DD.md and latest.md).")] = Path(
        "tracker/reports"
    ),
) -> None:
    """Write the daily Markdown report: current numbers and everything that changed since the last report."""
    store = _load(state)
    rep = report_mod.build(store)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{rep.date}.md").write_text(rep.markdown)
    (out / "latest.md").write_text(rep.markdown)
    report_mod.commit(store, rep)
    store.export_jsonl(state)
    typer.echo(str(out / f"{rep.date}.md"))


ISSUE_TRACKERS = ("gitlab", "gitea", "github")
IssuesPublic = Annotated[
    bool, typer.Option(help="Allow issues anyone can read (public Gitea, Forgejo and GitHub repos).")
]
IssuesMaxNew = Annotated[
    int, typer.Option(min=0, help="Open at most this many new issues a run (per project); the rest open later.")
]
OsvCommits = Annotated[
    bool,
    typer.Option(
        help="Ask OSV which of its records include each pinned upstream commit (a submodule's, a CMake fetch's): "
        "sends those commit hashes to OSV."
    ),
]
ResolveMaven = Annotated[
    bool,
    typer.Option(
        help="Resolve pom.xml's transitive dependencies through deps.dev and Maven Central, as Maven would. "
        "Without it, only direct dependencies with a literal version are checked."
    ),
]


def load_inventory(
    path: Path, sbom_file: Path | None, binary: str, include_ignored: bool = False, resolve_maven: bool = True
) -> Inventory:
    """A project's dependencies, from an SBOM or by running OSV-Scanner over its tree."""
    if sbom_file is not None:
        return sbom.parse(sbom_file.read_text(errors="replace"), sbom_file.name)
    _check_osv_scanner(binary)
    try:
        inv = osv_scanner.run(path, binary, include_ignored=include_ignored, resolve_maven=resolve_maven)
    except osv_scanner.InventoryError as e:
        raise typer.Exit(_fail(str(e))) from e
    return upstream_inventory.combine(inv, upstream_inventory.detect_safely(path, include_ignored=include_ignored))


def _check_osv_scanner(binary: str) -> None:
    if shutil.which(binary) is None:
        raise typer.BadParameter(
            f"{binary} not found. Install OSV-Scanner {osv_scanner.TESTED_VERSION} "
            "(https://google.github.io/osv-scanner/installation/), or pass --sbom.",
            param_hint="--osv-scanner",
        )
    found = osv_scanner.version(binary)
    if found != osv_scanner.TESTED_VERSION:
        typer.echo(f"warning: tested with osv-scanner {osv_scanner.TESTED_VERSION}, found {found}", err=True)


def _fail(msg: str) -> int:
    typer.echo(f"error: {msg}", err=True)
    return 2


@app.command()
def inventory(
    path: Annotated[Path, typer.Argument(help="Project directory.")] = Path("."),
    sbom_file: Annotated[Path | None, typer.Option("--sbom", help="CycloneDX or SPDX JSON instead of a tree.")] = None,
    binary: Annotated[str, typer.Option("--osv-scanner", help="OSV-Scanner executable.")] = "osv-scanner",
    fmt: Annotated[str, typer.Option("--format", help="table or json.")] = "table",
    resolve_maven: ResolveMaven = True,
) -> None:
    """List the dependencies Limbowatch would check, and every one it can't, with the reason."""
    inv = load_inventory(path, sbom_file, binary, resolve_maven=resolve_maven)
    if fmt == "json":
        typer.echo(inv.model_dump_json(indent=1))
        return
    typer.echo(f"{len(inv.dependencies):,} dependencies from {len(inv.sources):,} files ({inv.tool})")
    for d in inv.dependencies:
        note = f"  ({d.note})" if d.note else ""
        typer.echo(f"  {d.ecosystem:<9} {d.name} {d.version}  {d.source}:{d.line}{note}")
    if inv.upstreams:
        typer.echo(f"\n{len(inv.upstreams):,} upstream sources (git, CMake, Bazel, vcpkg, Conan, meson):")
        for src in inv.upstreams:
            where = f"{src.host}/{src.repo}" if src.repo else (src.url or "")
            pin = src.ref or (f"version {src.version}" if src.version else "")
            what = "  ".join(x for x in (src.name, where, pin) if x)
            detail = f"  ({src.detail})" if src.detail else ""
            typer.echo(f"  {src.kind.value:<21} {what}  {src.source}:{src.line}{detail}")
    if inv.unresolved:
        typer.echo(f"\n{len(inv.unresolved):,} can't be checked:")
        for u in inv.unresolved:
            whole = u.reason in (Unchecked.LOCKFILE_UNREADABLE, Unchecked.NO_LOCKFILES, Unchecked.TRANSITIVE,
                                 Unchecked.NO_GRADLE_LOCKFILE)  # fmt: skip
            what = f"{u.name} {u.version}".strip() or ("(whole file)" if whole else "(no package name)")
            detail = f": {u.detail}" if u.detail else ""
            typer.echo(f"  {u.source}:{u.line}  {what}  {u.reason.value}{detail}")


def _base(path: Path) -> str:
    """The scanned directory relative to the working directory (the repo root in CI), or "" if outside it."""
    try:
        rel = path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return ""
    return "" if rel == "." else rel


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Project directory.")] = Path("."),
    sbom_file: Annotated[Path | None, typer.Option("--sbom", help="CycloneDX or SPDX JSON instead of a tree.")] = None,
    fmt: Annotated[
        str | None,
        typer.Option("--format", "-f", help=f"Format on stdout [default: table]: {', '.join(output.FORMATS)}."),
    ] = None,
    outputs: Annotated[
        list[str] | None,
        typer.Option(
            "--output",
            "-o",
            help="FORMAT or FORMAT=FILE, repeatable: one scan, many reports, e.g. -o table -o sarif=out.sarif "
            "-o junit=junit.xml. FORMAT alone (or FILE '-') writes to stdout.",
        ),
    ] = None,
    color: Annotated[
        str, typer.Option(help="Colour the table: auto, always or never (NO_COLOR is honoured).")
    ] = "auto",
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Nothing on stdout; files and exit code only.")] = False,
    state_file: Annotated[Path | None, typer.Option("--state", help="JSON state file: report what changed.")] = None,
    fail_on: Annotated[str, typer.Option(help="Fail at or above: critical, high, medium, low, or none.")] = "low",
    fail_on_unknown: Annotated[bool, typer.Option(help="Fail on findings with no severity.")] = True,
    ignore: Annotated[list[str] | None, typer.Option(help="Accept an advisory by GHSA or CVE ID; repeatable.")] = None,
    ignore_file: Annotated[Path | None, typer.Option(help="File of accepted IDs, one per line, # comments.")] = None,
    upstream: Annotated[bool, typer.Option(help="Also check source repos the tracker doesn't cover.")] = True,
    cache: Annotated[Path | None, typer.Option(help="Where the feed is cached [default: ~/.cache/limbowatch].")] = None,
    binary: Annotated[str, typer.Option("--osv-scanner", help="OSV-Scanner executable.")] = "osv-scanner",
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show the evidence for every finding.")] = False,
    scan_ignored: Annotated[bool, typer.Option(help="Also read lockfiles a .gitignore excludes.")] = False,
    resolve_maven: ResolveMaven = True,
    osv_commits: OsvCommits = True,
    issues: Annotated[
        str | None, typer.Option(help="Open and update issues: gitlab, gitea (also Forgejo) or github.")
    ] = None,
    issues_url: Annotated[
        str | None,
        typer.Option(help="Tracker base URL [default: $CI_SERVER_URL; for github, $GITHUB_API_URL or github.com]."),
    ] = None,
    issues_project: Annotated[
        str | None,
        typer.Option(help="GitLab project, or owner/repo [default: $CI_PROJECT_PATH or $GITHUB_REPOSITORY]."),
    ] = None,
    issues_min_severity: Annotated[str, typer.Option(help="Open issues at or above this severity.")] = "low",
    issues_public: IssuesPublic = False,
    issues_confidential: Annotated[bool, typer.Option(help="GitLab: open confidential issues.")] = True,
    issues_max_new: IssuesMaxNew = 50,
    issues_dry_run: Annotated[bool, typer.Option(help="Print the issue changes instead of making them.")] = False,
) -> None:
    """Check a project's dependencies against advisories in limbo.

    Exit codes: 0 passed, 1 a finding at or above --fail-on, 2 an error (nothing was judged).
    """
    if fail_on not in (*output.SEVERITIES, "none"):
        raise typer.BadParameter(f"--fail-on wants one of {', '.join((*output.SEVERITIES, 'none'))}, not {fail_on!r}")
    if color not in ("auto", "always", "never"):
        raise typer.BadParameter("--color wants auto, always or never")
    stdout_fmt, targets = _outputs(fmt, outputs or [])
    accepted = _accepted(ignore, ignore_file)
    tracker_token = os.environ.get("LIMBOWATCH_ISSUES_TOKEN")
    if issues is not None and issues not in ISSUE_TRACKERS:
        raise typer.BadParameter(f"--issues wants {', '.join(ISSUE_TRACKERS[:-1])} or {ISSUE_TRACKERS[-1]}")
    if issues and not tracker_token and not issues_dry_run:
        raise typer.BadParameter("set LIMBOWATCH_ISSUES_TOKEN to a token that can write issues", param_hint="--issues")
    cache = cache or _cache_dir()
    inv = load_inventory(path, sbom_file, binary, scan_ignored, resolve_maven)
    for skipped in inv.skipped:
        typer.echo(f"limbowatch: skipped {skipped}: a report from an earlier Limbowatch scan, not an SBOM", err=True)
    old = json.loads(state_file.read_text()) if state_file and state_file.exists() else None
    now = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")

    changes: list[watch_state.Change] | None = None
    log_lines: list[str] = []
    issues_error: list[str] = []

    async def run() -> tuple[watch_scan.ScanResult, str | None]:
        nonlocal changes
        async with HttpClient(_token()) as http:
            feed = await watch_scan.fetch(http, watch_scan.FEED_URL, cache)
            wl_doc = json.loads(await watch_scan.fetch(http, watch_scan.WATCHLIST_URL, cache))
            res = await watch_scan.scan(inv, http, feed_zip=feed, watchlist=dict(wl_doc.get("repos") or {}),
                                        now=datetime.now(UTC), upstream_check=upstream, git_cache=cache,
                                        osv_commits=osv_commits)  # fmt: skip
            gone = sorted(watch_state.vanished(old, res.findings))
            seen = await asyncio.gather(*(osv_source.present(http, g) for g in gone))
            visible = {g for g, v in zip(gone, seen, strict=True) if v}
            if state_file is not None:
                new_state, changes = watch_state.diff(old, res.findings, now, visible)
                state_file.parent.mkdir(parents=True, exist_ok=True)
                state_file.write_text(json.dumps(new_state, indent=1, sort_keys=True) + "\n")
            if issues:
                try:
                    log_lines.extend(await _sync_issues(http, res, inv, changes or [], issues, tracker_token or "",
                                                        issues_url, issues_project, issue_policy,
                                                        issues_confidential, issues_dry_run))  # fmt: skip
                except (trackers.TrackerError, RuntimeError) as e:  # the scan's reports are still written
                    issues_error.append(str(e))
                    log_lines.extend(_unsent_lines(changes or []))
            return res, wl_doc.get("generated_at")

    issue_policy = watch_issues.Policy(issues_min_severity, issues_public, issues_max_new)
    try:
        res, feed_at = asyncio.run(run())
    except (RuntimeError, OSError) as e:
        raise typer.Exit(_fail(str(e))) from e
    base = _base(path) if sbom_file is None else ""
    rep = output.Report(res.findings, res.unresolved, res.stats, inv.tool, feed_at, changes, accepted, base,
                        fail_on, fail_on_unknown, now, str(sbom_file or path.resolve().name or path))  # fmt: skip

    for name, dest in targets:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(output.FORMATS[name](rep))
    for line in log_lines:
        typer.echo(line, err=True)
    if stdout_fmt == "table" and not quiet:
        on, links = _color(color)
        # click strips ANSI codes when stdout isn't a terminal unless told otherwise: CI logs are such a case
        typer.echo(output.table(rep, verbose, output.Paint(on, links)), nl=False, color=on)
    elif not quiet:
        typer.echo(output.FORMATS[stdout_fmt](rep), nl=False)
    if stdout_fmt != "table" or quiet:  # the verdict still reaches the CI log
        failed, why = output.verdict(rep)
        typer.echo(f"limbowatch: {'FAILED' if failed else 'PASSED'}: {why}", err=True)
    if issues_error:  # the reports are written, but the run didn't do all it was asked to
        raise typer.Exit(_fail(f"issues couldn't be updated: {issues_error[0]}"))
    if rep.failed:
        raise typer.Exit(1)


def _accepted(ignore: list[str] | None, ignore_file: Path | None) -> set[str]:
    accepted = set(ignore or [])
    if ignore_file is not None:
        accepted |= {ln.split("#", 1)[0].strip() for ln in ignore_file.read_text().splitlines()} - {""}
    return accepted


def _cache_dir() -> Path:
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "limbowatch"


def _outputs(
    fmt: str | None, specs: list[str], formats: Collection[str] = tuple(output.FORMATS)
) -> tuple[str, list[tuple[str, Path]]]:
    """The stdout format and the FORMAT=FILE targets from --format and repeated --output."""
    known = ", ".join(formats)
    stdout = [fmt] if fmt else []
    files: list[tuple[str, Path]] = []
    for spec in specs:
        name, eq, file = spec.partition("=")
        if name not in formats or (eq and not file):
            raise typer.BadParameter(f"--output wants FORMAT or FORMAT=FILE, with FORMAT one of {known}; got {spec!r}")
        if not eq or file == "-":
            stdout.append(name)
        else:
            files.append((name, Path(file)))
    if fmt is not None and fmt not in formats:
        raise typer.BadParameter(f"--format wants one of {known}; got {fmt!r}")
    if len(stdout) > 1:
        raise typer.BadParameter(
            f"only one format can go to stdout; got {', '.join(stdout)}. Send the others to files."
        )
    return (stdout[0] if stdout else "table"), files


async def _sync_issues(
    http: HttpClient,
    res: watch_scan.ScanResult,
    inv: Inventory,
    changes: list[watch_state.Change],
    kind: str,
    token: str,
    url: str | None,
    project: str | None,
    policy: watch_issues.Policy,
    confidential: bool,
    dry_run: bool,
) -> list[str]:
    """Open, comment on and close issues for this scan's findings (watch.issues)."""
    if kind == "github":
        url = url or os.environ.get("GITHUB_API_URL") or "https://api.github.com"
        project = project or os.environ.get("GITHUB_REPOSITORY")
    else:
        url = url or os.environ.get("CI_SERVER_URL") or os.environ.get("GITHUB_SERVER_URL")
        project = project or os.environ.get("CI_PROJECT_PATH") or os.environ.get("GITHUB_REPOSITORY")
    if not url or not project:
        where = "GITHUB_REPOSITORY" if kind == "github" else "CI_SERVER_URL and CI_PROJECT_PATH"
        raise RuntimeError(f"--issues needs --issues-url and --issues-project (or {where})")
    tracker: trackers.GitLab | trackers.Gitea | trackers.GitHub
    if kind == "gitlab":
        tracker = trackers.GitLab(http, project, token, url, confidential)
    elif kind == "github":
        tracker = trackers.GitHub(http, project, token, github_host.api_url(url, _actions_api()))
    else:
        tracker = trackers.Gitea(http, project, token, url)
    try:
        await tracker.prepare()
        existing = await tracker.issues()
    except BudgetExhausted:
        return [f"issues: {tracker.name}'s rate limit is used up; nothing changed this run", *_unsent_lines(changes)]
    if tracker.public and not policy.allow_public:
        note = f"{tracker.name} issues in {project} are public; not opening new ones (--issues-public allows it)"
    else:
        note = ""
    current = watch_state.entries(res.findings, "")
    one: dict[str, dict[str, Any]] = {}
    for f in res.findings:
        one.setdefault(f.key, f.model_dump(mode="json"))
    installed: dict[tuple[str, str], list[str]] = {}
    for d in inv.dependencies:
        installed.setdefault((d.ecosystem, norm_name(d.ecosystem, d.name)), []).append(d.version)
    gone: dict[str, watch_issues.Gone] = {}
    present = {f"{u.host}/{u.repo}" for u in res.upstreams if u.repo}
    for key, issue in existing.items():
        if not issue.open or key in current:
            continue
        meta = issue.meta
        eco = str(meta.get("ecosystem", ""))
        if eco == UPSTREAM:  # an upstream source: closed only when checked in full or removed, never when unchecked
            name = str(meta.get("package", ""))
            if name in res.upstreams_checked:
                visible = await osv_source.present(http, str(meta.get("ghsa_id")))
                gone[key] = watch_issues.Gone.VISIBLE if visible else watch_issues.Gone.FIXED
            elif name not in present:
                gone[key] = watch_issues.Gone.FIXED
            continue
        versions = installed.get((eco, norm_name(eco, str(meta.get("package", "")))), [])
        osv_eco = info(eco).osv
        ids: list[set[str] | None] = []
        if versions and osv_eco and await osv_source.present(http, str(meta.get("ghsa_id"))):
            ids = list(await asyncio.gather(*(osv_source.affecting(http, osv_eco, str(meta["package"]), v)
                                              for v in versions)))  # fmt: skip
        verdict = watch_issues.still_affected(meta, versions, ids) if versions else False
        if verdict is False:
            gone[key] = watch_issues.Gone.FIXED
        elif verdict is True and ids:
            gone[key] = watch_issues.Gone.VISIBLE
    actions = watch_issues.plan(current, one, existing, changes, gone, policy, tracker.public)
    lines = [note] if note else []
    if dry_run:
        later = sum(1 for a in actions if a.kind == "later")
        lines += [f"would {a.kind}: {a.title or ('#' + str(a.issue.number) if a.issue else a.key)}"
                  for a in actions if a.kind != "later"]  # fmt: skip
        return lines + ([f"would leave {later} new issue(s) for later runs (--issues-max-new)"] if later else [])
    return [*lines, *await watch_issues.apply(tracker, actions)]


def _source_token(hosts: set[str]) -> str | None:
    """LIMBOWATCH_SOURCE_TOKEN reads the groups and clones their projects; it's sent to one host only."""
    token = os.environ.get("LIMBOWATCH_SOURCE_TOKEN") or os.environ.get("LIMBOWATCH_ISSUES_TOKEN")
    if token and len(hosts) > 1:
        raise typer.BadParameter(
            f"the sources are on {len(hosts)} hosts ({', '.join(sorted(hosts))}), and one token would be sent to all "
            "of them; run `limbowatch watch` once per host"
        )
    return token


async def _list_sources(
    http: HttpClient, groups: list[tuple[str, str]], orgs: list[tuple[str, str]], gh_orgs: list[tuple[str, str]],
    git_urls: list[str], token: str | None, include_archived: bool,
) -> list[hosts.Listing]:  # fmt: skip
    listings = list(
        await asyncio.gather(
            *(gitlab_host.list_group(http, base, path, token, include_archived) for base, path in groups),
            *(gitea_host.list_org(http, base, path, token, include_archived) for base, path in orgs),
            *(
                github_host.list_org(
                    http, base, path, token, include_archived, github_host.api_url(base, _actions_api())
                )
                for base, path in gh_orgs
            ),
        )
    )
    for ls in listings:
        if ls.kind is hosts.HostKind.GITHUB and not ls.error and not ls.note:
            ls.note = _github_token_note(token)
    for url in git_urls:
        listings.append(hosts.Listing(hosts.redact(url), hosts.HostKind.GIT, [hosts.git_project(url)]))
    return listings


_STOP_HOST = ("rate limit", trackers.NO_LABELS)  # no more issue writes to that host this run


def _unsent_lines(changes: list[watch_state.Change]) -> list[str]:
    lines = watch_issues.unsent(changes)
    return ["issues: these changes weren't commented on, and won't be again:", *lines] if lines else []


def _github_org(value: str, default_base: str) -> tuple[str, str]:
    """`acme`, `https://github.com/acme` or `https://github.com/orgs/acme/repositories` → (server, "acme")."""
    base, path = hosts.split_url(value, default_base.rstrip("/"))
    parts = path.split("/")
    if parts[0] == "orgs" and len(parts) > 1:
        parts = parts[1:]
    if parts[1:] in ([], ["repositories"]):
        if urlsplit(base).hostname == "www.github.com":
            base = "https://github.com"
        return base, parts[0]
    raise hosts.SourceError(f"--github-org wants an organization or user, like https://github.com/acme; got {value!r}")


def _actions_api() -> dict[str, str]:
    """The job's own GitHub server and its API, from Actions (GITHUB_SERVER_URL, GITHUB_API_URL)."""
    server, api = os.environ.get("GITHUB_SERVER_URL"), os.environ.get("GITHUB_API_URL")
    return {server: api} if server and api else {}


def _github_token_note(token: str | None) -> str | None:
    """GitHub lists what a token can see without saying that more exists (F-147)."""
    if not token:
        return "no LIMBOWATCH_SOURCE_TOKEN: public repositories only"
    if token.startswith("github_pat_"):
        return "a fine-grained token lists only the repositories it was given access to"
    if os.environ.get("GITHUB_ACTIONS") == "true" and token.startswith("ghs_"):
        return ("the token is an app installation token, such as the job's GITHUB_TOKEN, which sees public "
                "repositories and its own only; set LIMBOWATCH_SOURCE_TOKEN to one that reads the rest")  # fmt: skip
    return None


def _state_path(state_dir: Path, project: hosts.Project) -> Path:
    """`<state>/<host>/<group>/<project>.json`; the path was checked by hosts.safe_path."""
    return state_dir / project.host.replace(":", "_") / f"{hosts.safe_path(project.path)}.json"


@app.command()
def watch(
    gitlab_group: Annotated[
        list[str] | None,
        typer.Option(
            help="GitLab group URL (https://gitlab.example.com/group/sub), or a path with --gitlab-url; "
            "repeatable. Subgroups are included."
        ),
    ] = None,
    gitea_org: Annotated[
        list[str] | None,
        typer.Option(help="Gitea or Forgejo organization (or user) URL, e.g. https://codeberg.org/org; repeatable."),
    ] = None,
    github_org: Annotated[
        list[str] | None,
        typer.Option(help="GitHub organization or user (https://github.com/name, or a name); repeatable."),
    ] = None,
    git: Annotated[list[str] | None, typer.Option(help="A git repository's https URL; repeatable.")] = None,
    gitlab_url: Annotated[
        str | None, typer.Option(help="Base URL for --gitlab-group paths [default: $CI_SERVER_URL or gitlab.com].")
    ] = None,
    github_url: Annotated[
        str | None,
        typer.Option(
            help="GitHub server for --github-org names (Enterprise Server) [default: $GITHUB_SERVER_URL or github.com]."
        ),
    ] = None,
    exclude: Annotated[
        list[str] | None, typer.Option(help="Skip projects whose path matches this glob (group/legacy-*); repeatable.")
    ] = None,
    include_archived: Annotated[bool, typer.Option(help="Also check archived projects.")] = False,
    state_dir: Annotated[
        Path | None, typer.Option("--state", help="Directory of per-project state files: report what changed.")
    ] = None,
    fmt: Annotated[
        str | None,
        typer.Option("--format", "-f", help=f"Format on stdout [default: table]: {', '.join(org_output.FORMATS)}."),
    ] = None,
    outputs: Annotated[
        list[str] | None,
        typer.Option("--output", "-o", help="FORMAT or FORMAT=FILE, repeatable (table, json, markdown)."),
    ] = None,
    color: Annotated[str, typer.Option(help="Colour the table: auto, always or never.")] = "auto",
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Nothing on stdout; files and exit code only.")] = False,
    fail_on: Annotated[str, typer.Option(help="Fail at or above: critical, high, medium, low, or none.")] = "low",
    fail_on_unknown: Annotated[bool, typer.Option(help="Fail on findings with no severity.")] = True,
    ignore: Annotated[list[str] | None, typer.Option(help="Accept an advisory by GHSA or CVE ID; repeatable.")] = None,
    ignore_file: Annotated[Path | None, typer.Option(help="File of accepted IDs, one per line, # comments.")] = None,
    upstream: Annotated[bool, typer.Option(help="Also check source repos the tracker doesn't cover.")] = True,
    cache: Annotated[Path | None, typer.Option(help="Where the feed is cached [default: ~/.cache/limbowatch].")] = None,
    binary: Annotated[str, typer.Option("--osv-scanner", help="OSV-Scanner executable.")] = "osv-scanner",
    jobs: Annotated[int, typer.Option(help="Projects cloned and inventoried at a time.")] = 4,
    resolve_maven: ResolveMaven = True,
    osv_commits: OsvCommits = True,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show every project's unchecked dependencies.")
    ] = False,
    issues: Annotated[
        bool,
        typer.Option(help="Open and update issues in each GitLab, Gitea or GitHub project (LIMBOWATCH_ISSUES_TOKEN)."),
    ] = False,
    issues_min_severity: Annotated[str, typer.Option(help="Open issues at or above this severity.")] = "low",
    issues_public: IssuesPublic = False,
    issues_confidential: Annotated[bool, typer.Option(help="GitLab: open confidential issues.")] = True,
    issues_max_new: IssuesMaxNew = 50,
    issues_dry_run: Annotated[bool, typer.Option(help="Print the issue changes instead of making them.")] = False,
) -> None:
    """Check every project of GitLab groups, Gitea or Forgejo orgs, GitHub orgs, or git URLs, in one run (org-wide
    mode).

    Each project is cloned shallowly and inventoried like `scan`; each source repo is polled once for all
    projects. Run it on a schedule. Exit codes: 0 passed, 1 a project's findings meet --fail-on, 2 a source
    couldn't be listed or no project could be checked. LIMBOWATCH_SOURCE_TOKEN reads private groups.
    """
    if fail_on not in (*output.SEVERITIES, "none"):
        raise typer.BadParameter(f"--fail-on wants one of {', '.join((*output.SEVERITIES, 'none'))}, not {fail_on!r}")
    if color not in ("auto", "always", "never"):
        raise typer.BadParameter("--color wants auto, always or never")
    stdout_fmt, targets = _outputs(fmt, outputs or [], tuple(org_output.FORMATS))
    accepted = _accepted(ignore, ignore_file)
    gl_base = gitlab_url or os.environ.get("CI_SERVER_URL") or "https://gitlab.com"
    try:
        groups = [hosts.split_url(g, gl_base) for g in gitlab_group or []]
        orgs = [hosts.split_url(o) for o in gitea_org or []]
        gh_orgs = [_github_org(o, github_url or os.environ.get("GITHUB_SERVER_URL") or "https://github.com")
                   for o in github_org or []]  # fmt: skip
        git_projects = [hosts.git_project(u) for u in git or []]
    except hosts.SourceError as e:
        raise typer.BadParameter(str(e)) from e
    if not (groups or orgs or gh_orgs or git_projects):
        raise typer.BadParameter("name at least one --gitlab-group, --gitea-org, --github-org or --git")
    token = _source_token({urlsplit(b).netloc for b, _ in groups + orgs + gh_orgs} | {p.host for p in git_projects})
    issues_token = os.environ.get("LIMBOWATCH_ISSUES_TOKEN")
    if issues and not issues_token and not issues_dry_run:
        raise typer.BadParameter("set LIMBOWATCH_ISSUES_TOKEN to a token that can write issues", param_hint="--issues")
    _check_osv_scanner(binary)
    cache = cache or _cache_dir()
    now = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    policy = watch_issues.Policy(issues_min_severity, issues_public, issues_max_new)
    log_lines: list[str] = []
    rate_limited: set[str] = set()  # hosts whose issue writes hit a rate limit this run: no more tries there

    def take(path: Path) -> Inventory:
        inv = osv_scanner.run(path, binary, resolve_maven=resolve_maven)
        return upstream_inventory.combine(inv, upstream_inventory.detect_safely(path))

    async def run() -> org_output.OrgReport:
        async with HttpClient(_token()) as http:
            listings = await _list_sources(http, groups, orgs, gh_orgs, git or [], token, include_archived)
            feed = await watch_scan.fetch(http, watch_scan.FEED_URL, cache)
            wl_doc = json.loads(await watch_scan.fetch(http, watch_scan.WATCHLIST_URL, cache))
            w = await org_mod.run(listings, http, feed_zip=feed, watchlist=dict(wl_doc.get("repos") or {}),
                                  now=datetime.now(UTC), inventory=take, token=token, exclude=exclude or [],
                                  upstream_check=upstream, jobs=jobs, git_cache=cache,
                                  osv_commits=osv_commits)  # fmt: skip
            olds: dict[str, Any] = {}
            for c in w.checked:
                f = _state_path(state_dir, c.project) if state_dir and c.result else None
                olds[c.project.name] = json.loads(f.read_text()) if f and f.exists() else None
            gone = sorted(
                {
                    g
                    for c in w.checked
                    if c.result
                    for g in watch_state.vanished(olds[c.project.name], c.result.findings)
                }
            )
            seen = await asyncio.gather(*(osv_source.present(http, g) for g in gone))
            visible = {g for g, v in zip(gone, seen, strict=True) if v}
            entries: list[org_output.Entry] = []
            for c in w.checked:
                if c.result is None:
                    entries.append(org_output.Entry(c.project, None, c.commit, c.error))
                    continue
                changes: list[watch_state.Change] | None = None
                if state_dir is not None:
                    new_state, changes = watch_state.diff(olds[c.project.name], c.result.findings, now, visible)
                    f = _state_path(state_dir, c.project)
                    f.parent.mkdir(parents=True, exist_ok=True)
                    f.write_text(json.dumps(new_state | {"project": c.project.web_url, "commit": c.commit},
                                            indent=1, sort_keys=True) + "\n")  # fmt: skip
                rep = output.Report(c.result.findings, c.result.unresolved, c.result.stats, c.result.inventory.tool,
                                    wl_doc.get("generated_at"), changes, accepted, "", fail_on, fail_on_unknown, now,
                                    c.project.name)  # fmt: skip
                entries.append(org_output.Entry(c.project, rep, c.commit))
                if issues and c.project.kind is not hosts.HostKind.GIT:
                    if c.project.host in rate_limited:
                        lines = ["issues: not updated this run (an earlier project hit the host's rate limit, or "
                                 "its token can't label issues)", *_unsent_lines(changes or [])]  # fmt: skip
                    else:
                        try:
                            lines = await _sync_issues(
                                http, c.result, c.result.inventory, changes or [], c.project.kind.value,
                                issues_token or "", c.project.base_url, c.project.path, policy, issues_confidential,
                                issues_dry_run,
                            )  # fmt: skip
                        except (trackers.TrackerError, RuntimeError) as e:
                            lines = [f"issues: {e}", *_unsent_lines(changes or [])]
                        if any(stop in ln for ln in lines for stop in _STOP_HOST):
                            rate_limited.add(c.project.host)
                    log_lines.extend(f"{c.project.name}: {ln}" for ln in lines)
            if issues:
                n_git = sum(1 for e in entries if e.project.kind is hosts.HostKind.GIT)
                if n_git:
                    log_lines.append(f"issues: {n_git} plain git project(s) have no issue tracker; none opened")
            return org_output.OrgReport(entries, listings, w.skipped, w.stats, wl_doc.get("generated_at"), now,
                                        fail_on)  # fmt: skip

    try:
        rep = asyncio.run(run())
    except (RuntimeError, OSError, hosts.SourceError) as e:
        raise typer.Exit(_fail(str(e))) from e
    for name, dest in targets:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(org_output.FORMATS[name](rep))
    for line in log_lines:
        typer.echo(line, err=True)
    if stdout_fmt == "table" and not quiet:
        on, links = _color(color)
        typer.echo(org_output.table(rep, verbose, output.Paint(on, links)), nl=False, color=on)
    elif not quiet:
        typer.echo(org_output.FORMATS[stdout_fmt](rep), nl=False)
    if stdout_fmt != "table" or quiet:
        word, why = org_output.verdict(rep)
        typer.echo(f"limbowatch: {word}: {why}", err=True)
    if rep.exit_code:
        raise typer.Exit(rep.exit_code)


def main() -> None:
    """The `limbowatch` command. Exit codes stay a contract even when something unexpected breaks: 0 passed,
    1 a finding meets --fail-on, 2 couldn't run. Python ends an uncaught exception with 1, which CI would read
    as a finding."""
    try:
        app()
    except Exception as e:  # typer re-raises what its commands don't handle: a crash, not a finding
        traceback.print_exc()
        typer.echo(f"error: unexpected {type(e).__name__}: {e}", err=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
