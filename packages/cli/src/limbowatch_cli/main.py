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
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from limbowatch.ecosystems import info
from limbowatch.http import HttpClient
from limbowatch.inventory import osv_scanner, sbom
from limbowatch.models import Inventory, Unchecked
from limbowatch.publish import all_events, dumps, items, metrics, repos_with_advisories, watchlist
from limbowatch.publish import feed as feed_mod
from limbowatch.publish import report as report_mod
from limbowatch.publish import site as site_mod
from limbowatch.sources import osv as osv_source
from limbowatch.store import Store
from limbowatch.tracker import Tracker, TrackerConfig, import_cve_list
from limbowatch.versions import norm_name
from limbowatch.watch import issues as watch_issues
from limbowatch.watch import output, trackers
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
    cfg = TrackerConfig(seeds=seed or [], nvd=nvd, max_nvd=max_nvd, checkpoint=lambda: store.export_jsonl(state))

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
    m = metrics(store, now)
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


def load_inventory(path: Path, sbom_file: Path | None, binary: str, include_ignored: bool = False) -> Inventory:
    """A project's dependencies, from an SBOM or by running OSV-Scanner offline over its tree."""
    if sbom_file is not None:
        return sbom.parse(sbom_file.read_text(errors="replace"), sbom_file.name)
    if shutil.which(binary) is None:
        raise typer.BadParameter(
            f"{binary} not found. Install OSV-Scanner {osv_scanner.TESTED_VERSION} "
            "(https://google.github.io/osv-scanner/installation/), or pass --sbom.",
            param_hint="--osv-scanner",
        )
    found = osv_scanner.version(binary)
    if found != osv_scanner.TESTED_VERSION:
        typer.echo(f"warning: tested with osv-scanner {osv_scanner.TESTED_VERSION}, found {found}", err=True)
    try:
        return osv_scanner.run(path, binary, include_ignored=include_ignored)
    except osv_scanner.InventoryError as e:
        raise typer.Exit(_fail(str(e))) from e


def _fail(msg: str) -> int:
    typer.echo(f"error: {msg}", err=True)
    return 2


@app.command()
def inventory(
    path: Annotated[Path, typer.Argument(help="Project directory.")] = Path("."),
    sbom_file: Annotated[Path | None, typer.Option("--sbom", help="CycloneDX or SPDX JSON instead of a tree.")] = None,
    binary: Annotated[str, typer.Option("--osv-scanner", help="OSV-Scanner executable.")] = "osv-scanner",
    fmt: Annotated[str, typer.Option("--format", help="table or json.")] = "table",
) -> None:
    """List the dependencies Limbowatch would check, and every one it can't, with the reason."""
    inv = load_inventory(path, sbom_file, binary)
    if fmt == "json":
        typer.echo(inv.model_dump_json(indent=1))
        return
    typer.echo(f"{len(inv.dependencies):,} dependencies from {len(inv.sources):,} files ({inv.tool})")
    for d in inv.dependencies:
        note = f"  ({d.note})" if d.note else ""
        typer.echo(f"  {d.ecosystem:<9} {d.name} {d.version}  {d.source}:{d.line}{note}")
    if inv.unresolved:
        typer.echo(f"\n{len(inv.unresolved):,} can't be checked:")
        for u in inv.unresolved:
            whole = u.reason in (Unchecked.LOCKFILE_UNREADABLE, Unchecked.NO_LOCKFILES)
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
    issues: Annotated[str | None, typer.Option(help="Open and update issues: gitlab or gitea (also Forgejo).")] = None,
    issues_url: Annotated[str | None, typer.Option(help="Tracker base URL [default: $CI_SERVER_URL].")] = None,
    issues_project: Annotated[
        str | None, typer.Option(help="GitLab project or Gitea owner/repo [default: $CI_PROJECT_PATH].")
    ] = None,
    issues_min_severity: Annotated[str, typer.Option(help="Open issues at or above this severity.")] = "low",
    issues_public: Annotated[bool, typer.Option(help="Allow issues anyone can read (public Gitea repos).")] = False,
    issues_confidential: Annotated[bool, typer.Option(help="GitLab: open confidential issues.")] = True,
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
    accepted = set(ignore or [])
    if ignore_file is not None:
        accepted |= {ln.split("#", 1)[0].strip() for ln in ignore_file.read_text().splitlines()} - {""}
    cache = cache or Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "limbowatch"
    inv = load_inventory(path, sbom_file, binary, scan_ignored)
    old = json.loads(state_file.read_text()) if state_file and state_file.exists() else None
    now = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")

    tracker_token = os.environ.get("LIMBOWATCH_ISSUES_TOKEN")
    if issues is not None and issues not in ("gitlab", "gitea"):
        raise typer.BadParameter("--issues wants gitlab or gitea")
    if issues and not tracker_token and not issues_dry_run:
        raise typer.BadParameter("set LIMBOWATCH_ISSUES_TOKEN to a token that can write issues", param_hint="--issues")
    changes: list[watch_state.Change] | None = None
    log_lines: list[str] = []

    async def run() -> tuple[watch_scan.ScanResult, str | None]:
        nonlocal changes
        async with HttpClient(_token()) as http:
            feed = await watch_scan.fetch(http, watch_scan.FEED_URL, cache)
            wl_doc = json.loads(await watch_scan.fetch(http, watch_scan.WATCHLIST_URL, cache))
            res = await watch_scan.scan(inv, http, feed_zip=feed, watchlist=dict(wl_doc.get("repos") or {}),
                                        now=datetime.now(UTC), upstream_check=upstream)  # fmt: skip
            gone = sorted(watch_state.vanished(old, res.findings))
            seen = await asyncio.gather(*(osv_source.present(http, g) for g in gone))
            visible = {g for g, v in zip(gone, seen, strict=True) if v}
            if state_file is not None:
                new_state, changes = watch_state.diff(old, res.findings, now, visible)
                state_file.parent.mkdir(parents=True, exist_ok=True)
                state_file.write_text(json.dumps(new_state, indent=1, sort_keys=True) + "\n")
            if issues:
                log_lines.extend(await _sync_issues(http, res, inv, changes or [], issues, tracker_token or "",
                                                    issues_url, issues_project, issue_policy, issues_confidential,
                                                    issues_dry_run))  # fmt: skip
            return res, wl_doc.get("generated_at")

    issue_policy = watch_issues.Policy(issues_min_severity, issues_public)
    try:
        res, feed_at = asyncio.run(run())
    except (RuntimeError, OSError) as e:
        raise typer.Exit(_fail(str(e))) from e
    base = _base(path) if sbom_file is None else ""
    rep = output.Report(res.findings, res.unresolved, res.stats, inv.tool, feed_at, changes, accepted, base,
                        fail_on, fail_on_unknown, now, str(sbom_file or path))  # fmt: skip

    for name, dest in targets:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(output.FORMATS[name](rep))
    for line in log_lines:
        typer.echo(line, err=True)
    if stdout_fmt == "table" and not quiet:
        typer.echo(output.table(rep, verbose, output.Paint(*_color(color))), nl=False)
    elif not quiet:
        typer.echo(output.FORMATS[stdout_fmt](rep), nl=False)
    if stdout_fmt != "table" or quiet:  # the verdict still reaches the CI log
        failed, why = output.verdict(rep)
        typer.echo(f"limbowatch: {'FAILED' if failed else 'PASSED'}: {why}", err=True)
    if rep.failed:
        raise typer.Exit(1)


def _outputs(fmt: str | None, specs: list[str]) -> tuple[str, list[tuple[str, Path]]]:
    """The stdout format and the FORMAT=FILE targets from --format and repeated --output."""
    known = ", ".join(output.FORMATS)
    stdout = [fmt] if fmt else []
    files: list[tuple[str, Path]] = []
    for spec in specs:
        name, eq, file = spec.partition("=")
        if name not in output.FORMATS or (eq and not file):
            raise typer.BadParameter(f"--output wants FORMAT or FORMAT=FILE, with FORMAT one of {known}; got {spec!r}")
        if not eq or file == "-":
            stdout.append(name)
        else:
            files.append((name, Path(file)))
    if fmt is not None and fmt not in output.FORMATS:
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
    url = url or os.environ.get("CI_SERVER_URL") or os.environ.get("GITHUB_SERVER_URL")
    project = project or os.environ.get("CI_PROJECT_PATH") or os.environ.get("GITHUB_REPOSITORY")
    if not url or not project:
        raise RuntimeError("--issues needs --issues-url and --issues-project (or CI_SERVER_URL and CI_PROJECT_PATH)")
    tracker: trackers.GitLab | trackers.Gitea = (
        trackers.GitLab(http, project, token, url, confidential)
        if kind == "gitlab"
        else trackers.Gitea(http, project, token, url)
    )
    await tracker.prepare()
    if tracker.public and not policy.allow_public:
        note = f"{tracker.name} issues in {project} are public; not opening new ones (--issues-public allows it)"
    else:
        note = ""
    existing = await tracker.issues()
    current = watch_state.entries(res.findings, "")
    one: dict[str, dict[str, Any]] = {}
    for f in res.findings:
        one.setdefault(f.key, f.model_dump(mode="json"))
    installed: dict[tuple[str, str], list[str]] = {}
    for d in inv.dependencies:
        installed.setdefault((d.ecosystem, norm_name(d.ecosystem, d.name)), []).append(d.version)
    gone: dict[str, watch_issues.Gone] = {}
    for key, issue in existing.items():
        if not issue.open or key in current:
            continue
        meta = issue.meta
        eco = str(meta.get("ecosystem", ""))
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
        return [*lines, *(f"would {a.kind}: {a.title or ('#' + str(a.issue.number) if a.issue else a.key)}"
                          for a in actions)]  # fmt: skip
    return [*lines, *await watch_issues.apply(tracker, actions)]


if __name__ == "__main__":
    app()
