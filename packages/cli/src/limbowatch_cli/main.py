"""`limbowatch track` runs the live tracker; `limbowatch publish` writes the feed, metrics and site;
`limbowatch inventory` lists what a project depends on and what can't be checked."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
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

app = typer.Typer(no_args_is_help=True, add_completion=False)

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
    for name, target in (("favicon.svg", "favicon.svg"), ("avatar-500.png", "avatar-500.png")):
        if (assets / name).exists():
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


def load_inventory(path: Path, sbom_file: Path | None, binary: str) -> Inventory:
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
        return osv_scanner.run(path, binary)
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


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Project directory.")] = Path("."),
    sbom_file: Annotated[Path | None, typer.Option("--sbom", help="CycloneDX or SPDX JSON instead of a tree.")] = None,
    fmt: Annotated[str, typer.Option("--format", help=f"Output on stdout: {', '.join(output.FORMATS)}.")] = "table",
    outputs: Annotated[
        list[str] | None, typer.Option("--output", help="FORMAT=FILE, repeatable, e.g. codequality=gl-cq.json.")
    ] = None,
    state_file: Annotated[Path | None, typer.Option("--state", help="JSON state file: report what changed.")] = None,
    fail_on: Annotated[str, typer.Option(help="Fail at or above: critical, high, medium, low, or none.")] = "low",
    fail_on_unknown: Annotated[bool, typer.Option(help="Fail on findings with no severity.")] = True,
    ignore: Annotated[list[str] | None, typer.Option(help="Accept an advisory by GHSA or CVE ID; repeatable.")] = None,
    ignore_file: Annotated[Path | None, typer.Option(help="File of accepted IDs, one per line, # comments.")] = None,
    upstream: Annotated[bool, typer.Option(help="Also check source repos the tracker doesn't cover.")] = True,
    cache: Annotated[Path | None, typer.Option(help="Where the feed is cached [default: ~/.cache/limbowatch].")] = None,
    binary: Annotated[str, typer.Option("--osv-scanner", help="OSV-Scanner executable.")] = "osv-scanner",
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show the evidence for every finding.")] = False,
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
    """Check a project's dependencies against advisories in limbo. Exit 1 when --fail-on is met, 2 on errors."""
    if fmt not in output.FORMATS or fail_on not in (*output.SEVERITIES, "none"):
        raise typer.BadParameter(f"unknown --format {fmt!r} or --fail-on {fail_on!r}")
    targets: list[tuple[str, Path]] = []
    for o in outputs or []:
        name, _, file = o.partition("=")
        if name not in output.FORMATS or not file:
            raise typer.BadParameter(f"--output wants FORMAT=FILE with FORMAT one of {', '.join(output.FORMATS)}")
        targets.append((name, Path(file)))
    accepted = set(ignore or [])
    if ignore_file is not None:
        accepted |= {ln.split("#", 1)[0].strip() for ln in ignore_file.read_text().splitlines()} - {""}
    cache = cache or Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "limbowatch"
    inv = load_inventory(path, sbom_file, binary)
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
    rep = output.Report(res.findings, res.unresolved, res.stats, inv.tool, feed_at, changes, accepted)

    typer.echo(output.table(rep, verbose) if fmt == "table" else output.FORMATS[fmt](rep), nl=False)
    for name, dest in targets:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(output.FORMATS[name](rep))
    for line in log_lines:
        typer.echo(line, err=True)
    if output.gate(rep, fail_on, fail_on_unknown):
        raise typer.Exit(1)


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
