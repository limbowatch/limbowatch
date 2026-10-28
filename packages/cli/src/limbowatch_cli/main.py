"""`limbowatch track` runs the live tracker; `limbowatch publish` writes the feed, metrics and site."""

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
from typing import Annotated

import typer
from limbowatch.http import HttpClient
from limbowatch.publish import all_events, dumps, items, metrics
from limbowatch.publish import feed as feed_mod
from limbowatch.publish import report as report_mod
from limbowatch.publish import site as site_mod
from limbowatch.store import Store
from limbowatch.tracker import Tracker, TrackerConfig, import_cve_list

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
    (out / "metrics.json").write_text(dumps(m))
    for r in records:
        (out / "feed" / f"{r['id']}.json").write_text(dumps(r))
    # the feed page shows a real record: the newest pending one with a machine-readable range
    pending = {i.adv.ghsa_id: i for i in all_items if not i.assessment.likely_permanent}
    with_ranges = [r for r in records if r["id"] in pending and any("ranges" in a for a in r["affected"])]
    sample = max(with_ranges, key=lambda r: r.get("published") or "", default=None)
    for path, text in site_mod.build(all_items, m, now, events=all_events(store), sample=sample).items():
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


if __name__ == "__main__":
    app()
