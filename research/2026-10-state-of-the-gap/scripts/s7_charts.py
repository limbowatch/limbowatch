# /// script
# requires-python = ">=3.12"
# dependencies = ["matplotlib"]
# ///
"""Stage 7: charts for the report, as static SVG in light and dark variants.

Static images (the report renders on GitHub), so there's no hover layer; every chart has
direct value labels and the report carries the same numbers as tables (palette relief rule).
Palette and mark specs follow the dataviz reference instance (validated light and dark).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import matplotlib

matplotlib.use("svg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import PathPatch, Rectangle  # noqa: E402
from matplotlib.path import Path as MplPath  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = os.environ.get("SNAPSHOT_DATE", time.strftime("%Y-%m-%d"))
OUT = ROOT / "charts" / os.environ["CHARTS_SUBDIR"] if os.environ.get("CHARTS_SUBDIR") else ROOT / "charts"

THEMES = {
    "light": {"surface": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781", "grid": "#e1e0d9",
              "axis": "#c3c2b7", "s1": "#2a78d6", "s2": "#eb6834", "neutral": "#c3c2b7"},
    "dark": {"surface": "#1a1a19", "ink": "#f0efec", "ink2": "#c3c2b7", "muted": "#898781", "grid": "#2c2c2a",
             "axis": "#383835", "s1": "#3987e5", "s2": "#d95926", "neutral": "#52514e"},
}
BAR_PX = 20
BUCKETS = ["< 3 days", "3–7 days", "1–2 weeks", "2–4 weeks", "1–2 months", "2–3 months", "> 3 months"]
SLOT_PX = 36
PX = 1 / 100  # inches per px at dpi 100

import logging  # noqa: E402

logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
plt.rcParams.update({"font.family": ["Helvetica", "Arial", "DejaVu Sans"],
                     "svg.fonttype": "none", "font.size": 11, "figure.dpi": 100})


def style(ax, t, value_axis: str) -> None:
    ax.set_facecolor(t["surface"])
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    base = "left" if value_axis == "x" else "bottom"
    other = "bottom" if value_axis == "x" else "left"
    ax.spines[base].set_color(t["axis"])
    ax.spines[other].set_visible(False)
    ax.tick_params(colors=t["muted"], length=0, labelsize=10)
    ax.grid(axis=value_axis, color=t["grid"], linewidth=1, linestyle="-")
    ax.set_axisbelow(True)


def rounded_bar(ax, fig, x0, y, length, thick, color, horizontal=True) -> None:
    """Bar with a 4px rounded data-end and a square baseline, built in pixel space."""
    if length <= 0:
        return
    fig.canvas.draw()
    if horizontal:
        (ax0, ay0), (ax1, ay1) = ax.transData.transform([(x0, y - thick / 2), (x0 + length, y + thick / 2)])
        lo, hi = min(ay0, ay1), max(ay0, ay1)
        r = min(4, abs(ax1 - ax0), (hi - lo) / 2)
        verts = [(ax0, lo), (ax1 - r, lo), (ax1, lo), (ax1, lo + r), (ax1, hi - r), (ax1, hi), (ax1 - r, hi), (ax0, hi), (ax0, lo)]
    else:
        (ax0, ay0), (ax1, ay1) = ax.transData.transform([(y - thick / 2, x0), (y + thick / 2, x0 + length)])
        lo, hi = min(ax0, ax1), max(ax0, ax1)
        r = min(4, abs(ay1 - ay0), (hi - lo) / 2)
        verts = [(lo, ay0), (lo, ay1 - r), (lo, ay1), (lo + r, ay1), (hi - r, ay1), (hi, ay1), (hi, ay1 - r), (hi, ay0), (lo, ay0)]
    codes = [MplPath.MOVETO, MplPath.LINETO, MplPath.CURVE3, MplPath.CURVE3, MplPath.LINETO, MplPath.CURVE3, MplPath.CURVE3, MplPath.LINETO, MplPath.CLOSEPOLY]
    data = ax.transData.inverted().transform(verts)
    ax.add_patch(PathPatch(MplPath(data, codes), facecolor=color, linewidth=0, transform=ax.transData))


def titles(fig, t, title: str, subtitle: str) -> None:
    fig.text(0.012, 0.975, title, ha="left", va="top", fontsize=14, fontweight="semibold", color=t["ink"])
    fig.text(0.012, 0.975 - 26 / (fig.get_figheight() * 100), subtitle, ha="left", va="top", fontsize=10.5, color=t["ink2"])


def footer(fig, t, text: str) -> None:
    fig.text(0.012, 0.012, text, ha="left", va="bottom", fontsize=9, color=t["muted"])


def hbars(name, theme, title, subtitle, labels, values, colors_key, value_fmt, note, xmax=None):
    t = THEMES[theme]
    n = len(labels)
    h_px = 92 + n * SLOT_PX + 40
    fig = plt.figure(figsize=(760 * PX, h_px * PX), facecolor=t["surface"])
    ax = fig.add_axes([0.30, 40 / h_px, 0.60, (n * SLOT_PX) / h_px])
    style(ax, t, "x")
    ax.set_ylim(n - 0.5, -0.5)
    ax.set_xlim(0, xmax or max(values) * 1.18)
    ax.set_yticks(range(n), labels)
    ax.tick_params(axis="y", colors=t["ink2"], labelsize=10.5)
    thick = BAR_PX / SLOT_PX
    for i, (v, ck) in enumerate(zip(values, colors_key)):
        rounded_bar(ax, fig, 0, i, v, thick, t[ck])
        ax.text(v + (ax.get_xlim()[1] * 0.012), i, value_fmt(v, i), va="center", ha="left", fontsize=10.5, color=t["ink"])
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    titles(fig, t, title, subtitle)
    footer(fig, t, note)
    fig.savefig(OUT / f"{name}-{theme}.svg", facecolor=t["surface"])
    plt.close(fig)


def columns(name, theme, title, subtitle, labels, values, value_fmt, note, highlight_from=None):
    t = THEMES[theme]
    n = len(labels)
    w_px, h_px = 760, 380
    fig = plt.figure(figsize=(w_px * PX, h_px * PX), facecolor=t["surface"])
    ax = fig.add_axes([0.07, 0.16, 0.90, 0.60])
    style(ax, t, "y")
    ax.set_xlim(-0.6, n - 0.4)
    ax.set_ylim(0, max(values) * 1.2)
    ax.set_xticks(range(n), labels)
    ax.tick_params(axis="x", colors=t["ink2"], labelsize=10)
    slot = 0.90 * w_px / n
    thick = min(24, slot * 0.6) / slot
    for i, v in enumerate(values):
        color = t["s1"] if highlight_from is None or i >= highlight_from else t["neutral"]
        rounded_bar(ax, fig, 0, i, v, thick, color, horizontal=False)
        ax.text(i, v + ax.get_ylim()[1] * 0.02, value_fmt(v), ha="center", va="bottom", fontsize=10.5, color=t["ink"])
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    titles(fig, t, title, subtitle)
    footer(fig, t, note)
    fig.savefig(OUT / f"{name}-{theme}.svg", facecolor=t["surface"])
    plt.close(fig)


def grouped_hbars(name, theme, title, subtitle, labels, a, b, a_label, b_label, note):
    t = THEMES[theme]
    n = len(labels)
    slot = 56
    h_px = 130 + n * slot + 40
    fig = plt.figure(figsize=(760 * PX, h_px * PX), facecolor=t["surface"])
    ax = fig.add_axes([0.25, 40 / h_px, 0.66, (n * slot) / h_px])
    style(ax, t, "x")
    ax.set_ylim(n - 0.5, -0.5)
    ax.set_xlim(0, max(a + b) * 1.15)
    ax.set_yticks(range(n), labels)
    ax.tick_params(axis="y", colors=t["ink2"], labelsize=10.5)
    thick = 18 / slot
    gap = 2 / slot  # 2px surface gap between the paired bars
    for i in range(n):
        for off, v, ck in ((-(thick + gap) / 2, a[i], "s1"), ((thick + gap) / 2, b[i], "s2")):
            rounded_bar(ax, fig, 0, i + off, v, thick, t[ck])
            ax.text(v + ax.get_xlim()[1] * 0.012, i + off, f"{v:,}", va="center", ha="left", fontsize=10, color=t["ink"])
    titles(fig, t, title, subtitle)
    # legend (always present for 2 series): swatch + ink text
    y = 0.975 - 52 / h_px
    for k, (lbl, ck) in enumerate(((a_label, "s1"), (b_label, "s2"))):
        x = 0.012 + k * 0.42
        fig.patches.append(Rectangle((x, y - 0.012), 0.016, 0.024, transform=fig.transFigure, facecolor=t[ck], linewidth=0))
        fig.text(x + 0.024, y, lbl, va="center", ha="left", fontsize=10, color=t["ink2"])
    footer(fig, t, note)
    fig.savefig(OUT / f"{name}-{theme}.svg", facecolor=t["surface"])
    plt.close(fig)


def main() -> None:
    s = json.loads((ROOT / "data" / SNAPSHOT / "summary.json").read_text())
    OUT.mkdir(exist_ok=True)
    note = f"Snapshot {SNAPSHOT} · Limbowatch research · data CC BY 4.0 · advisory data: GitHub Advisory Database (CC BY 4.0), OSV"
    cls = s["classes"]
    order = [("LIMBO_ADVISORY", "In limbo, no CVE anywhere"), ("LIMBO_ADVISORY_RBP", "In limbo, CVE reserved (RBP)"),
             ("LIMBO_CVE", "In limbo, CVE published"), ("REVIEWED_NO_CVE", "Reviewed, no CVE"), ("REVIEWED_WITH_CVE", "Reviewed, with CVE")]
    total = sum(cls.values())
    lag = s["review_lag"]
    def short(key: str) -> str:
        return key.rstrip("/").split("/")[-1]

    for theme in THEMES:
        hbars("fig1-advisory-states", theme,
              f"{s['limbo']['count']:,} of {total:,} upstream advisories are in limbo",
              f"Published repository advisories of the {s['upstreams']['repos_with_advisories']} upstream repos (of {s['upstreams']['repos_polled']:,}) "
              f"behind {s['inventory']['projects']} popular projects",
              [lbl for _, lbl in order], [cls.get(k, 0) for k, _ in order],
              ["s1", "s1", "s1", "neutral", "neutral"],
              lambda v, i: f"{v:,}  ({v / total:.0%})", note)
        b = lag["lag_buckets"] if lag else None
        if lag:
            columns("fig2-review-lag", theme,
                f"Median wait for GitHub review: {lag['lag_days']['median']:.0f} days",
                f"Time from repo advisory publication to GitHub review, {lag['from_repo_advisories']:,} advisories reviewed "
                f"{lag['reviewed_window'][0][:10]} → {lag['reviewed_window'][1][:10]} · gray: within the 72 hours GitHub documents",
                BUCKETS, [b.get(k, 0) for k in BUCKETS], lambda v: f"{v:,}", note, highlight_from=1)
        ab = s["limbo"]["age_buckets"]
        columns("fig3-limbo-age", theme,
                "How long the advisories in limbo have waited so far",
                f"{s['limbo']['count']:,} advisories not yet in GitHub's reviewed database or OSV, by days since repo publication",
                BUCKETS, [ab.get(k, 0) for k in BUCKETS], lambda v: f"{v:,}", note)
        pp = s["per_project"]
        # projects with no readable lockfile aren't "clean" - they're inventory gaps, reported in the text
        names = sorted((k for k in pp if pp[k]["packages"] > 0), key=lambda k: (-pp[k]["affected_packages"], k))
        grouped_hbars("fig4-projects", theme,
                      "Packages with advisories in limbo, which scanners can't see",
                      "Per project: affected package-versions (likely duplicates excluded), and how many OSV-Scanner reports fully clean",
                      [short(n) for n in names],
                      [pp[n]["affected_packages"] for n in names], [pp[n]["affected_packages_osv_scanner_reports_clean"] for n in names],
                      "Affected by an advisory in limbo", "…of which OSV-Scanner reports the package clean", note)
    print("charts written to", OUT)


if __name__ == "__main__":
    main()
