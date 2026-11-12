# /// script
# requires-python = ">=3.12"
# dependencies = ["pillow>=10"]
# ///
"""Regenerate the scan page's own-output screenshots, dark and light (docs/SCREENSHOTS.md).

    uv run scripts/screenshots.py --demo <checkout of limbowatch/demo-app at add-scapy> --report <artifact dir>

- terminal.png / terminal-light.png: `limbowatch scan . --fail-on high --color always` on the demo, run with the
  released CLI (`uvx --from limbowatch-cli==<version>`), drawn in a terminal window.
- html-report.png / html-report-light.png: report.html from the demo pull request's CI artifact
  (`gh run download <run> -R limbowatch/demo-app -n limbowatch-report -D <dir>`), in each color scheme.

Needs Google Chrome (CHROME=<path> to override) and OSV-Scanner 2.7.1 on PATH. The GitHub and GitLab screenshots are
captured from a signed-in browser; docs/SCREENSHOTS.md has the steps.
"""

from __future__ import annotations

import argparse
import html
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageChops

OUT = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
CHROME = os.environ.get("CHROME") or next(
    (p for p in ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", shutil.which("google-chrome") or ""]
     if p and Path(p).exists()), "google-chrome")  # fmt: skip
ANSI = re.compile(r"\x1b\[([0-9;]*)m")

THEMES = {
    "dark": {"page": "#0b0e14", "win": "#0f1218", "bar": "#161a22", "line": "#2a303b", "dot": "#3a404c", "ink": "#e6e1d6",
             "dim": "#7d8590", "shadow": "rgba(0,0,0,.5)",
             "31": "#ff6b6b", "32": "#5fd38d", "33": "#f4c152", "35": "#c792ea", "36": "#5ccfe6"},
    "light": {"page": "#ecebe5", "win": "#fcfcfb", "bar": "#f2f1ec", "line": "#d9d7cf", "dot": "#c9c7bd", "ink": "#1d2129",
              "dim": "#6b6f78", "shadow": "rgba(15,18,24,.14)",
              "31": "#c4302b", "32": "#1f7a45", "33": "#8f5a00", "35": "#7b3fa8", "36": "#0b6e85"},
}  # fmt: skip


def trim(text: str) -> list[str]:
    """The screenshot's lines: drop the unchecked-dependency list and the attribution, collapse blank runs."""
    keep, skip = [], False
    for ln in text.splitlines():
        plain = ANSI.sub("", ln)
        if re.match(r"\d+ dependenc(y|ies) can't be checked", plain):
            skip = True
        if plain.startswith("FAILED") or plain.startswith("PASSED"):
            skip = False
        if plain.startswith("Advisory data:") or skip:
            continue
        if not (ln.strip() == "" and keep and keep[-1].strip() == ""):
            keep.append(ln)
    return keep


def terminal_html(lines: list[str], t: dict[str, str]) -> str:
    out = []
    for ln in lines:
        buf, style = [], {}
        for part in re.split(r"(\x1b\[[0-9;]*m)", ln):
            if m := ANSI.fullmatch(part):
                codes = m.group(1).split(";")
                if codes in (["0"], [""]):
                    style = {}
                for c in codes:
                    if c == "1":
                        style["font-weight"] = "700"
                    elif c == "2":
                        style["color"] = t["dim"]
                    elif c in t:
                        style["color"] = t[c]
                continue
            if part:
                css = ";".join(f"{k}:{v}" for k, v in style.items())
                buf.append(f'<span style="{css}">{html.escape(part)}</span>' if css else html.escape(part))
        out.append("".join(buf))
    return f"""<!doctype html><meta charset="utf-8"><style>
body{{margin:0;background:{t["page"]};padding:28px}}
.win{{background:{t["win"]};border:1px solid {t["line"]};border-radius:12px;overflow:hidden;box-shadow:0 20px 50px {t["shadow"]};width:max-content}}
.bar{{height:34px;background:{t["bar"]};border-bottom:1px solid {t["line"]};display:flex;align-items:center;gap:8px;padding:0 14px;color:{t["dim"]};font:13px -apple-system,system-ui,sans-serif}}
.bar i{{width:12px;height:12px;border-radius:50%;background:{t["dot"]};display:inline-block}}.bar span{{margin-left:10px}}
pre{{margin:0;padding:18px 22px;color:{t["ink"]};font:14px/1.5 "JetBrains Mono",Menlo,monospace}}
</style><div class="win"><div class="bar"><i></i><i></i><i></i><span>$ limbowatch scan . --fail-on high</span></div><pre>{"\n".join(out)}</pre></div>"""


def shoot(url: str, out: Path, width: int, height: int, scale: float, scheme: str) -> None:
    flag = "1" if scheme == "light" else "0"  # Blink's preferredColorScheme: 0 dark, 1 light
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--force-device-scale-factor={scale}",
                    f"--blink-settings=preferredColorScheme={flag}", f"--window-size={width},{height}",
                    f"--screenshot={out}", url], check=True, capture_output=True, timeout=120)  # fmt: skip


def content_box(path: Path, background: str, pad: int) -> tuple[int, int, int, int]:
    """The terminal window's box, shadow included, plus `pad` pixels of the page background."""
    im = Image.open(path).convert("RGB")
    diff = ImageChops.difference(im, Image.new("RGB", im.size, background))
    left, top, right, bottom = diff.point(lambda v: 255 if v > 12 else 0).getbbox() or (0, 0, im.width, im.height)
    return max(left - pad, 0), max(top - pad, 0), min(right + pad, im.width), min(bottom + pad, im.height)


def terminal(demo: Path, version: str) -> None:
    run = subprocess.run(["uvx", "--from", f"limbowatch-cli=={version}", "limbowatch", "scan", ".", "--fail-on", "high",
                          "--color", "always"], cwd=demo, capture_output=True, text=True, timeout=600)  # fmt: skip
    if run.returncode not in (0, 1):
        raise SystemExit(f"limbowatch scan failed ({run.returncode}): {run.stderr[-2000:]}")
    lines = trim(run.stdout)
    box = None
    with tempfile.TemporaryDirectory() as tmp:
        for scheme, t in THEMES.items():  # dark first: its shadow sets the box both variants share, so they swap in place
            page = Path(tmp) / f"terminal-{scheme}.html"
            page.write_text(terminal_html(lines, t), encoding="utf-8")
            out = OUT / ("terminal.png" if scheme == "dark" else "terminal-light.png")
            shoot(page.as_uri(), out, 1100, 60 + 21 * len(lines) + 120, 2, scheme)
            box = box or content_box(out, t["page"], 2 * 28)
            Image.open(out).crop(box).save(out)


def report(artifact: Path) -> None:
    page = artifact / "report.html"
    for scheme in THEMES:
        out = OUT / ("html-report.png" if scheme == "dark" else "html-report-light.png")
        shoot(page.as_uri(), out, 1000, 910, 1.6, scheme)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--demo", type=Path, help="checkout of limbowatch/demo-app, branch add-scapy")
    ap.add_argument("--report", type=Path, help="the demo pull request's limbowatch-report artifact, unzipped")
    ap.add_argument("--version", help="the released limbowatch-cli version to run (default: the workspace's)")
    a = ap.parse_args()
    version = a.version or re.search(r'^version = "([^"]+)"', (OUT.parent.parent / "packages/cli/pyproject.toml")
                                     .read_text(), re.M).group(1)  # type: ignore[union-attr]  # fmt: skip
    if a.demo:
        terminal(a.demo.resolve(), version)
    if a.report:
        report(a.report.resolve())
    for p in sorted(OUT.glob("*.png")):
        with Image.open(p) as im:
            print(f"{p.name}: {im.width}x{im.height}")


if __name__ == "__main__":
    main()
