# /// script
# requires-python = ">=3.12"
# dependencies = ["resvg-py"]
# ///
"""Round 3 concept board: three constructed marks, each with construction view, small sizes and lockup."""
import math
from pathlib import Path
import resvg_py

INK, PANEL, LIGHT, MUTED, AMBER, GRID = "#0F1218", "#161A22", "#F3F1EA", "#7C818C", "#F4A62A", "#2A303B"
OUT = Path(__file__).parent / "concepts"
C0 = 256


def pt(r, clock_deg):  # clock angle: 0 = 12 o'clock, clockwise
    a = math.radians(90 - clock_deg)
    return C0 + r * math.cos(a), C0 - r * math.sin(a)


def missing_hour(construction=False):
    parts = []
    if construction:
        for r in (196, 170, 134, 100):
            parts.append(f'<circle cx="256" cy="256" r="{r}" fill="none" stroke="{GRID}" stroke-width="2" stroke-dasharray="6 6"/>')
        parts.append(f'<line x1="256" y1="40" x2="256" y2="472" stroke="{GRID}" stroke-width="2"/><line x1="40" y1="256" x2="472" y2="256" stroke="{GRID}" stroke-width="2"/>')
    for h in range(12):
        if h == 1:
            continue
        major = h % 3 == 0
        x1, y1 = pt(170 if major else 180, h * 30)
        x2, y2 = pt(198, h * 30)
        parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{LIGHT}" stroke-width="{22 if major else 16}" stroke-linecap="round"/>')
    ax, ay = pt(184, 30)
    parts.append(f'<circle cx="{ax:.1f}" cy="{ay:.1f}" r="28" fill="{AMBER}"/>')
    parts.append(f'<path d="M 256 118 L 256 256 L 362 256" fill="none" stroke="{LIGHT}" stroke-width="34" stroke-linecap="round" stroke-linejoin="round"/>')
    return "".join(parts)


def out_of_frame(construction=False):
    parts = []
    if construction:
        parts.append(f'<rect x="132" y="132" width="248" height="248" fill="none" stroke="{GRID}" stroke-width="2" stroke-dasharray="6 6"/>')
        parts.append(f'<circle cx="420" cy="92" r="64" fill="none" stroke="{GRID}" stroke-width="2" stroke-dasharray="6 6"/>')
    a = 78
    for (x, y, dx, dy) in ((132, 132, 1, 1), (380, 132, -1, 1), (132, 380, 1, -1), (380, 380, -1, -1)):
        color = LIGHT
        parts.append(f'<path d="M {x} {y + dy * a} L {x} {y} L {x + dx * a} {y}" fill="none" stroke="{color}" stroke-width="30" stroke-linecap="round" stroke-linejoin="round"/>')
    parts.append(f'<circle cx="420" cy="92" r="34" fill="{AMBER}"/>')
    parts.append(f'<circle cx="256" cy="256" r="12" fill="{MUTED}"/>')
    return "".join(parts)


def threshold(construction=False):
    parts = []
    if construction:
        parts.append(f'<circle cx="256" cy="236" r="104" fill="none" stroke="{GRID}" stroke-width="2" stroke-dasharray="6 6"/>')
        parts.append(f'<line x1="80" y1="404" x2="432" y2="404" stroke="{GRID}" stroke-width="2"/>')
    parts.append(f'<path d="M 152 404 L 152 236 A 104 104 0 0 1 360 236 L 360 404" fill="none" stroke="{LIGHT}" stroke-width="30" stroke-linecap="round" stroke-linejoin="round"/>')
    parts.append(f'<path d="M 214 404 L 214 250 A 42 42 0 0 1 256 208 L 298 208 L 298 404 Z" fill="none"/>')
    parts.append(f'<path d="M 278 192 L 300 196 L 300 404 L 278 404 Z" fill="{AMBER}"/>')
    parts.append(f'<path d="M 278 404 L 300 404 L 408 452 L 300 452 Z" fill="{AMBER}" opacity="0.55"/>')
    parts.append(f'<line x1="104" y1="404" x2="408" y2="404" stroke="{LIGHT}" stroke-width="18" stroke-linecap="round"/>')
    return "".join(parts)


def tile(body, x, y, size, bg=INK, rx=None):
    s = size / 512
    rx = 96 if rx is None else rx
    return f'<g transform="translate({x},{y}) scale({s})"><rect width="512" height="512" rx="{rx}" fill="{bg}"/>{body}</g>'


def label(x, y, text, size=18, color=MUTED, weight="400", family="Helvetica, Arial, sans-serif"):
    return f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{weight}" fill="{color}" letter-spacing="0.5">{text}</text>'


concepts = [("01", "Missing Hour", "L-hands at 3:00 · one hour turned amber", missing_hour),
            ("02", "Out of Frame", "four L corners · the advisory outside the view", out_of_frame),
            ("03", "Threshold", "limbo = threshold · light under the door", threshold)]
W, H = 1600, 1180
el = [f'<rect width="{W}" height="{H}" fill="#0A0C10"/>', label(48, 58, "LIMBOWATCH — LOGO EXPLORATION, ROUND 3", 16, MUTED, "600"),
      label(W - 210, 58, "limbo.watch", 16, MUTED)]
for i, (num, name, idea, fn) in enumerate(concepts):
    x0 = 48 + i * 512
    y0 = 96
    el.append(f'<rect x="{x0}" y="{y0}" width="488" height="1040" rx="18" fill="{PANEL}"/>')
    el.append(tile(fn(), x0 + 44, y0 + 44, 400))
    el.append(label(x0 + 44, y0 + 490, num, 15, AMBER, "600"))
    el.append(label(x0 + 80, y0 + 490, name, 26, LIGHT, "600"))
    el.append(label(x0 + 44, y0 + 522, idea, 15, MUTED))
    el.append(tile(fn(True), x0 + 44, y0 + 552, 188, bg="#0F1218", rx=40))
    for j, sz in enumerate((96, 48, 32, 20)):
        el.append(tile(fn(), x0 + 256 + [0, 108, 168, 212][j], y0 + 552, sz))
    el.append(label(x0 + 256, y0 + 690, "96 · 48 · 32 · 20 px", 13, MUTED))
    # lockup on light and dark
    el.append(f'<rect x="{x0 + 44}" y="{y0 + 770}" width="400" height="104" rx="14" fill="{INK}"/>')
    el.append(f'<g transform="translate({x0 + 64},{y0 + 786}) scale({72 / 512})">{fn()}</g>')
    el.append(label(x0 + 150, y0 + 836, "limbo<tspan fill=\'" + AMBER + "\'>.</tspan>watch", 34, LIGHT, "600"))
    el.append(f'<rect x="{x0 + 44}" y="{y0 + 890}" width="400" height="104" rx="14" fill="#F3F1EA"/>')
    light_body = fn().replace(LIGHT, INK)
    el.append(f'<g transform="translate({x0 + 64},{y0 + 906}) scale({72 / 512})">{light_body}</g>')
    el.append(label(x0 + 150, y0 + 956, "limbo<tspan fill=\'#C47F00\'>.</tspan>watch", 34, INK, "600"))
board = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}">{"".join(el)}</svg>'
(OUT / "round3-board.svg").write_text(board)
(OUT / "round3-board.png").write_bytes(bytes(resvg_py.svg_to_bytes(svg_string=board, width=W, height=H)))
for _, name, _, fn in concepts:
    slug = name.lower().replace(" ", "-")
    (OUT / f"r3-{slug}.svg").write_text(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="96" fill="{INK}"/>{fn()}</svg>')
print("ok")
