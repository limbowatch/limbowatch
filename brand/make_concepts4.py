# /// script
# requires-python = ">=3.12"
# dependencies = ["resvg-py"]
# ///
"""Logo exploration, round 4 (2026-11-07): Missing Hour solid, Elapsed, Stopwatch, Suspended. Suspended won."""
import math
from pathlib import Path
import resvg_py

OUT = Path(__file__).parent / "concepts"  # was argv; run: uv run brand/make_concepts4.py
INK, LIGHT, AMBER, AMBER_DEEP, PAPER, MUTED = "#0F1218", "#F3F1EA", "#F4A62A", "#B87400", "#F7F6F2", "#7C818C"
C = 256
FONT = "Helvetica Neue, Helvetica, Arial, sans-serif"

def pt(r, deg, cx=C, cy=C):
    a = math.radians(90 - deg)
    return cx + r * math.cos(a), cy - r * math.sin(a)

def arc(r, d0, d1, cx=C, cy=C):  # clockwise from clock-degree d0 to d1
    x0, y0 = pt(r, d0, cx, cy); x1, y1 = pt(r, d1, cx, cy)
    large = 1 if (d1 - d0) % 360 > 180 else 0
    return f"M {x0:.1f} {y0:.1f} A {r} {r} 0 {large} 1 {x1:.1f} {y1:.1f}"

def sector(r, d0, d1, cx=C, cy=C):
    x0, y0 = pt(r, d0, cx, cy); x1, y1 = pt(r, d1, cx, cy)
    large = 1 if (d1 - d0) % 360 > 180 else 0
    return f"M {cx} {cy} L {x0:.1f} {y0:.1f} A {r} {r} 0 {large} 1 {x1:.1f} {y1:.1f} Z"

# 1 Missing Hour, solid: a closed dial with the 1 o'clock segment knocked out of the ring.
def m1(fg, acc, bg, small=False):
    w = 52 if small else 44
    gap = 24 if small else 20
    ring = f'<path d="{arc(190, 30 + gap, 360 + 30 - gap)}" fill="none" stroke="{fg}" stroke-width="{w}" stroke-linecap="round"/>'
    dx, dy = pt(232 if small else 236, 30)
    dot = f'<circle cx="{dx:.1f}" cy="{dy:.1f}" r="{34 if small else 28}" fill="{acc}"/>'
    hands = f'<path d="M 256 {140 if small else 130} L 256 256 L {360 if small else 366} 256" fill="none" stroke="{fg}" stroke-width="{w}" stroke-linecap="round" stroke-linejoin="round"/>'
    return ring + hands + dot

# 2 Elapsed: a solid dial; the hands at 3:00 sweep out an amber quarter, the time spent waiting.
def m2(fg, acc, bg, small=False):
    disc = f'<circle cx="256" cy="256" r="216" fill="{fg}"/>'
    sec = f'<path d="{sector(176 if not small else 184, 0, 90)}" fill="{acc}"/>'
    w = 40 if not small else 52
    hands = f'<path d="M 256 {96 if not small else 92} L 256 256 L {416 if not small else 420} 256" fill="none" stroke="{bg}" stroke-width="{w}" stroke-linecap="round" stroke-linejoin="round"/>'
    return disc + sec + hands

# 3 Stopwatch: it measures how long an advisory has waited. Amber = elapsed.
def m3(fg, acc, bg, small=False):
    cy = 284
    r = 176
    w = 44 if not small else 54
    ring = f'<circle cx="256" cy="{cy}" r="{r}" fill="none" stroke="{fg}" stroke-width="{w}"/>'
    crown = (f'<rect x="{256 - (44 if not small else 52)}" y="{40 if not small else 32}" width="{88 if not small else 104}" height="{w}" rx="{w/2}" fill="{fg}"/>'
             f'<rect x="{256 - w/2}" y="60" width="{w}" height="{cy - r - 60 + 4}" fill="{fg}"/>')
    bx, by = pt(r + 46, 45, 256, cy); bx2, by2 = pt(r + 6, 45, 256, cy)
    button = f'<line x1="{bx2:.1f}" y1="{by2:.1f}" x2="{bx:.1f}" y2="{by:.1f}" stroke="{fg}" stroke-width="{w*0.8:.0f}" stroke-linecap="round"/>' if not small else ""
    sec = f'<path d="{sector(r - w/2 - (22 if not small else 18), 0, 120, 256, cy)}" fill="{acc}"/>'
    hx, hy = pt(r - w/2 - 18, 120, 256, cy)
    hand = f'<line x1="256" y1="{cy}" x2="{hx:.1f}" y2="{hy:.1f}" stroke="{fg}" stroke-width="{w*0.8:.0f}" stroke-linecap="round"/>' if not small else ""
    pivot = f'<circle cx="256" cy="{cy}" r="{w*0.7:.0f}" fill="{fg}"/>' if not small else ""
    return ring + crown + button + sec + hand + pivot

# 4 Suspended: an hourglass whose last grain is stuck in the neck. Published above, reviewed below.
def m4(fg, acc, bg, small=False):
    sw = 40 if not small else 52
    top = f'<path d="M 132 76 L 380 76 L 256 214 Z" fill="{fg}" stroke="{fg}" stroke-width="{sw}" stroke-linejoin="round"/>'
    bot = f'<path d="M 132 436 L 380 436 L 256 298 Z" fill="none" stroke="{fg}" stroke-width="{sw}" stroke-linejoin="round"/>'
    dot = f'<circle cx="256" cy="256" r="{22 if not small else 26}" fill="{acc}"/>'
    return top + bot + dot

CONCEPTS = [
    ("01", "Missing Hour, solid", "Today's idea, made bolder: a closed dial, the 1 o'clock piece knocked out of the ring.", m1),
    ("02", "Elapsed", "A solid dial. The hands at 3:00 form the L and sweep out an amber quarter: time spent waiting.", m2),
    ("03", "Stopwatch", "Limbowatch measures how long advisories wait. Amber is the time elapsed so far.", m3),
    ("04", "Suspended", "An hourglass whose grain is stuck in the neck: published above, not reviewed below.", m4),
]

def g(body, x, y, size):
    return f'<g transform="translate({x},{y}) scale({size/512})">{body}</g>'

def tile(fn, x, y, size, small, bg=INK, fg=LIGHT, acc=AMBER, rx=True):
    pad = size * 0.14
    return (f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="{size*0.22 if rx else 0}" fill="{bg}"/>'
            + g(fn(fg, acc, bg, small), x + pad, y + pad, size - 2 * pad))

def lockup(fn, x, y, h, bg, fg, acc, dot):
    return (f'<rect x="{x}" y="{y}" width="400" height="{h}" rx="16" fill="{bg}"/>'
            + g(fn(fg, acc, bg, True), x + 28, y + (h - 52) / 2, 52)
            + f'<text x="{x + 96}" y="{y + h/2 + 13}" font-family="{FONT}" font-size="36" font-weight="600" fill="{fg}" letter-spacing="-0.5">limbo<tspan fill="{dot}">.</tspan>watch</text>')

W, H = 1760, 1180
s = [f'<rect width="{W}" height="{H}" fill="#0A0C10"/>',
     f'<text x="48" y="60" font-family="{FONT}" font-size="18" font-weight="600" fill="{MUTED}" letter-spacing="1.5">LIMBOWATCH — LOGO EXPLORATION, ROUND 4</text>']
for i, (num, name, desc, fn) in enumerate(CONCEPTS):
    x = 48 + i * 424
    s.append(f'<rect x="{x}" y="96" width="400" height="1040" rx="24" fill="#161A22"/>')
    s.append(tile(fn, x + 32, 128, 336, False))
    s.append(f'<text x="{x+32}" y="512" font-family="{FONT}" font-size="15" font-weight="700" fill="{AMBER}">{num}</text>'
             f'<text x="{x+62}" y="512" font-family="{FONT}" font-size="24" font-weight="600" fill="{LIGHT}">{name}</text>')
    words, line, lines = desc.split(), "", []
    for wd in words:
        if len(line) + len(wd) > 40: lines.append(line); line = wd
        else: line = (line + " " + wd).strip()
    lines.append(line)
    for j, ln in enumerate(lines):
        s.append(f'<text x="{x+32}" y="{544 + j*22}" font-family="{FONT}" font-size="15" fill="{MUTED}">{ln}</text>')
    # real-size tiles 64/48/32/24/16
    xx = x + 32
    for px in (64, 48, 32, 24, 16):
        s.append(tile(fn, xx, 640, px, True))
        xx += px + 16
    s.append(f'<text x="{x+32}" y="728" font-family="{FONT}" font-size="12" fill="{MUTED}">64 · 48 · 32 · 24 · 16 px</text>')
    # browser-tab mock
    s.append(f'<rect x="{x+32}" y="748" width="336" height="40" rx="8" fill="#252A33"/>' + tile(fn, x + 44, 760, 16, True)
             + f'<text x="{x+70}" y="773" font-family="{FONT}" font-size="13" fill="{LIGHT}">limbo.watch · advisories in limbo</text>')
    s.append(lockup(fn, x, 812, 96, INK, LIGHT, AMBER, AMBER))
    s.append(lockup(fn, x, 924, 96, PAPER, INK, AMBER_DEEP, AMBER_DEEP))
    # avatar-ish: the mark on light paper, transparent bg
    s.append(f'<rect x="{x+16}" y="1036" width="96" height="96" rx="12" fill="{PAPER}"/>')
    s.append(g(fn(INK, AMBER_DEEP, PAPER, False), x + 24, 1044, 80))
    s.append(f'<rect x="{x+128}" y="1044" width="80" height="80" rx="40" fill="{INK}"/>' + g(fn(LIGHT, AMBER, INK, False), x + 140, 1056, 56))
s.append(f'<rect x="0" y="1036" width="0" height="0"/>')
svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}">' + "".join(s) + "</svg>"
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "round4-board.svg").write_text(svg)
(OUT / "round4-board.png").write_bytes(bytes(resvg_py.svg_to_bytes(svg_string=svg, width=W, height=H)))
for num, name, desc, fn in CONCEPTS:
    big = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" fill="{PAPER}"/>{g(fn(INK, AMBER_DEEP, PAPER), 48, 48, 416)}</svg>'
    (OUT / f"r4-{num}.png").write_bytes(bytes(resvg_py.svg_to_bytes(svg_string=big, width=512, height=512)))
print("ok")
