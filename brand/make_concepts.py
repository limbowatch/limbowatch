# /// script
# requires-python = ">=3.12"
# dependencies = ["resvg-py"]
# ///
"""Logo concepts for Limbowatch: three marks on the org-avatar background, rendered large and tiny."""
import math
from pathlib import Path
import resvg_py

INK, LIGHT, AMBER = "#0F1218", "#F3F1EA", "#F4A62A"
OUT = Path(__file__).parent / "concepts"
EYE = "M 52 256 C 136 112, 376 112, 460 256 C 376 400, 136 400, 52 256 Z"


def svg(body: str, bg: str = INK) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">'
            f'<rect width="512" height="512" rx="96" fill="{bg}"/>{body}</svg>')


def hand(cx, cy, length, deg):
    a = math.radians(deg)
    return cx + length * math.cos(a), cy - length * math.sin(a)


# A: "waiting eye" - eye whose iris is a clock with one amber hand (watch = see + time)
hx, hy = hand(256, 256, 58, 125)
A = svg(f'<path d="{EYE}" fill="none" stroke="{LIGHT}" stroke-width="30" stroke-linejoin="round"/>'
        f'<circle cx="256" cy="256" r="84" fill="none" stroke="{LIGHT}" stroke-width="26"/>'
        f'<line x1="256" y1="256" x2="{hx:.1f}" y2="{hy:.1f}" stroke="{AMBER}" stroke-width="26" stroke-linecap="round"/>'
        f'<circle cx="256" cy="256" r="20" fill="{AMBER}"/>')

# B: "suspended" - a ring broken open, an amber dot hanging in the gap (between published and seen)
r = 150
gap = 34  # degrees each side of the gap at 45 deg (upper right)
x1, y1 = hand(256, 256, r, 45 + gap)
x2, y2 = hand(256, 256, r, 45 - gap)
dx, dy = hand(256, 256, r, 45)
B = svg(f'<path d="M {x1:.1f} {y1:.1f} A {r} {r} 0 1 0 {x2:.1f} {y2:.1f}" fill="none" stroke="{LIGHT}" stroke-width="40" stroke-linecap="round"/>'
        f'<circle cx="{dx:.1f}" cy="{dy:.1f}" r="34" fill="{AMBER}"/>')

# C: "half-lit eye" - the pupil is half amber, half dark: visible to some, not to others
C = svg(f'<path d="{EYE}" fill="none" stroke="{LIGHT}" stroke-width="30" stroke-linejoin="round"/>'
        f'<circle cx="256" cy="256" r="88" fill="{LIGHT}"/>'
        f'<path d="M 256 168 A 88 88 0 0 1 256 344 Z" fill="{AMBER}"/>'
        f'<circle cx="256" cy="256" r="88" fill="none" stroke="{INK}" stroke-width="0"/>'
        f'<path d="M 256 168 L 256 344" stroke="{INK}" stroke-width="10"/>')

for name, s in (("A-waiting-eye", A), ("B-suspended", B), ("C-half-lit-eye", C)):
    (OUT / f"{name}.svg").write_text(s)
    for px in (512, 32):
        (OUT / f"{name}-{px}.png").write_bytes(bytes(resvg_py.svg_to_bytes(svg_string=s, width=px, height=px)))

# contact sheet: each concept big + at 64 / 32 / 20 px (scaled back up with nearest-neighbour feel via image)
cells = []
for i, (name, s) in enumerate((("A", A), ("B", B), ("C", C))):
    inner = s.replace('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">', "").replace("</svg>", "")
    x0 = 40 + i * 420
    cells.append(f'<g transform="translate({x0},40) scale(0.72)">{inner}</g>')
    for j, size in enumerate((64, 32, 20)):
        cells.append(f'<g transform="translate({x0 + j * 90},440) scale({size / 512})">{inner}</g>')
    cells.append(f'<text x="{x0}" y="560" font-family="Helvetica, Arial, sans-serif" font-size="28" fill="#333">{"ABC"[i]}</text>')
sheet = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1300 600"><rect width="1300" height="600" fill="#FFFFFF"/>{"".join(cells)}</svg>'
(OUT / "sheet.png").write_bytes(bytes(resvg_py.svg_to_bytes(svg_string=sheet, width=1300, height=600)))
print("written", sorted(p.name for p in OUT.iterdir()))
