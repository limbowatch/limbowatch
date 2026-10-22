# /// script
# requires-python = ">=3.12"
# dependencies = ["resvg-py"]
# ///
"""Round 2: marks built from Limbowatch's own idea (limbo, the gap), not a generic eye."""
from pathlib import Path
import resvg_py

INK, LIGHT, AMBER = "#0F1218", "#F3F1EA", "#F4A62A"
OUT = Path(__file__).parent / "concepts"


def svg(body: str) -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="96" fill="{INK}"/>{body}</svg>'


# D "Under the bar": the limbo bar is the scanners' line of sight; the advisory slips under it.
D = svg(f'<line x1="104" y1="214" x2="408" y2="214" stroke="{LIGHT}" stroke-width="44" stroke-linecap="round"/>'
        f'<circle cx="300" cy="318" r="40" fill="{AMBER}"/>')

# E "L-gap": monogram L whose corner never closes; the advisory sits in the gap.
E = svg(f'<line x1="156" y1="104" x2="156" y2="300" stroke="{LIGHT}" stroke-width="52" stroke-linecap="round"/>'
        f'<line x1="244" y1="388" x2="384" y2="388" stroke="{LIGHT}" stroke-width="52" stroke-linecap="round"/>'
        f'<circle cx="166" cy="378" r="30" fill="{AMBER}"/>')

# F "Missing link": published ●── gap ──○ reviewed; the advisory hangs in the gap.
F = svg(f'<line x1="96" y1="300" x2="196" y2="300" stroke="{LIGHT}" stroke-width="32" stroke-linecap="round"/>'
        f'<line x1="316" y1="300" x2="416" y2="300" stroke="{LIGHT}" stroke-width="32" stroke-linecap="round"/>'
        f'<circle cx="96" cy="300" r="36" fill="{LIGHT}"/>'
        f'<circle cx="416" cy="300" r="30" fill="{INK}" stroke="{LIGHT}" stroke-width="16"/>'
        f'<circle cx="256" cy="212" r="38" fill="{AMBER}"/>')

C = (OUT / "C-half-lit-eye.svg").read_text()
marks = (("C", C), ("D", D), ("E", E), ("F", F))
for name, s in marks[1:]:
    (OUT / f"{name}.svg").write_text(s)
cells = []
for i, (name, s) in enumerate(marks):
    inner = s.split(">", 1)[1].rsplit("</svg>", 1)[0]
    x0 = 30 + i * 330
    cells.append(f'<g transform="translate({x0},30) scale(0.56)">{inner}</g>')
    for j, size in enumerate((64, 32, 20)):
        cells.append(f'<g transform="translate({x0 + j * 84},340) scale({size / 512})">{inner}</g>')
    cells.append(f'<text x="{x0}" y="452" font-family="Helvetica, Arial, sans-serif" font-size="26" fill="#333">{name}</text>')
sheet = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1340 480"><rect width="1340" height="480" fill="#FFFFFF"/>{"".join(cells)}</svg>'
(OUT / "sheet2.png").write_bytes(bytes(resvg_py.svg_to_bytes(svg_string=sheet, width=1340, height=480)))
print("ok")
