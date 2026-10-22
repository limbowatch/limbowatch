# /// script
# requires-python = ">=3.12"
# dependencies = ["resvg-py", "pillow"]
# ///
"""Limbowatch brand assets: the "Missing Hour" mark.

A watch dial at 3:00. The hands form an L (Limbowatch); the dial is a watch (looking, and time
passing); the 1 o'clock mark has turned amber: the advisory waiting in limbo.

Run: uv run brand/make_brand.py  ->  brand/assets/
"""

from __future__ import annotations

import io
import math
from pathlib import Path

import resvg_py
from PIL import Image

OUT = Path(__file__).parent / "assets"
INK = "#0F1218"      # background / ink
LIGHT = "#F3F1EA"    # mark on dark
AMBER = "#F4A62A"    # the advisory in limbo (on dark)
AMBER_DEEP = "#B87400"  # amber on light backgrounds (contrast)
PAPER = "#F7F6F2"    # light background
MUTED = "#7C818C"
C = 256
FONT = "Helvetica Neue, Helvetica, Arial, sans-serif"


def pt(r: float, clock_deg: float) -> tuple[float, float]:
    a = math.radians(90 - clock_deg)
    return C + r * math.cos(a), C - r * math.sin(a)


def mark(fg: str = LIGHT, accent: str = AMBER, small: bool = False, tiny: bool = False) -> str:
    """The mark on a 512 grid, no background.

    small: optical version for 24-48 px (only the 6 and 9 marks; 12 and 3 would fuse with the hands).
    tiny:  16 px (the L and the amber hour only).
    """
    small = small or tiny
    parts = []
    for h in range(12):
        if h == 1:
            continue  # the missing hour
        major = h % 3 == 0
        if small and (h not in (6, 9) or tiny):
            continue
        r_in = (160 if small else 170) if major else 180
        x1, y1 = pt(r_in, h * 30)
        x2, y2 = pt(200, h * 30)
        w = (34 if small else 22) if major else 16
        parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{fg}" stroke-width="{w}" stroke-linecap="round"/>')
    ax, ay = pt(184, 30)
    if tiny:
        ax, ay = pt(150, 38)
    parts.append(f'<circle cx="{ax:.1f}" cy="{ay:.1f}" r="{56 if tiny else 38 if small else 28}" fill="{accent}"/>')
    hand_w = 64 if tiny else 46 if small else 34
    top, right = (96, 376) if tiny else (112, 370) if small else (118, 362)
    ox, oy = (-24, 40) if tiny else (0, 0)  # tiny: re-centre the L + dot in the tile
    parts.append(f'<path d="M {256 + ox} {top + oy} L {256 + ox} {256 + oy} L {right + ox} {256 + oy}" fill="none" stroke="{fg}" '
                 f'stroke-width="{hand_w}" stroke-linecap="round" stroke-linejoin="round"/>')
    return "".join(parts)


def doc(w: int, h: int, body: str, title: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{title}">'
            f'<title>{title}</title>{body}</svg>')


def inner(svg: str) -> str:
    """Body of a doc() SVG, without the <svg> wrapper and <title>."""
    return svg.split("</title>", 1)[1].rsplit("</svg>", 1)[0]


def png(svg: str, w: int, h: int) -> bytes:
    return bytes(resvg_py.svg_to_bytes(svg_string=svg, width=w, height=h))


def write(name: str, data: str | bytes) -> None:
    p = OUT / name
    if isinstance(data, str):
        p.write_text(data)
    else:
        p.write_bytes(data)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    t = "Limbowatch"

    # 1) marks, transparent
    write("mark-on-dark.svg", doc(512, 512, mark(LIGHT, AMBER), t))
    write("mark-on-light.svg", doc(512, 512, mark(INK, AMBER_DEEP), t))
    write("mark-small-on-dark.svg", doc(512, 512, mark(LIGHT, AMBER, small=True), t))
    write("mark-small-on-light.svg", doc(512, 512, mark(INK, AMBER_DEEP, small=True), t))

    # 2) GitHub org avatar: full-bleed square (GitHub rounds it); mark inside an 80 % safe area
    avatar = doc(1024, 1024, f'<rect width="1024" height="1024" fill="{INK}"/>'
                 f'<g transform="translate(112,112) scale({800 / 512})">{mark()}</g>', t)
    write("avatar.svg", avatar)
    write("avatar-1024.png", png(avatar, 1024, 1024))
    write("avatar-500.png", png(avatar, 500, 500))

    # 3) favicons / app icons (small optical version), rounded tile
    tile = lambda small, tiny=False: doc(512, 512, f'<rect width="512" height="512" rx="112" fill="{INK}"/>'
                                                   f'<g transform="translate(48,48) scale({416 / 512})">{mark(small=small, tiny=tiny)}</g>', t)
    write("favicon.svg", tile(True))
    write("favicon-16.png", png(tile(True, tiny=True), 16, 16))
    for px in (32, 48):
        write(f"favicon-{px}.png", png(tile(True), px, px))
    write("apple-touch-icon-180.png", png(doc(512, 512, f'<rect width="512" height="512" fill="{INK}"/>'
                                                       f'<g transform="translate(64,64) scale({384 / 512})">{mark()}</g>', t), 180, 180))
    write("icon-512.png", png(tile(False), 512, 512))
    ico = io.BytesIO()
    layers = [Image.open(io.BytesIO(png(tile(True, tiny=(px == 16)), px, px))) for px in (48, 32, 16)]
    layers[0].save(ico, format="ICO", sizes=[(48, 48), (32, 32), (16, 16)], append_images=layers[1:])
    write("favicon.ico", ico.getvalue())

    # 4) wordmark lockups (text is live SVG text; PNGs are the portable versions)
    def lockup(bg: str | None, fg: str, accent: str, dot: str) -> str:
        back = f'<rect width="1200" height="320" rx="0" fill="{bg}"/>' if bg else ""
        return doc(1200, 320, back +
                   f'<g transform="translate(64,64) scale({192 / 512})">{mark(fg, accent)}</g>'
                   f'<text x="300" y="196" font-family="{FONT}" font-size="128" font-weight="600" fill="{fg}" letter-spacing="-2">'
                   f'limbo<tspan fill="{dot}">.</tspan>watch</text>', "limbo.watch")
    for name, args in (("wordmark-on-dark", (INK, LIGHT, AMBER, AMBER)), ("wordmark-on-light", (PAPER, INK, AMBER_DEEP, AMBER_DEEP)),
                       ("wordmark-transparent-dark-text", (None, INK, AMBER_DEEP, AMBER_DEEP)),
                       ("wordmark-transparent-light-text", (None, LIGHT, AMBER, AMBER))):
        s = lockup(*args)
        write(f"{name}.svg", s)
        write(f"{name}.png", png(s, 1200, 320))

    # 5) GitHub social preview 1280x640
    ticks = "".join(
        f'<line x1="{x:.0f}" y1="0" x2="{x:.0f}" y2="{14 if i % 5 else 30}" stroke="#2A303B" stroke-width="3"/>'
        for i, x in enumerate(range(0, 1281, 32)))
    social = doc(1280, 640,
                 f'<rect width="1280" height="640" fill="{INK}"/>'
                 f'<g transform="translate(0,604)">{ticks}</g>'
                 f'<g transform="translate(96,136) scale({368 / 512})">{mark()}</g>'
                 f'<text x="540" y="290" font-family="{FONT}" font-size="104" font-weight="600" fill="{LIGHT}" letter-spacing="-2">'
                 f'limbo<tspan fill="{AMBER}">.</tspan>watch</text>'
                 f'<text x="546" y="370" font-family="{FONT}" font-size="38" fill="{MUTED}">Published. Not reviewed. Not scanned.</text>'
                 f'<text x="546" y="420" font-family="{FONT}" font-size="38" fill="{AMBER}">In limbo.</text>',
                 "limbo.watch — Published. Not reviewed. Not scanned. In limbo.")
    write("social-preview.svg", social)
    write("social-preview-1280x640.png", png(social, 1280, 640))

    # 6) preview sheet for review
    cells = (f'<rect width="1400" height="900" fill="#0A0C10"/>'
             f'<image href="data:image/png;base64,{__import__("base64").b64encode(png(avatar, 1024, 1024)).decode()}" x="40" y="40" width="380" height="380"/>')
    for i, px in enumerate((96, 48, 32, 20, 16)):
        cells += f'<g transform="translate({460 + i * 110},40) scale({px / 512})"><rect width="512" height="512" rx="112" fill="{INK}"/><g transform="translate(48,48) scale({416 / 512})">{mark(small=px <= 48, tiny=px <= 16)}</g></g>'
    cells += f'<rect x="460" y="180" width="900" height="240" fill="{PAPER}"/>'
    cells += f'<g transform="translate(460,200) scale(0.75)">{inner(lockup(None, INK, AMBER_DEEP, AMBER_DEEP))}</g>'
    cells += f'<g transform="translate(40,460) scale(1.03)">{inner(social)}</g>'
    sheet = f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 1400 1180"><rect width="1400" height="1180" fill="#0A0C10"/>{cells}</svg>'
    write("_preview.png", png(sheet, 1400, 1180))
    print("assets:", ", ".join(sorted(p.name for p in OUT.iterdir())))


if __name__ == "__main__":
    main()
