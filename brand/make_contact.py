# /// script
# requires-python = ">=3.12"
# dependencies = ["resvg-py"]
# ///
"""The press contact as an image, so the address isn't in any page's text for scrapers to harvest.

The address is an argument, not in this file:  uv run brand/make_contact.py someone@example.com
Writes brand/assets/contact.png (2x, shown at 340x48); `limbowatch publish` copies it to assets/contact.png.
"""

from __future__ import annotations

import sys
from pathlib import Path
from xml.sax.saxutils import escape

import resvg_py

OUT = Path(__file__).parent / "assets" / "contact.png"
W, H = 340, 48


def main() -> None:
    if len(sys.argv) != 2 or "@" not in sys.argv[1]:
        raise SystemExit("usage: uv run brand/make_contact.py <email address>")
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">'
        f'<rect width="{W}" height="{H}" rx="10" fill="#F3F1EA"/>'
        f'<text x="{W / 2}" y="30" text-anchor="middle" font-family="Helvetica Neue, Helvetica, Arial, sans-serif" '
        f'font-size="16" font-weight="600" fill="#0F1218">{escape(sys.argv[1])}</text></svg>'
    )
    OUT.write_bytes(bytes(resvg_py.svg_to_bytes(svg_string=svg, width=W * 2, height=H * 2)))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
