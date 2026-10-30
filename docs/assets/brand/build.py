# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Builds revokt's brand SVGs from Source Code Pro's outlines (docs/assets/brand/README.md).

  uv run --no-project --with fonttools==4.55.3 python3 -I docs/assets/brand/build.py \
      <dir holding SourceCodePro-Bold.ttf and SourceCodePro-Regular.ttf, release 2.042> docs/assets/brand

It writes the SVGs only; render.sh turns them into the PNGs and the favicon.
"""
import os
import sys

from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.pointInsidePen import PointInsidePen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

FONTS, OUT = sys.argv[1], sys.argv[2]
BOLD = os.path.join(FONTS, "SourceCodePro-Bold.ttf")
REGULAR = os.path.join(FONTS, "SourceCodePro-Regular.ttf")

INK, HIT = "#15303d", "#c62d42"            # light ground
INK_DARK, HIT_DARK = "#e2ebef", "#ef5b6e"  # dark ground
GROUND_DARK = "#10202a"
ROWS = 6                                   # the pixel r's height in cells
KT_OPACITY = 0.7                           # the faded "kt"
HEADER = "<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->\n<!-- SPDX-License-Identifier: Apache-2.0 -->\n"


def pixel_r():
    """Samples Bold's r on a square grid ROWS cells tall, over its ink box: a cell is on when the outline covers half
    of its 12 x 12 sample points or more."""
    font = TTFont(BOLD)
    glyphs = font.getGlyphSet()
    glyph = glyphs[font.getBestCmap()[ord("r")]]
    bounds = BoundsPen(glyphs)
    glyph.draw(bounds)
    x0, y0, x1, y1 = bounds.bounds   # font units, y up
    cell = (y1 - y0) / ROWS
    cols = max(1, round((x1 - x0) / cell))
    n = 12
    on = []
    for r in range(ROWS):
        for c in range(cols):
            hit = 0
            for i in range(n):
                for j in range(n):
                    pen = PointInsidePen(glyphs, (x0 + (c + (j + 0.5) / n) * cell, y1 - (r + (i + 0.5) / n) * cell))
                    glyph.draw(pen)
                    hit += pen.getResult()
            if hit / (n * n) >= 0.5:
                on.append((c, r))
    red = max(on, key=lambda p: (p[0], -p[1]))   # the arm's end: the rightmost cell, the topmost among ties
    return cols, on, red


def mark(cols, on, red, ink, hit, gap, ground=None, units=8):
    """The pixel r centred on a units × units grid of whole cells; gap is the inset per cell side, 0 for pixel-exact."""
    ox, oy = (units - cols) / 2, (units - ROWS) / 2
    rects = []
    for c, r in on:
        fill = hit if (c, r) == red else ink
        rects.append(f'<rect x="{ox + c + gap:g}" y="{oy + r + gap:g}" width="{1 - 2 * gap:g}" height="{1 - 2 * gap:g}" '
                     f'rx="{gap * 1.2:g}" fill="{fill}"/>')
    bg = f'<rect width="{units}" height="{units}" rx="{units * 0.22:g}" fill="{ground}"/>' if ground else ""
    return (f'{HEADER}<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {units} {units}">'
            f'<title>revokt</title>{bg}{"".join(rects)}</svg>\n')


def favicon_svg(cols, on, red):
    """The mark with its colours following the viewer's theme, for browsers that take an SVG favicon."""
    ox, oy = (8 - cols) / 2, (8 - ROWS) / 2
    rects = "".join(f'<rect class="{"h" if (c, r) == red else "i"}" x="{ox + c:g}" y="{oy + r:g}" width="1" height="1"/>'
                    for c, r in on)
    style = (f".i{{fill:{INK}}}.h{{fill:{HIT}}}"
             f"@media (prefers-color-scheme:dark){{.i{{fill:{INK_DARK}}}.h{{fill:{HIT_DARK}}}}}")
    return (f'{HEADER}<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8" shape-rendering="crispEdges">'
            f"<title>revokt</title><style>{style}</style>{rects}</svg>\n")


def outline(path, text, x, baseline, size):
    """The text as one SVG path per glyph, at x and baseline in user units, size the em in user units."""
    font = TTFont(path)
    glyphs, cmap, hmtx = font.getGlyphSet(), font.getBestCmap(), font["hmtx"]
    scale = size / font["head"].unitsPerEm
    out = []
    for ch in text:
        name = cmap[ord(ch)]
        pen = SVGPathPen(glyphs)
        glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x, baseline)))
        out.append((ch, pen.getCommands()))
        x += hmtx[name][0] * scale
    return out, x


PENCIL = ('<filter id="pencil" x="-4%" y="-60%" width="108%" height="220%">'
          '<feTurbulence type="fractalNoise" baseFrequency="0.7" numOctaves="2" seed="4" result="wobble"/>'
          '<feDisplacementMap in="SourceGraphic" in2="wobble" scale="2.4" xChannelSelector="R" yChannelSelector="G" result="edge"/>'
          '<feTurbulence type="fractalNoise" baseFrequency="1.4 2.6" numOctaves="1" seed="9" result="grain"/>'
          '<feColorMatrix in="grain" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  1.9 0 0 0 -0.32" result="grainAlpha"/>'
          '<feComposite in="edge" in2="grainAlpha" operator="in"/></filter>')


def wordmark_body(ink, hit, x=10, baseline=48, size=52):
    """revokt with kt faded and a red pencil strike across the word, as in the approved concept (52-unit em)."""
    glyphs, end = outline(BOLD, "revokt", x, baseline, size)
    paths = []
    for i, (ch, d) in enumerate(glyphs):
        opacity = f' fill-opacity="{KT_OPACITY}"' if i >= 4 else ""
        paths.append(f'<path d="{d}" fill="{ink}"{opacity}/>')
    k = size / 52   # the strike was drawn for a 52-unit em with the word at x = 10, baseline 48
    def p(px, py):
        return f"{x + (px - 10) * k:.2f} {baseline + (py - 48) * k:.2f}"
    strike = (f'<path d="M{p(3, 40)} C {p(60, 35.5)}, {p(140, 31)}, {p(213, 25.5)}" stroke="{hit}" '
              f'stroke-width="{4.2 * k:.2f}" stroke-linecap="round" fill="none" opacity=".82" filter="url(#pencil)"/>')
    return "".join(paths) + strike, end


def wordmark(ink, hit):
    body, end = wordmark_body(ink, hit)
    w = round(end + 18)
    return (f'{HEADER}<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} 70" width="{w * 2}" height="140">'
            f"<title>revokt</title><defs>{PENCIL}</defs>{body}</svg>\n")


def social(cols, on, red):
    """The 1280 × 640 social preview: dark ground, the wordmark, the tagline, the mark in the corner."""
    body, _ = wordmark_body(INK_DARK, HIT_DARK, x=104, baseline=300, size=220)
    line_paths = []
    for i, line in enumerate(["Browser-grade TLS revocation checking", "for the JVM and Android, in pure Kotlin."]):
        glyphs, _ = outline(REGULAR, line, 110, 400 + i * 52, 38)
        line_paths += [f'<path d="{d}" fill="#9fb3bd"/>' for _, d in glyphs if d]
    ox, oy, unit = 1080, 450, 22
    cells = "".join(f'<rect x="{ox + c * unit + 1.5}" y="{oy + r * unit + 1.5}" width="{unit - 3}" height="{unit - 3}" rx="3" '
                    f'fill="{HIT_DARK if (c, r) == red else INK_DARK}"/>' for c, r in on)
    return (f'{HEADER}<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 640" width="1280" height="640">'
            f'<title>revokt</title><defs>{PENCIL}</defs><rect width="1280" height="640" fill="{GROUND_DARK}"/>'
            f'{body}{"".join(line_paths)}{cells}</svg>\n')


def write(name, text):
    with open(os.path.join(OUT, name), "w") as f:
        f.write(text)


cols, on, red = pixel_r()
write("mark.svg", mark(cols, on, red, INK, HIT, gap=0.06))
write("mark-dark.svg", mark(cols, on, red, INK_DARK, HIT_DARK, gap=0.06))
write("mark-tile.svg", mark(cols, on, red, INK_DARK, HIT_DARK, gap=0.06, ground=GROUND_DARK))
write("mark-pixel.svg", mark(cols, on, red, INK, HIT, gap=0))
write("favicon.svg", favicon_svg(cols, on, red))
write("wordmark.svg", wordmark(INK, HIT))
write("wordmark-dark.svg", wordmark(INK_DARK, HIT_DARK))
write("social-preview.svg", social(cols, on, red))
grid = ["".join("R" if (c, r) == red else "#" if (c, r) in on else "." for c in range(cols)) for r in range(ROWS)]
print(f"pixel r: {cols} x {ROWS}\n" + "\n".join(grid))
