<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Brand assets

revokt's visual identity has two marks, both drawn from [Source Code Pro](https://github.com/adobe-fonts/source-code-pro)
Bold, release 2.042.

| Mark | Use | Files |
|---|---|---|
| **Pixel r** | Small sizes: favicon, touch icon, avatar | `mark.svg`, `mark-dark.svg`, `mark-tile.svg`, `mark-square.svg`, `mark-pixel.svg`, `favicon.svg`, `favicon.ico`, `favicon-16.png`, `favicon-32.png`, `apple-touch-icon.png`, `mark-512.png` |
| **Struck wordmark** | Large sizes: README header, social preview | `wordmark.svg`, `wordmark-dark.svg`, `social-preview.svg`, `social-preview.png` |

**The pixel r** is Source Code Pro Bold's own `r`, sampled onto a square grid 6 cells tall: a cell is filled when the
glyph's outline covers half of it or more. The cell at the end of the arm is red. That is the revoked certificate,
the one bit CRLite exists to find. On an 8 × 8 grid the mark is pixel-exact at 16, 32 and 48 px (`mark-pixel.svg`,
used for the favicons). The other versions inset each cell slightly so the grid reads at large sizes. `favicon.svg`
follows the viewer's light or dark theme; `favicon.ico` and the favicon PNGs use the light-ground ink.
`apple-touch-icon.png` is an opaque square (`mark-square.svg`), since iOS applies its own mask.

**The wordmark** is `revokt` in Source Code Pro Bold, converted to outlines so it renders without the font:
- `kt` is faded to 70%, a nod to Kotlin's file extension;
- a red pencil strike runs through the whole word, faint and grainy, as if struck off a list by hand.

The pencil texture is an SVG filter and disappears at small sizes, which is why the small mark has no strike.

**Colours**

| | Ink | Revoked red | Ground |
|---|---|---|---|
| Light | `#15303d` | `#c62d42` | any light |
| Dark | `#e2ebef` | `#ef5b6e` | `#10202a` |

The social preview's tagline is `#9fb3bd`, in Source Code Pro Regular.

**Rebuilding.** `build.py` writes the SVGs from the font files. `render.sh` renders the PNGs and `favicon.ico` with
`rsvg-convert` and ImageMagick:

```sh
uv run --no-project --with fonttools==4.55.3 python3 -I docs/assets/brand/build.py <font dir> docs/assets/brand
sh docs/assets/brand/render.sh
```

`<font dir>` holds the TTFs of the font's release 2.042 (`TTF-source-code-pro-2.042R-u_1.062R-i.zip`):

| File | SHA-256 |
|---|---|
| `SourceCodePro-Bold.ttf` | `b2095e0d657e6d28dc32444a9dacabab0c9241d0bf39d96371756cc9bdbc3a5f` |
| `SourceCodePro-Regular.ttf` (the social preview's tagline) | `74bd80d3e42a08517cd7e1108ba3d86f2da29ac0f3065be95e0357956ab9db37` |

**Licence.** Source Code Pro is under the SIL Open Font License 1.1. The OFL FAQ (1.1 and 1.1.1) allows logos made
from a font's outlines and says the resulting artwork is not subject to the OFL. These files are Apache-2.0, like the
rest of the repository.

**Not set from here.** GitHub's social preview is uploaded in the repository's settings (Settings → General → Social
preview) from `social-preview.png`. A repository has no avatar of its own; `mark-512.png` is for any place that wants
the mark as an image.
