<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Brand assets

revokt's visual identity has two marks, both drawn from [Source Code Pro](https://github.com/adobe-fonts/source-code-pro)
Bold, release 2.042.

| Mark | Use | Files |
|---|---|---|
| **Pixel r** | Small sizes: favicon, touch icon, avatar | `mark.svg`, `mark-dark.svg`, `mark-tile.svg`, `mark-pixel.svg`, `favicon.svg`, `favicon.ico`, `favicon-16.png`, `favicon-32.png`, `apple-touch-icon.png`, `mark-512.png` |
| **Struck wordmark** | Large sizes: README header, social preview | `wordmark.svg`, `wordmark-dark.svg`, `social-preview.svg`, `social-preview.png` |

**The pixel r** is Source Code Pro Bold's own `r`, sampled onto a square grid 6 cells tall: a cell is filled when the
glyph's outline covers half of it or more. The cell at the end of the arm is red. That is the revoked certificate,
the one bit CRLite exists to find. On an 8 × 8 grid the mark is pixel-exact at 16, 32 and 48 px (`mark-pixel.svg`,
used for the favicons). The other versions inset each cell slightly so the grid reads at large sizes.

**The wordmark** is `revokt` in Source Code Pro Bold, converted to outlines so it renders without the font:
- `kt` is faded to 70%, a nod to Kotlin's file extension;
- a red pencil strike runs through the whole word, faint and grainy, as if struck off a list by hand.

The pencil texture is an SVG filter and disappears at small sizes, which is why the small mark has no strike.

**Colours**

| | Ink | Revoked red | Ground |
|---|---|---|---|
| Light | `#15303d` | `#c62d42` | any light |
| Dark | `#e2ebef` | `#ef5b6e` | `#10202a` |

**Rebuilding.** `build.py` writes the SVGs from the font files. `render.sh` renders the PNGs and `favicon.ico` with
`rsvg-convert` and ImageMagick:

```sh
uv run --no-project --with fonttools==4.55.3 python3 -I docs/assets/brand/build.py <font dir> docs/assets/brand
sh docs/assets/brand/render.sh
```

`<font dir>` holds `SourceCodePro-Bold.ttf` (SHA-256 `b2095e0d…bdbc3a5f`) and `SourceCodePro-Regular.ttf` (SHA-256
`74bd80d3…6ab9db37`, for the social preview's tagline) from the font's release 2.042.

**Licence.** Source Code Pro is under the SIL Open Font License 1.1. The OFL FAQ (1.1 and 1.1.1) allows logos made
from a font's outlines and says the resulting artwork is not subject to the OFL. These files are Apache-2.0, like the
rest of the repository.

**Not set from here.** GitHub's social preview is uploaded in the repository's settings (Settings → General → Social
preview) from `social-preview.png`. An avatar belongs to the account, not to a repository; `mark-512.png` is ready if
the project moves to an organisation.
