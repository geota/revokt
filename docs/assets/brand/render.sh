#!/bin/sh
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
# Renders the PNGs and favicon.ico from the SVGs build.py writes (README.md). Needs rsvg-convert and ImageMagick.
set -eu
cd "$(dirname "$0")"
for px in 16 32 48; do rsvg-convert -w "$px" -h "$px" mark-pixel.svg -o "favicon-$px.png"; done
magick favicon-16.png favicon-32.png favicon-48.png favicon.ico
rm favicon-48.png
rsvg-convert -w 180 -h 180 mark-tile.svg -o apple-touch-icon.png
rsvg-convert -w 512 -h 512 mark-tile.svg -o mark-512.png
rsvg-convert -w 1280 -h 640 social-preview.svg -o social-preview.png
