#!/bin/sh
# Regenerates the application icons of src-tauri/icons from the SVG sources in
# src-tauri/icons/source (themselves taken from brand/logo). Needs rsvg-convert (librsvg)
# and Python 3 with Pillow. The generated files are committed: the build does not run this.
set -eu
cd "$(dirname "$0")/../src-tauri/icons"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

rsvg-convert -w 32 -h 32 source/icone-petite.svg -o 32x32.png
rsvg-convert -w 128 -h 128 source/icone.svg -o 128x128.png
rsvg-convert -w 256 -h 256 source/icone.svg -o 128x128@2x.png
rsvg-convert -w 512 -h 512 source/icone.svg -o icon.png
for s in 16 24 32 48 64 256 1024; do
  src=source/icone.svg
  if [ "$s" -le 32 ]; then src=source/icone-petite.svg; fi
  rsvg-convert -w "$s" -h "$s" "$src" -o "$tmp/i$s.png"
done
python3 -I - "$tmp" <<'EOF'
import sys
from PIL import Image
tmp = sys.argv[1]
img = {s: Image.open(f"{tmp}/i{s}.png").convert("RGBA") for s in (16, 24, 32, 48, 64, 256, 1024)}
img[256].save("icon.ico", sizes=[(s, s) for s in (16, 24, 32, 48, 64, 256)],
              append_images=[img[s] for s in (16, 24, 32, 48, 64)])
img[1024].save("icon.icns")
EOF
