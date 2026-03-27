#!/bin/sh
set -e

basedir="$(realpath "$0" | xargs dirname)"

SRC="$basedir/icon_raw_2.png"
DST="$basedir/icon.png"

magick "$SRC" -crop 560x560+40+40 +repage -resize 64x64 "$DST"

echo "Wrote $DST"
