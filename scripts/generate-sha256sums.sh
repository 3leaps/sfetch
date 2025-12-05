#!/usr/bin/env bash
set -euo pipefail
TAG=${1:?"usage: generate-sha256sums.sh <tag> [dir]"}
DIR=${2:-dist/release}
# This script operates on the artifacts downloaded from GitHub releases.
# It does not rebuild or clobber any archives locally.
if [ ! -d "$DIR" ]; then
  echo "directory $DIR not found" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  HASHER=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  HASHER=(shasum -a 256)
else
  echo "sha256sum or shasum required" >&2
  exit 1
fi
OUTPUT="$DIR/SHA256SUMS"
rm -f "$OUTPUT"
shopt -s nullglob
found=0
for file in "$DIR"/sfetch_*; do
  base=$(basename "$file")
  case "$base" in
    *.asc|*.sha256|SHA256SUMS*) continue ;;
  esac
  if [ -f "$file" ]; then
    "${HASHER[@]}" "$file" >> "$OUTPUT"
    found=1
  fi
done
if [ $found -eq 0 ]; then
  rm -f "$OUTPUT"
  echo "no release archives found in $DIR" >&2
  exit 1
fi
echo "✅ Wrote SHA256SUMS with $(wc -l < "$OUTPUT") entries"
