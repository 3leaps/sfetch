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

# Determine hasher command
if command -v sha256sum >/dev/null 2>&1; then
	HASHER="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
	HASHER="shasum -a 256"
else
	echo "sha256sum or shasum required" >&2
	exit 1
fi

OUTPUT="$DIR/SHA256SUMS"
rm -f "$OUTPUT"

# Hash files from within the directory so output contains basenames only
(
	cd "$DIR" || exit 1
	shopt -s nullglob

	for file in sfetch_*; do
		case "$file" in
		*.asc | *.sha256 | *.minisig | SHA256SUMS*) continue ;;
		esac
		if [ -f "$file" ]; then
			$HASHER "$file"
		fi
	done

	# Include install-sfetch.sh if present (bootstrap script)
	if [ -f "install-sfetch.sh" ]; then
		$HASHER "install-sfetch.sh"
	fi
) >"$OUTPUT"

# Check if we found any files
if [ ! -s "$OUTPUT" ]; then
	rm -f "$OUTPUT"
	echo "no release archives found in $DIR" >&2
	exit 1
fi

echo "✅ [$TAG] Wrote SHA256SUMS with $(wc -l <"$OUTPUT") entries"
