#!/usr/bin/env bash
set -euo pipefail

# Upload only provenance assets (manifests, signatures, keys, notes) to a
# GitHub release. Does NOT upload binaries — CI handles those.
#
# Usage: release-upload-provenance.sh <tag> [dir]

TAG="${1:?"usage: release-upload-provenance.sh <tag> [dir]"}"
DIR="${2:-dist/release}"

if ! command -v gh >/dev/null 2>&1; then
    echo "gh CLI is required" >&2
    exit 1
fi

if [ ! -d "$DIR" ]; then
    echo "directory $DIR not found" >&2
    exit 1
fi

shopt -s nullglob

# Collect provenance assets, filtering to files that exist.
candidates=()
candidates+=("$DIR"/SHA256SUMS "$DIR"/SHA512SUMS)
candidates+=("$DIR"/SHA256SUMS.* "$DIR"/SHA512SUMS.*)
candidates+=("$DIR"/*.pub)
candidates+=("$DIR"/*-signing-key.asc)
candidates+=("$DIR"/release-notes-*.md)

assets=()
for f in "${candidates[@]}"; do
    if [ -f "$f" ]; then
        assets+=("$f")
    fi
done

if [ ${#assets[@]} -eq 0 ]; then
    echo "❌ No provenance assets found in $DIR" >&2
    exit 1
fi

echo "📤 Uploading ${#assets[@]} provenance asset(s) to ${TAG} (clobber)"
gh release upload "$TAG" "${assets[@]}" --clobber

# Update release notes if present
NOTES_FILE="$DIR/release-notes-${TAG}.md"
if [ -f "$NOTES_FILE" ]; then
    echo "📝 Updating release notes"
    gh release edit "$TAG" --notes-file "$NOTES_FILE"
fi

echo "✅ Provenance upload complete"
