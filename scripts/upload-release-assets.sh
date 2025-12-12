#!/usr/bin/env bash
set -euo pipefail
TAG=${1:?"usage: upload-release-assets.sh <tag> [dir]"}
DIR=${2:-dist/release}
if ! command -v gh >/dev/null 2>&1; then
    echo "gh CLI is required" >&2
    exit 1
fi
if [ ! -d "$DIR" ]; then
    echo "directory $DIR not found" >&2
    exit 1
fi
NOTES_FILE="$DIR/release-notes-${TAG}.md"
if [ ! -f "$NOTES_FILE" ]; then
    echo "release notes file $NOTES_FILE not found" >&2
    exit 1
fi
# Assumes release artifacts were built in CI and downloaded locally.
# This script only re-uploads/clobbers assets on GitHub.
shopt -s nullglob
ARTIFACTS=("$DIR"/sfetch_* "$DIR"/SHA256SUMS "$DIR"/SHA2-512SUMS "$DIR"/install-sfetch.sh)
SIGNATURES=("$DIR"/SHA256SUMS.minisig "$DIR"/SHA256SUMS.asc "$DIR"/SHA2-512SUMS.minisig "$DIR"/SHA2-512SUMS.asc "$DIR"/*-minisign.pub "$DIR"/*-signing-key.asc)
if [ ${#ARTIFACTS[@]} -eq 0 ]; then
    echo "no artifacts to upload" >&2
    exit 1
fi
echo "📤 Uploading binaries/checksums for ${TAG}"
gh release upload "$TAG" "${ARTIFACTS[@]}" --clobber
echo "📤 Uploading signatures and keys"
if [ ${#SIGNATURES[@]} -gt 0 ]; then
    gh release upload "$TAG" "${SIGNATURES[@]}" --clobber
else
    echo "⚠️  No signature files found; skipping"
fi
echo "📝 Updating release notes"
gh release edit "$TAG" --notes-file "$NOTES_FILE"
echo "✅ Release updated"
