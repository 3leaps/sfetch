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

# Installer detached signature is required before upload (release contract).
# Without it the release must not be treated as consumable for bootstrap.
if [ ! -f "$DIR/install-sfetch.sh.minisig" ]; then
    echo "❌ required signature missing: $DIR/install-sfetch.sh.minisig" >&2
    echo "   Run 'make release-sign' then 'make release-verify' before upload." >&2
    exit 1
fi

# Assumes release artifacts were built in CI and downloaded locally.
# This script only re-uploads/clobbers assets on GitHub.
shopt -s nullglob
ARTIFACTS=("$DIR"/sfetch_* "$DIR"/SHA256SUMS "$DIR"/SHA512SUMS "$DIR"/install-sfetch.sh)
# Build signature list from globs only; filter to existing files.
# Include installer minisig explicitly (not covered by SHA*SUMS.* globs).
SIG_CANDIDATES=(
    "$DIR"/SHA256SUMS.*
    "$DIR"/SHA512SUMS.*
    "$DIR"/install-sfetch.sh.minisig
    "$DIR"/*-minisign.pub
    "$DIR"/*-signing-key.asc
)
SIGNATURES=()
for f in "${SIG_CANDIDATES[@]}"; do
    if [ -f "$f" ]; then
        SIGNATURES+=("$f")
    fi
done
if [ ${#ARTIFACTS[@]} -eq 0 ]; then
    echo "no artifacts to upload" >&2
    exit 1
fi
echo "📤 Uploading binaries/checksums for ${TAG}"
gh release upload "$TAG" "${ARTIFACTS[@]}" --clobber
echo "📤 Uploading signatures and keys"
if [ ${#SIGNATURES[@]} -eq 0 ]; then
    echo "❌ No signature files found in $DIR" >&2
    echo "   Did you run 'make release-sign' first?" >&2
    exit 1
fi
# Hard-require installer minisig in the upload set (belt and suspenders with file check above).
has_installer_sig=false
for f in "${SIGNATURES[@]}"; do
    case "$f" in
        */install-sfetch.sh.minisig) has_installer_sig=true ;;
    esac
done
if [ "$has_installer_sig" != true ]; then
    echo "❌ install-sfetch.sh.minisig not in upload set" >&2
    exit 1
fi
gh release upload "$TAG" "${SIGNATURES[@]}" --clobber
echo "📝 Updating release notes"
gh release edit "$TAG" --notes-file "$NOTES_FILE"
echo "✅ Release updated"
echo ""
echo "If the release is still a draft, publish only after this upload succeeds:"
echo "  gh release edit ${TAG} --draft=false"
echo "Until then the release is incomplete / non-consumable for bootstrap consumers."
