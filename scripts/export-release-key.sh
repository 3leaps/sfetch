#!/usr/bin/env bash
set -euo pipefail

# Export PGP public key for release signing verification
#
# Usage: export-release-key.sh <key-id> [dest_dir]
#
# Environment variables:
#   SFETCH_GPG_HOMEDIR - Custom GPG homedir (optional, defaults to ~/.gnupg)

KEY_ID=${1:?"usage: export-release-key.sh <key-id> [dest_dir]"}
DIR=${2:-dist/release}
SFETCH_GPG_HOMEDIR=${SFETCH_GPG_HOMEDIR:-}

if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg is required" >&2
    exit 1
fi
mkdir -p "$DIR"
OUTPUT="$DIR/sfetch-release-signing-key.asc"

if [ -n "$SFETCH_GPG_HOMEDIR" ]; then
    env GNUPGHOME="$SFETCH_GPG_HOMEDIR" gpg --armor --export "$KEY_ID" >"$OUTPUT"
else
    gpg --armor --export "$KEY_ID" >"$OUTPUT"
fi

echo "✅ Exported $KEY_ID to $OUTPUT"
