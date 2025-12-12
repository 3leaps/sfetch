#!/usr/bin/env bash
set -euo pipefail
KEY_ID=${1:?"usage: export-release-key.sh <key-id> [dest_dir]"}
DIR=${2:-dist/release}
if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg is required" >&2
    exit 1
fi
mkdir -p "$DIR"
OUTPUT="$DIR/sfetch-release-signing-key.asc"
exec gpg --armor --export "$KEY_ID" >"$OUTPUT"
echo "✅ Exported $KEY_ID to $OUTPUT"
