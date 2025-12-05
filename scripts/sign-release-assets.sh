#!/usr/bin/env bash
set -euo pipefail
TAG=${1:?"usage: sign-release-assets.sh <tag> [dir]"}
DIR=${2:-dist/release}
KEY_ID=${PGP_KEY_ID:-}
if ! command -v gpg >/dev/null 2>&1; then
  echo "gpg is required to sign artifacts" >&2
  exit 1
fi
if [ ! -d "$DIR" ]; then
  echo "directory $DIR not found" >&2
  exit 1
fi
shopt -s nullglob
artifacts=("$DIR"/sfetch_* "$DIR"/SHA256SUMS)
if [ ${#artifacts[@]} -eq 0 ]; then
  echo "no artifacts found in $DIR" >&2
  exit 1
fi
sign() {
  local file=$1
  local output="${file}.asc"
  echo "🔏 Signing $(basename "$file")"
  gpg --batch --yes --armor ${KEY_ID:+--local-user "$KEY_ID"} --detach-sign -o "$output" "$file"
}
for artifact in "${artifacts[@]}"; do
  case "$artifact" in
    *.asc|*.sha256)
      continue
      ;;
    *)
      if [ -f "$artifact" ]; then
        sign "$artifact"
      fi
      ;;
  esac
done
if [ -f "$DIR/SHA256SUMS" ]; then
  sign "$DIR/SHA256SUMS"
fi
echo "✅ Signing complete"
