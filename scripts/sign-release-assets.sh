#!/usr/bin/env bash
set -euo pipefail

# Dual-format release signing: minisign (.minisig) + PGP (.asc)
#
# Usage: sign-release-assets.sh <tag> [dir]
#
# Environment variables:
#   MINISIGN_KEY - Path to minisign secret key file. Primary format.
#   PGP_KEY_ID   - GPG key ID for PGP signing. Optional secondary format.
#
# Minisign was chosen over raw ed25519 because:
# - Created by Frank Denis (libsodium author), well-audited
# - Trusted comments provide signed metadata (version, timestamp)
# - Password-protected keys by default
# - Compatible with OpenBSD signify
#
# Only SHA256SUMS is signed (not individual files). This is the standard pattern:
# verify signature on checksum file, then verify file checksums against that.
# This means one password prompt instead of N.

TAG=${1:?"usage: sign-release-assets.sh <tag> [dir]"}
DIR=${2:-dist/release}

MINISIGN_KEY=${MINISIGN_KEY:-}
PGP_KEY_ID=${PGP_KEY_ID:-}

# Validation
if [ ! -d "$DIR" ]; then
	echo "error: directory $DIR not found" >&2
	exit 1
fi

if [ ! -f "$DIR/SHA256SUMS" ]; then
	echo "error: $DIR/SHA256SUMS not found (run make release-sha256 first)" >&2
	exit 1
fi

has_minisign=false
has_pgp=false

if [ -n "$MINISIGN_KEY" ]; then
	if [ ! -f "$MINISIGN_KEY" ]; then
		echo "error: MINISIGN_KEY=$MINISIGN_KEY not found" >&2
		exit 1
	fi
	if ! command -v minisign >/dev/null 2>&1; then
		echo "error: minisign not found in PATH" >&2
		echo "  Install: brew install minisign (macOS) or see https://jedisct1.github.io/minisign/" >&2
		exit 1
	fi
	has_minisign=true
	echo "minisign signing enabled (key: $MINISIGN_KEY)"
fi

# Only enable PGP if explicitly requested via PGP_KEY_ID
if [ -n "$PGP_KEY_ID" ]; then
	if ! command -v gpg >/dev/null 2>&1; then
		echo "error: PGP_KEY_ID set but gpg not found in PATH" >&2
		exit 1
	fi
	has_pgp=true
	echo "PGP signing enabled (key: $PGP_KEY_ID)"
fi

if [ "$has_minisign" = false ] && [ "$has_pgp" = false ]; then
	echo "error: no signing method available" >&2
	echo "  Set MINISIGN_KEY for minisign signing" >&2
	echo "  Set PGP_KEY_ID for PGP signing" >&2
	exit 1
fi

# Sign SHA256SUMS only (standard practice)
# Users verify: 1) signature on SHA256SUMS, 2) file checksums against SHA256SUMS

if [ "$has_minisign" = true ]; then
	echo "🔏 [minisign] Signing SHA256SUMS"
	# Remove old signature if present (minisign won't overwrite)
	rm -f "$DIR/SHA256SUMS.minisig"
	minisign -S -s "$MINISIGN_KEY" -t "sfetch $TAG $(date -u +%Y-%m-%dT%H:%M:%SZ)" -m "$DIR/SHA256SUMS"
fi

if [ "$has_pgp" = true ]; then
	echo "🔏 [PGP] Signing SHA256SUMS"
	gpg --batch --yes --armor --local-user "$PGP_KEY_ID" --detach-sign -o "$DIR/SHA256SUMS.asc" "$DIR/SHA256SUMS"
fi

echo ""
echo "✅ Signing complete for $TAG"
if [ "$has_minisign" = true ]; then
	echo "   SHA256SUMS.minisig: verify with --minisign-key"
fi
if [ "$has_pgp" = true ]; then
	echo "   SHA256SUMS.asc: verify with --pgp-key-file"
fi
