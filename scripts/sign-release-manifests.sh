#!/usr/bin/env bash
set -euo pipefail

# Dual-format release signing: minisign (.minisig) + optional PGP (.asc)
#
# Usage: sign-release-manifests.sh <tag> [dir]
#
# Environment variables:
#   SFETCH_MINISIGN_KEY - Path to minisign secret key file. Primary format.
#   SFETCH_PGP_KEY_ID   - GPG key ID for PGP signing. Optional secondary format.
#   SFETCH_GPG_HOMEDIR  - Custom GPG homedir (optional, defaults to ~/.gnupg)
#
# Signing sets (deliberate split — do not "harmonise" without a lock):
#   minisign: SHA256SUMS, SHA512SUMS, and install-sfetch.sh
#   PGP:      SHA256SUMS and SHA512SUMS only (manifests)
#
# Why the installer is signed with minisign (second password prompt):
#   The installer is the one artifact consumers execute *before* any verifier
#   chain exists. Signing only manifests forces a five-step consumer path;
#   a detached install-sfetch.sh.minisig collapses that to three steps.
#   All other release assets remain covered by the signed checksum manifests.
#   Scaling is 2 prompts (manifests + installer), not N per-file signatures.
#
# Minisign was chosen over raw ed25519 because:
# - Created by Frank Denis (libsodium author), well-audited
# - Trusted comments provide signed metadata (version, timestamp)
# - Password-protected keys by default
# - Compatible with OpenBSD signify

TAG=${1:?"usage: sign-release-manifests.sh <tag> [dir]"}
DIR=${2:-dist/release}

SFETCH_MINISIGN_KEY=${SFETCH_MINISIGN_KEY:-}
SFETCH_PGP_KEY_ID=${SFETCH_PGP_KEY_ID:-}
SFETCH_GPG_HOMEDIR=${SFETCH_GPG_HOMEDIR:-}

if [ ! -d "$DIR" ]; then
    echo "error: directory $DIR not found" >&2
    exit 1
fi

checksum_files=()
for file in SHA256SUMS SHA512SUMS; do
    if [ -f "$DIR/$file" ]; then
        checksum_files+=("$file")
    fi
done

if [ ${#checksum_files[@]} -eq 0 ]; then
    echo "error: no checksum files found (run make release-checksums first)" >&2
    exit 1
fi

installer_file=""
if [ -f "$DIR/install-sfetch.sh" ]; then
    installer_file="install-sfetch.sh"
else
    echo "error: install-sfetch.sh not found in $DIR (run make bootstrap-script / release-checksums first)" >&2
    exit 1
fi

has_minisign=false
has_pgp=false

if [ -n "$SFETCH_MINISIGN_KEY" ]; then
    if [ ! -f "$SFETCH_MINISIGN_KEY" ]; then
        echo "error: SFETCH_MINISIGN_KEY=$SFETCH_MINISIGN_KEY not found" >&2
        exit 1
    fi
    if ! command -v minisign >/dev/null 2>&1; then
        echo "error: minisign not found in PATH" >&2
        echo "  Install: brew install minisign (macOS) or see https://jedisct1.github.io/minisign/" >&2
        exit 1
    fi
    has_minisign=true
    echo "minisign signing enabled (key: $SFETCH_MINISIGN_KEY)"
fi

if [ -n "$SFETCH_PGP_KEY_ID" ]; then
    if ! command -v gpg >/dev/null 2>&1; then
        echo "error: SFETCH_PGP_KEY_ID set but gpg not found in PATH" >&2
        exit 1
    fi
    has_pgp=true
    echo "PGP signing enabled (key: $SFETCH_PGP_KEY_ID)"
    if [ -n "$SFETCH_GPG_HOMEDIR" ]; then
        echo "GPG homedir: $SFETCH_GPG_HOMEDIR"
    fi
fi

if [ "$has_minisign" = false ] && [ "$has_pgp" = false ]; then
    echo "error: no signing method available" >&2
    echo "  Set SFETCH_MINISIGN_KEY for minisign signing" >&2
    echo "  Set SFETCH_PGP_KEY_ID for PGP signing" >&2
    exit 1
fi

# Minisign is required for the installer signature (release contract).
if [ "$has_minisign" = false ]; then
    echo "error: SFETCH_MINISIGN_KEY is required to sign install-sfetch.sh" >&2
    exit 1
fi

# Signing is grouped by tool (all minisign first, then all PGP) to minimize
# password prompt switching during manual signing workflows.

if [ "$has_minisign" = true ]; then
    echo ""
    echo "=== Minisign signatures (manifests + installer) ==="
    for file in "${checksum_files[@]}"; do
        echo "🔏 [minisign] Signing $file"
        rm -f "$DIR/$file.minisig"
        minisign -S -s "$SFETCH_MINISIGN_KEY" -t "sfetch $TAG $(date -u +%Y-%m-%dT%H:%M:%SZ)" -m "$DIR/$file"
    done
    echo "🔏 [minisign] Signing $installer_file"
    rm -f "$DIR/${installer_file}.minisig"
    minisign -S -s "$SFETCH_MINISIGN_KEY" -t "sfetch $TAG install-sfetch.sh $(date -u +%Y-%m-%dT%H:%M:%SZ)" -m "$DIR/$installer_file"
fi

if [ "$has_pgp" = true ]; then
    echo ""
    echo "=== PGP signatures (manifests only) ==="
    for file in "${checksum_files[@]}"; do
        echo "🔏 [PGP] Signing $file"
        if [ -n "$SFETCH_GPG_HOMEDIR" ]; then
            env GNUPGHOME="$SFETCH_GPG_HOMEDIR" gpg --batch --yes --armor --local-user "$SFETCH_PGP_KEY_ID" --detach-sign -o "$DIR/$file.asc" "$DIR/$file"
        else
            gpg --batch --yes --armor --local-user "$SFETCH_PGP_KEY_ID" --detach-sign -o "$DIR/$file.asc" "$DIR/$file"
        fi
    done
fi

echo ""
echo "✅ Signing complete for $TAG"
for file in "${checksum_files[@]}"; do
    if [ "$has_minisign" = true ]; then
        echo "   $file.minisig: verify with --minisign-key"
    fi
    if [ "$has_pgp" = true ]; then
        echo "   $file.asc: verify with --pgp-key-file"
    fi
done
if [ "$has_minisign" = true ]; then
    echo "   ${installer_file}.minisig: required release-gate artifact (minisign only)"
fi
