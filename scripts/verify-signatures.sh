#!/usr/bin/env bash
set -euo pipefail

# Verify release signatures (minisign and optional PGP) on checksum manifests.
#
# Usage: verify-signatures.sh [dir]
#
# Env:
#   SFETCH_MINISIGN_PUB - path to minisign public key (required for minisign)
#   SFETCH_GPG_HOMEDIR  - isolated gpg homedir for PGP verification (optional)

DIR=${1:-dist/release}

if [ ! -d "$DIR" ]; then
    echo "error: directory $DIR not found" >&2
    exit 1
fi

SFETCH_MINISIGN_PUB=${SFETCH_MINISIGN_PUB:-}
SFETCH_GPG_HOMEDIR=${SFETCH_GPG_HOMEDIR:-}

verified=0
failed=0

verify_minisign() {
    local manifest="$1"
    local base="${DIR}/${manifest}"
    local sig="${base}.minisig"

    if [ ! -f "${sig}" ]; then
        echo "ℹ️  No minisign signature for ${manifest} (skipping)"
        return 0
    fi

    if [ -z "${SFETCH_MINISIGN_PUB}" ]; then
        echo "⚠️  SFETCH_MINISIGN_PUB not set, cannot verify ${manifest}.minisig"
        failed=$((failed + 1))
        return 1
    fi

    if [ ! -f "${SFETCH_MINISIGN_PUB}" ]; then
        echo "error: SFETCH_MINISIGN_PUB=${SFETCH_MINISIGN_PUB} not found" >&2
        failed=$((failed + 1))
        return 1
    fi

    if ! command -v minisign >/dev/null 2>&1; then
        echo "error: minisign not found in PATH" >&2
        failed=$((failed + 1))
        return 1
    fi

    echo "🔍 [minisign] Verifying ${manifest}"
    if minisign -V -p "${SFETCH_MINISIGN_PUB}" -m "${base}"; then
        echo "✅ ${manifest}.minisig verified"
        verified=$((verified + 1))
    else
        echo "❌ ${manifest}.minisig verification FAILED"
        failed=$((failed + 1))
    fi
}

verify_pgp() {
    local manifest="$1"
    local base="${DIR}/${manifest}"
    local sig="${base}.asc"

    if [ ! -f "${sig}" ]; then
        echo "ℹ️  No PGP signature for ${manifest} (skipping)"
        return 0
    fi

    if ! command -v gpg >/dev/null 2>&1; then
        echo "⚠️  gpg not found, cannot verify ${manifest}.asc"
        failed=$((failed + 1))
        return 1
    fi

    local -a gpg_opts=()
    if [ -n "${SFETCH_GPG_HOMEDIR}" ] && [ -d "${SFETCH_GPG_HOMEDIR}" ]; then
        gpg_opts=("--homedir" "${SFETCH_GPG_HOMEDIR}")
    fi

    echo "🔍 [PGP] Verifying ${manifest}"
    if gpg "${gpg_opts[@]}" --verify "${sig}" "${base}" 2>&1; then
        echo "✅ ${manifest}.asc verified"
        verified=$((verified + 1))
    else
        echo "❌ ${manifest}.asc verification FAILED"
        failed=$((failed + 1))
    fi
}

echo "Verifying release signatures in ${DIR}..."
echo ""

verify_minisign "SHA256SUMS"
verify_minisign "SHA512SUMS"

echo ""

verify_pgp "SHA256SUMS"
verify_pgp "SHA512SUMS"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $failed -gt 0 ]; then
    echo "❌ Signature verification: ${verified} passed, ${failed} FAILED"
    exit 1
elif [ $verified -eq 0 ]; then
    echo "⚠️  No signatures found to verify"
    exit 1
else
    echo "✅ Signature verification: ${verified} passed"
fi
