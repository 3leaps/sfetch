#!/usr/bin/env bash
set -euo pipefail

# Verify release signatures (minisign and optional PGP).
#
# Usage: verify-signatures.sh [dir]
#
# Env:
#   SFETCH_MINISIGN_PUB - path to minisign public key (required for minisign)
#   SFETCH_GPG_HOMEDIR  - isolated gpg homedir for PGP verification (optional)
#
# Policy (deliberate divergence — do not re-harmonise without a lock):
#   - install-sfetch.sh.minisig is REQUIRED. Missing signature ⇒ non-zero exit.
#     This is the gate that prevents declaring a release consumable before the
#     installer is signed (bootstrap consumers must not race the pre-signature window).
#   - SHA256SUMS / SHA512SUMS minisign: optional-skip when absent (legacy path);
#     if present, verification must pass.
#   - PGP (.asc) remains optional: skip when absent; verify when present.

DIR=${1:-dist/release}

if [ ! -d "$DIR" ]; then
    echo "error: directory $DIR not found" >&2
    exit 1
fi

SFETCH_MINISIGN_PUB=${SFETCH_MINISIGN_PUB:-}
SFETCH_GPG_HOMEDIR=${SFETCH_GPG_HOMEDIR:-}

verified=0
failed=0
_anchor_checked=0

# Canonical consumer-facing trust anchor SSOT (must match main.go embed,
# install-sfetch.sh, and bootstrap-sfetch-verified.sh).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANONICAL_ANCHOR_PUB="${SCRIPT_DIR}/sfetch-minisign-anchor.pub"

extract_minisign_rw_line() {
    local f="$1"
    # Prefer a line that is exactly the RW key; fall back to first RW token.
    local line
    line="$(grep -E '^RW[A-Za-z0-9+/]{54}$' "$f" 2>/dev/null | head -n1 | tr -d '\r\n' || true)"
    if [ -n "$line" ]; then
        printf '%s\n' "$line"
        return 0
    fi
    line="$(grep -E 'RW[A-Za-z0-9+/]{54}' "$f" 2>/dev/null | head -n1 | tr -d '\r\n' || true)"
    # Extract the RW token if surrounded by other text
    printf '%s\n' "$line" | grep -oE 'RW[A-Za-z0-9+/]{54}' | head -n1
}

require_minisign_tool() {
    if ! command -v minisign >/dev/null 2>&1; then
        echo "error: minisign not found in PATH" >&2
        failed=$((failed + 1))
        return 1
    fi
    return 0
}

# F1: gate must prove signatures verify against *the* consumer anchor, not an
# arbitrary operator-supplied key that happens to match the signatures.
assert_operator_pub_is_canonical_anchor() {
    if [ "${_anchor_checked}" -eq 1 ]; then
        return 0
    fi
    if [ ! -f "${CANONICAL_ANCHOR_PUB}" ]; then
        echo "error: canonical trust anchor missing: ${CANONICAL_ANCHOR_PUB}" >&2
        failed=$((failed + 1))
        return 1
    fi
    local expect got
    expect="$(extract_minisign_rw_line "${CANONICAL_ANCHOR_PUB}")"
    got="$(extract_minisign_rw_line "${SFETCH_MINISIGN_PUB}")"
    if [ -z "${expect}" ]; then
        echo "error: canonical anchor has no RW… key line: ${CANONICAL_ANCHOR_PUB}" >&2
        failed=$((failed + 1))
        return 1
    fi
    if [ -z "${got}" ]; then
        echo "error: SFETCH_MINISIGN_PUB has no RW… key line: ${SFETCH_MINISIGN_PUB}" >&2
        failed=$((failed + 1))
        return 1
    fi
    if [ "${got}" != "${expect}" ]; then
        echo "error: SFETCH_MINISIGN_PUB does not match the canonical consumer trust anchor" >&2
        echo "  expected (scripts/sfetch-minisign-anchor.pub): ${expect}" >&2
        echo "  got (SFETCH_MINISIGN_PUB):                     ${got}" >&2
        echo "  Signing with a non-consumer key would make the release gate green while" >&2
        echo "  every bootstrap consumer fails against the embedded anchor." >&2
        failed=$((failed + 1))
        return 1
    fi
    _anchor_checked=1
    return 0
}

require_minisign_pub() {
    if [ -z "${SFETCH_MINISIGN_PUB}" ]; then
        echo "error: SFETCH_MINISIGN_PUB not set, cannot verify minisign signatures" >&2
        failed=$((failed + 1))
        return 1
    fi
    if [ ! -f "${SFETCH_MINISIGN_PUB}" ]; then
        echo "error: SFETCH_MINISIGN_PUB=${SFETCH_MINISIGN_PUB} not found" >&2
        failed=$((failed + 1))
        return 1
    fi
    assert_operator_pub_is_canonical_anchor || return 1
    return 0
}

# Optional: skip when signature file is absent (manifests only).
verify_minisign_optional() {
    local manifest="$1"
    local base="${DIR}/${manifest}"
    local sig="${base}.minisig"

    if [ ! -f "${sig}" ]; then
        echo "ℹ️  No minisign signature for ${manifest} (skipping)"
        return 0
    fi

    require_minisign_pub || return 1
    require_minisign_tool || return 1

    echo "🔍 [minisign] Verifying ${manifest}"
    if minisign -V -p "${SFETCH_MINISIGN_PUB}" -m "${base}"; then
        echo "✅ ${manifest}.minisig verified"
        verified=$((verified + 1))
    else
        echo "❌ ${manifest}.minisig verification FAILED"
        failed=$((failed + 1))
    fi
}

# Required: missing signature is a hard failure (installer only).
verify_minisign_required() {
    local target="$1"
    local base="${DIR}/${target}"
    local sig="${base}.minisig"

    if [ ! -f "${base}" ]; then
        echo "❌ required file missing: ${target}"
        failed=$((failed + 1))
        return 1
    fi

    if [ ! -f "${sig}" ]; then
        # POLICY: installer signature is required — no skip-on-missing.
        # (Manifests may still skip via verify_minisign_optional; do not merge.)
        echo "❌ required minisign signature missing: ${target}.minisig"
        echo "   Release is incomplete until the installer is signed (make release-sign)."
        failed=$((failed + 1))
        return 1
    fi

    require_minisign_pub || return 1
    require_minisign_tool || return 1

    echo "🔍 [minisign] Verifying ${target} (required)"
    if minisign -V -p "${SFETCH_MINISIGN_PUB}" -m "${base}"; then
        echo "✅ ${target}.minisig verified"
        verified=$((verified + 1))
    else
        echo "❌ ${target}.minisig verification FAILED"
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

# Required first so a missing installer signature fails before optional skips.
verify_minisign_required "install-sfetch.sh"

verify_minisign_optional "SHA256SUMS"
verify_minisign_optional "SHA512SUMS"

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
