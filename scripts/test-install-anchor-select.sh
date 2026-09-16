#!/usr/bin/env bash
# Unit/coherence tests for install-sfetch.sh pin-map anchor selection.
# Sources installer functions from a temp copy with the `main "$@"` entry call
# stripped (same bytes as shipped; the bootstrap harness sources engine
# functions the same way). Never executes the installer. No network.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

INSTALLER="${ROOT}/scripts/install-sfetch.sh"
ENGINE="${ROOT}/scripts/bootstrap-sfetch-verified.sh"
ANCHOR="${ROOT}/scripts/sfetch-minisign-anchor.pub"

[ -f "$INSTALLER" ] || fail "installer missing"
[ -f "$ENGINE" ] || fail "engine missing"
[ -f "$ANCHOR" ] || fail "anchor SSOT missing"

# Entry-call strip must match exactly one line; sourcing an unstripped copy
# would execute the installer.
[ "$(grep -c '^main "$@"$' "$INSTALLER")" -eq 1 ] || fail "installer entry line not exactly-once (refusing to source)"
SRC_COPY="$(mktemp "${TMPDIR:-/tmp}/sft-install-src.XXXXXX")"
trap 'rm -f "$SRC_COPY"' EXIT
grep -v '^main "$@"$' "$INSTALLER" >"$SRC_COPY"
grep -q '^main ' "$SRC_COPY" && fail "strip failed: main invocation remains"
# shellcheck source=scripts/install-sfetch.sh
# shellcheck disable=SC1090
. "$SRC_COPY"

command -v is_exact_semver_tag >/dev/null || fail "is_exact_semver_tag not loaded"
command -v semver_le_tag >/dev/null || fail "semver_le_tag not loaded"

# --- tag shape: strict vMAJOR.MINOR.PATCH, no leading zeros ---
is_exact_semver_tag "v0.4.11" || fail "accept v0.4.11"
is_exact_semver_tag "v0.4.6" || fail "accept v0.4.6"
is_exact_semver_tag "v0.0.0" || fail "accept v0.0.0"
is_exact_semver_tag "v10.20.30" || fail "accept multi-digit"
if is_exact_semver_tag ""; then fail "reject empty"; fi
if is_exact_semver_tag "latest"; then fail "reject latest"; fi
if is_exact_semver_tag "v0.4.09"; then fail "reject leading zero v0.4.09"; fi
if is_exact_semver_tag "v0.4"; then fail "reject short v0.4"; fi
if is_exact_semver_tag "v1.2.3.4"; then fail "reject long v1.2.3.4"; fi
if is_exact_semver_tag "1.2.3"; then fail "reject missing v"; fi
if is_exact_semver_tag "v1.2.x"; then fail "reject non-numeric"; fi
pass "installer tag shape strict"

# --- comparison boundaries against the v0.4.11 cutoff ---
semver_le_tag "v0.4.11" "v0.4.11" || fail "v0.4.11 <= cutoff"
semver_le_tag "v0.4.10" "v0.4.11" || fail "v0.4.10 <= cutoff"
semver_le_tag "v0.4.9" "v0.4.11" || fail "v0.4.9 <= cutoff"
semver_le_tag "v0.4.6" "v0.4.11" || fail "v0.4.6 <= cutoff (Intel recovery pin)"
semver_le_tag "v0.4.0" "v0.4.11" || fail "v0.4.0 <= cutoff"
semver_le_tag "v0.3.99" "v0.4.11" || fail "v0.3.99 <= cutoff"
if semver_le_tag "v0.4.12" "v0.4.11"; then fail "v0.4.12 above cutoff"; fi
if semver_le_tag "v0.4.100" "v0.4.11"; then fail "v0.4.100 above cutoff"; fi
if semver_le_tag "v0.5.0" "v0.4.11"; then fail "v0.5.0 above cutoff"; fi
if semver_le_tag "v1.0.0" "v0.4.11"; then fail "v1.0.0 above cutoff"; fi
if semver_le_tag "v10.0.0" "v0.4.11"; then fail "v10.0.0 above cutoff"; fi
# Huge components must not wrap into range (length-then-lexical, no arithmetic).
if semver_le_tag "v18446744073709551616.4.10" "v0.4.11"; then fail "huge major must not alias below cutoff"; fi
if semver_le_tag "v0.4.18446744073709551615" "v0.4.11"; then fail "huge patch must not alias below cutoff"; fi
if semver_le_tag "v0.18446744073709551616.0" "v0.4.11"; then fail "huge minor must not alias below cutoff"; fi
pass "installer pin-map comparison boundaries"

# --- constants coherence across consumers ---
[ "${SFETCH_PREVKEY_MAX:-}" = "v0.4.11" ] || fail "installer PREVKEY cutoff must be v0.4.11"
ENG_PREVKEY="$(grep -E '^readonly SFETCH_PREVKEY_MAX=' "$ENGINE" | head -n1 | sed 's/^readonly SFETCH_PREVKEY_MAX="//; s/"$//')"
[ -n "$ENG_PREVKEY" ] || fail "engine PREVKEY cutoff missing"
[ "$ENG_PREVKEY" = "$SFETCH_PREVKEY_MAX" ] || fail "installer/engine PREVKEY cutoff drift ($SFETCH_PREVKEY_MAX vs $ENG_PREVKEY)"
ENG_LEGACY="$(grep -E '^readonly SFETCH_MINISIGN_PUBKEY_LEGACY=' "$ENGINE" | head -n1 | sed 's/^readonly SFETCH_MINISIGN_PUBKEY_LEGACY="//; s/"$//')"
[ -n "$ENG_LEGACY" ] || fail "engine legacy anchor missing"
[ "$ENG_LEGACY" = "${SFETCH_MINISIGN_PUBKEY_LEGACY:-}" ] || fail "installer/engine legacy anchor drift"
[ "${SFETCH_MINISIGN_PUBKEY_LEGACY:-}" != "${SFETCH_MINISIGN_PUBKEY:-}" ] || fail "legacy and current minisign anchors must differ"
[ "${SFETCH_PGP_FPR_LEGACY:-}" != "${SFETCH_PGP_FPR:-}" ] || fail "legacy and current GPG pins must differ"
case "${SFETCH_PGP_FPR_LEGACY:-}" in
    "") fail "legacy GPG pin missing" ;;
esac
[[ "${SFETCH_PGP_FPR_LEGACY}" =~ ^[0-9A-F]{40}$ ]] || fail "legacy GPG pin shape (got: ${SFETCH_PGP_FPR_LEGACY})"
[[ "${SFETCH_PGP_FPR:-}" =~ ^[0-9A-F]{40}$ ]] || fail "current GPG pin shape (got: ${SFETCH_PGP_FPR:-})"
pass "installer/engine legacy constants coherent"

# SSOT carries the current key only (legacy anchor is pin-scoped, never default).
ANCHOR_RW="$(grep -E '^RW' "$ANCHOR" | head -n1 | tr -d '\r\n')"
[ -n "$ANCHOR_RW" ] || fail "anchor has no RW line"
[ "$ANCHOR_RW" = "${SFETCH_MINISIGN_PUBKEY:-}" ] || fail "installer current anchor must equal SSOT"
if grep -q "${SFETCH_MINISIGN_PUBKEY_LEGACY}" "$ANCHOR"; then fail "SSOT must not carry the legacy anchor"; fi
pass "SSOT stays single-current"

echo "[ok] install anchor-select regression harness complete"
