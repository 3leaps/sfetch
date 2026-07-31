#!/usr/bin/env bash
# assert-bootstrap-range-release.sh — release-gate coherence for bootstrap constants.
#
# Compares two *committed* values visible at the same SHA:
#   VERSION file  vs  SFETCH_BOOTSTRAP_MAX in scripts/bootstrap-sfetch-verified.sh
# Also sanity-checks SFETCH_MINISIG_SINCE against the committed range.
#
# WHY THIS IS NOT IN THE ENGINE AT RUNTIME
# ----------------------------------------
# Do not "simplify" by reading VERSION (or any consumer-tree file) inside
# bootstrap-sfetch-verified.sh during install. The action SHA must declare a
# *frozen* supported range; a runtime-derived ceiling floats the contract and
# reintroduces a workspace trust seam (engine must not depend on GITHUB_WORKSPACE
# or consumer checkout contents for verification policy).
#
# This assert belongs in sfetch's release/CI gate so a *missing* MAX bump fails
# here, not first in a consumer repo that tried sfetch-version: vN+1.
#
# Usage: assert-bootstrap-range-release.sh
# Exit 0 if coherent; non-zero otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ENGINE="${ROOT}/scripts/bootstrap-sfetch-verified.sh"
VERSION_FILE="${ROOT}/VERSION"

fail() {
    echo "error: $*" >&2
    exit 1
}

[ -f "$VERSION_FILE" ] || fail "VERSION file missing"
[ -f "$ENGINE" ] || fail "engine missing: $ENGINE"

VER="$(tr -d '[:space:]' <"$VERSION_FILE")"
case "$VER" in
    [0-9]*.[0-9]*.[0-9]*)
        if ! [[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            fail "VERSION must be exact MAJOR.MINOR.PATCH (got: $VER)"
        fi
        ;;
    *)
        fail "VERSION must be exact MAJOR.MINOR.PATCH (got: $VER)"
        ;;
esac
TAG="v${VER}"

# Extract committed constants from the engine (readonly assignments).
extract_const() {
    local name="$1"
    local line
    line="$(grep -E "^readonly ${name}=" "$ENGINE" | head -n1 || true)"
    [ -n "$line" ] || fail "engine constant ${name} not found"
    # readonly NAME="value"
    local val="${line#*=}"
    val="${val#\"}"
    val="${val%\"}"
    val="${val#\'}"
    val="${val%\'}"
    printf '%s\n' "$val"
}

MAX="$(extract_const SFETCH_BOOTSTRAP_MAX)"
MIN="$(extract_const SFETCH_BOOTSTRAP_MIN)"
SINCE="$(extract_const SFETCH_MINISIG_SINCE)"

echo "bootstrap-range assert: VERSION=${VER} MAX=${MAX} MIN=${MIN} MINISIG_SINCE=${SINCE}"

[ "$MAX" = "$TAG" ] ||
    fail "SFETCH_BOOTSTRAP_MAX (${MAX}) must equal v\$(cat VERSION) (${TAG}). Advance the constant (and boundary tests) before cutting this release — see RELEASE_CHECKLIST.md §1."

# MINISIG_SINCE: route-selection constant. Wrong value is not a crypto hole but
# mis-routes consumers (5-step vs 3-step). Must be an exact tag within [MIN, MAX].
case "$SINCE" in
    v[0-9]*.[0-9]*.[0-9]*)
        if ! [[ "${SINCE#v}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            fail "SFETCH_MINISIG_SINCE must be exact vMAJOR.MINOR.PATCH (got: $SINCE)"
        fi
        ;;
    *)
        fail "SFETCH_MINISIG_SINCE must be exact vMAJOR.MINOR.PATCH (got: $SINCE)"
        ;;
esac

# Lightweight ordering using the engine's own helpers without installing.
# shellcheck source=scripts/bootstrap-sfetch-verified.sh
# We only need is_exact / semver helpers — source is heavy; inline minimal cmp.
semver_cmp_tag() {
    # echo -1/0/1 for a vs b (vX.Y.Z)
    local a="${1#v}" b="${2#v}"
    local a1 a2 a3 b1 b2 b3
    IFS=. read -r a1 a2 a3 <<<"$a"
    IFS=. read -r b1 b2 b3 <<<"$b"
    # Use pure string length+lex for decimal components (same class as engine;
    # components here are small committed constants, not untrusted input).
    _cmp_one() {
        local x="$1" y="$2"
        local lx=${#x} ly=${#y}
        if [ "$lx" -lt "$ly" ]; then
            echo -1
            return
        fi
        if [ "$lx" -gt "$ly" ]; then
            echo 1
            return
        fi
        if [[ "$x" < "$y" ]]; then
            echo -1
            return
        fi
        if [[ "$x" > "$y" ]]; then
            echo 1
            return
        fi
        echo 0
    }
    local c
    c="$(_cmp_one "$a1" "$b1")"
    [ "$c" != 0 ] && {
        echo "$c"
        return
    }
    c="$(_cmp_one "$a2" "$b2")"
    [ "$c" != 0 ] && {
        echo "$c"
        return
    }
    _cmp_one "$a3" "$b3"
}

[ "$(semver_cmp_tag "$SINCE" "$MIN")" != "-1" ] ||
    fail "SFETCH_MINISIG_SINCE (${SINCE}) is below SFETCH_BOOTSTRAP_MIN (${MIN})"
[ "$(semver_cmp_tag "$SINCE" "$MAX")" != "1" ] ||
    fail "SFETCH_MINISIG_SINCE (${SINCE}) is above SFETCH_BOOTSTRAP_MAX (${MAX})"
[ "$(semver_cmp_tag "$MIN" "$MAX")" != "1" ] ||
    fail "SFETCH_BOOTSTRAP_MIN (${MIN}) is above SFETCH_BOOTSTRAP_MAX (${MAX})"

echo "[ok] bootstrap range coherent: MAX=${MAX} == VERSION tag; MINISIG_SINCE=${SINCE} in [${MIN}..${MAX}]"
