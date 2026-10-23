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

WORK=""
GPG_HOMES=()
cleanup_anchor() {
    local h status=0
    local recorded=("${GPG_HOMES[@]+"${GPG_HOMES[@]}"}")
    if [ "${GPG_EXPECT_HOMES:-0}" = 1 ] && [ "${#recorded[@]}" -eq 0 ]; then
        echo "FAIL: parent GnuPG home registry empty after homes were created" >&2
        status=1
    fi
    for h in "${recorded[@]}"; do
        [ -n "$h" ] || continue
        gpgconf --homedir "$h" --kill all >/dev/null 2>&1 || true
        rm -rf "$h"
    done
    rm -f "$SRC_COPY"
    rm -rf "${WORK:-}"
    for h in "${recorded[@]}"; do
        [ -n "$h" ] || continue
        if [ -e "$h" ]; then
            echo "FAIL: GnuPG home still exists after cleanup: $h" >&2
            status=1
        fi
    done
    return "$status"
}
new_gpg_home() {
    local dest="${1:?new_gpg_home dest var}"
    local d
    d="$(mktemp -d /tmp/sfetch-gpg.XXXXXX)" || fail "mktemp GnuPG home"
    chmod 700 "$d" || fail "chmod GnuPG home"
    GPG_HOMES+=("$d")
    GPG_EXPECT_HOMES=1
    printf -v "$dest" '%s' "$d"
}
if grep -nE '\$\(new_gpg_home\)' "${BASH_SOURCE[0]}"; then
    fail "new_gpg_home must be called in the parent shell, not via command substitution"
fi
if grep -nE 'rm[[:space:]]+-rf[[:space:]]+["'\'']?/tmp/sfetch-gpg' "${BASH_SOURCE[0]}"; then
    fail "must not broadly remove /tmp/sfetch-gpg.*"
fi
gpg_run() {
    local log="${WORK:-/tmp}/gpg-fixture.err"
    if ! "$@" >"$log" 2>&1; then
        echo "FAIL: gpg fixture failed: $*" >&2
        cat "$log" >&2
        fail "gpg fixture"
    fi
}

INSTALLER="${ROOT}/scripts/install-sfetch.sh"
ENGINE="${ROOT}/scripts/bootstrap-sfetch-verified.sh"
ANCHOR="${ROOT}/docs/security/sfetch-minisign.pub"
RETIRED="${ROOT}/docs/security/sfetch-minisign-retired-1.pub"

[ -f "$INSTALLER" ] || fail "installer missing"
[ -f "$ENGINE" ] || fail "engine missing"
[ -f "$ANCHOR" ] || fail "anchor SSOT missing"
[ -f "$RETIRED" ] || fail "retired minisign pin missing"
# PDR-0008: binaries embed the committed file; no second copy beside it.
[ ! -e "${ROOT}/scripts/sfetch-minisign-anchor.pub" ] || fail "scripts/sfetch-minisign-anchor.pub must not exist (SSOT is docs/security/sfetch-minisign.pub)"
[ ! -e "${ROOT}/.github/keys/fulmenhq-goneat-minisign.pub" ] || fail ".github/keys must not hold third-party pins (docs/security/<org>-<tool>-minisign.pub)"

# Entry-call strip must match exactly one line; sourcing an unstripped copy
# would execute the installer.
[ "$(grep -c '^main "$@"$' "$INSTALLER")" -eq 1 ] || fail "installer entry line not exactly-once (refusing to source)"
SRC_COPY="$(mktemp "${TMPDIR:-/tmp}/sft-install-src.XXXXXX")"
trap cleanup_anchor EXIT
grep -q 'mktemp -d /tmp/sfetch-gpg.XXXXXX' "$INSTALLER" ||
    fail "installer GnuPG home must use mktemp -d /tmp/sfetch-gpg.XXXXXX"
grep -v '^main "$@"$' "$INSTALLER" >"$SRC_COPY"
grep -q '^main ' "$SRC_COPY" && fail "strip failed: main invocation remains"
# Ambient overrides must not leak into the coherence checks.
unset SFETCH_MINISIGN_PUBKEY SFETCH_PGP_FPR
# shellcheck source=scripts/install-sfetch.sh
# shellcheck disable=SC1090
. "$SRC_COPY"

command -v is_exact_semver_tag >/dev/null || fail "is_exact_semver_tag not loaded"
command -v semver_le_tag >/dev/null || fail "semver_le_tag not loaded"
command -v select_trust_anchor >/dev/null || fail "select_trust_anchor not loaded"
command -v verify_signature >/dev/null || fail "verify_signature not loaded"
command -v gpg_cleanup >/dev/null || fail "gpg_cleanup not loaded"

# --- shipped trust constants, pinned by value ---
# minisign key id = bytes 2..10 of the decoded key, little-endian.
minisign_key_id() {
    printf '%s' "$1" | base64 -d 2>/dev/null | od -An -tx1 -j2 -N8 |
        tr -d ' \n' | sed -E 's/(..)(..)(..)(..)(..)(..)(..)(..)/\8\7\6\5\4\3\2\1/' |
        tr '[:lower:]' '[:upper:]'
}
[ "$(minisign_key_id "$SFETCH_MINISIGN_PUBKEY")" = "6DC067B6CF9F51EA" ] || fail "current minisign key id"
[ "$(minisign_key_id "$SFETCH_MINISIGN_PUBKEY_LEGACY")" = "DE44B5D37442A1C0" ] || fail "legacy minisign key id"
# Full key material, not just the id (an id-preserving payload change must fail).
[ "$SFETCH_MINISIGN_PUBKEY" = "RWTqUZ/PtmfAbQ3RKIlp/YTKT6zFeNMAZ8iAMelhlmqEsVqjKj3ctSA1" ] || fail "current minisign key material"
[ "$SFETCH_MINISIGN_PUBKEY_LEGACY" = "RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC" ] || fail "legacy minisign key material"
[ "$SFETCH_PGP_FPR" = "0CACA49B3119B6BC12B2CA11B9B485F294B9FE07" ] || fail "current GPG fingerprint"
[ "$SFETCH_PGP_FPR_LEGACY" = "94BB7811D4AD49B2310E0C08FA0651DE91B828ED" ] || fail "legacy GPG fingerprint"
pass "shipped trust constants match pinned values"

# --- shipped selection: each tag selects exactly one generation ---
expect_selection() {
    local tag="$1" gen="$2" key="$3" fpr="$4"
    ACTIVE_MINISIGN_PUBKEY="" ACTIVE_PGP_FPR="" ANCHOR_GEN=""
    select_trust_anchor "$tag" 2>/dev/null
    [ "$ANCHOR_GEN" = "$gen" ] || fail "$tag: expected $gen, got ${ANCHOR_GEN:-<none>}"
    [ "$ACTIVE_MINISIGN_PUBKEY" = "$key" ] || fail "$tag: wrong minisign anchor for $gen"
    [ "$ACTIVE_PGP_FPR" = "$fpr" ] || fail "$tag: wrong GPG pin for $gen"
}
for tag in v0.4.0 v0.4.6 v0.4.10 v0.4.11; do
    expect_selection "$tag" legacy "$SFETCH_MINISIGN_PUBKEY_LEGACY" "$SFETCH_PGP_FPR_LEGACY"
done
for tag in v0.4.12 v0.4.14 v0.4.15 v1.0.0; do
    expect_selection "$tag" current "$SFETCH_MINISIGN_PUBKEY" "$SFETCH_PGP_FPR"
done
for tag in "" latest v0.4.09 v0.4.15-rc1 0.4.15; do
    if (select_trust_anchor "$tag") >/dev/null 2>&1; then fail "non-semver tag '$tag' must be refused"; fi
done
pass "select_trust_anchor picks one generation per tag; refuses non-semver"

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
[[ "${SFETCH_PGP_FPR_LEGACY:-}" =~ ^[0-9A-F]{40}$ ]] || fail "legacy GPG pin shape (got: ${SFETCH_PGP_FPR_LEGACY:-})"
[[ "${SFETCH_PGP_FPR:-}" =~ ^[0-9A-F]{40}$ ]] || fail "current GPG pin shape (got: ${SFETCH_PGP_FPR:-})"
pass "installer/engine legacy constants coherent"

# SSOT carries the current key only (legacy anchor is pin-scoped, never default).
ANCHOR_RW="$(grep -E '^RW' "$ANCHOR" | head -n1 | tr -d '\r\n')"
[ -n "$ANCHOR_RW" ] || fail "anchor has no RW line"
[ "$ANCHOR_RW" = "${SFETCH_MINISIGN_PUBKEY:-}" ] || fail "installer current anchor must equal SSOT"
if grep -q "${SFETCH_MINISIGN_PUBKEY_LEGACY}" "$ANCHOR"; then fail "SSOT must not carry the legacy anchor"; fi
RETIRED_RW="$(grep -E '^RW' "$RETIRED" | head -n1 | tr -d '\r\n')"
[ "$RETIRED_RW" = "${SFETCH_MINISIGN_PUBKEY_LEGACY:-}" ] || fail "retired pin must equal installer legacy literal"
grep -q 'last tag v0.4.11' "$RETIRED" || fail "retired pin must record last signed tag v0.4.11"
pass "SSOT stays single-current; retired pin labelled"

# --- shipped selection through shipped verification (hermetic, throwaway keys) ---
# Stand-in keys replace the anchors so real signatures can be produced locally;
# selection and verify_signature run unmodified.
if command -v minisign >/dev/null 2>&1; then
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/sft-anchor.XXXXXX")"
    minisign -G -W -p "$WORK/cur.pub" -s "$WORK/cur.key" >/dev/null 2>&1 || fail "keygen current"
    minisign -G -W -p "$WORK/old.pub" -s "$WORK/old.key" >/dev/null 2>&1 || fail "keygen legacy"
    SFETCH_MINISIGN_PUBKEY="$(sed -n 2p "$WORK/cur.pub")"
    SFETCH_MINISIGN_PUBKEY_LEGACY="$(sed -n 2p "$WORK/old.pub")"
    printf 'abc  sfetch_linux_amd64.tar.gz\n' >"$WORK/SHA256SUMS"
    VERIFY_MINISIGN=true VERIFY_GPG=false REQUIRE_MINISIGN=true REQUIRE_SIGNATURE=true

    # verify_as TAG SIGNER: 0 if the shipped path accepts SIGNER's signature for TAG.
    verify_as() {
        local tag="$1" signer="$2" d
        d="$(mktemp -d "$WORK/v.XXXXXX")"
        cp "$WORK/SHA256SUMS" "$d/SHA256SUMS"
        minisign -S -s "$WORK/${signer}.key" -m "$d/SHA256SUMS" -x "$d/SHA256SUMS.minisig" >/dev/null 2>&1 ||
            fail "sign as $signer"
        (
            select_trust_anchor "$tag"
            verify_signature "$d/SHA256SUMS" "$d"
        ) >/dev/null 2>&1
    }
    verify_as v0.4.11 old || fail "v0.4.11 must verify under the legacy key"
    verify_as v0.4.12 cur || fail "v0.4.12 must verify under the current key"
    if verify_as v0.4.11 cur; then fail "v0.4.11 must reject a current-key signature (no fallback)"; fi
    if verify_as v0.4.12 old; then fail "v0.4.12 must reject a legacy-key signature (no fallback)"; fi
    pass "selection through verify_signature: each generation accepts only its own key"

    # GPG route (minisign not required): the fingerprint pin follows the tag.
    if command -v gpg >/dev/null 2>&1; then
        new_gpg_home GH
        [ "${#GPG_HOMES[@]}" -ge 1 ] || fail "parent GnuPG home registry empty after new_gpg_home"
        gpg_gen() {
            gpg_run gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' \
                --quick-gen-key "$1" ed25519 sign never
            gpg --homedir "$GH" --with-colons --fingerprint "$1" | awk -F: '/^fpr:/ {print $10; exit}'
        }
        FPR_CUR="$(gpg_gen 'cur@test.invalid')"
        FPR_OLD="$(gpg_gen 'old@test.invalid')"
        SFETCH_PGP_FPR="$FPR_CUR"
        SFETCH_PGP_FPR_LEGACY="$FPR_OLD"
        # gpg_verify_as TAG SIGNER [MINISIG_SIGNER]: GPG-signed sums; optional
        # minisig from MINISIG_SIGNER exercises the minisign-reject path first.
        gpg_verify_as() {
            local tag="$1" signer="$2" msigner="${3:-}" d
            d="$(mktemp -d "$WORK/g.XXXXXX")"
            cp "$WORK/SHA256SUMS" "$d/SHA256SUMS"
            gpg --homedir "$GH" --batch --armor --export "${signer}@test.invalid" \
                >"$d/sfetch-release-signing-key.asc"
            gpg --homedir "$GH" --batch --yes --pinentry-mode loopback --passphrase '' \
                -u "${signer}@test.invalid" --armor --detach-sign -o "$d/SHA256SUMS.asc" "$d/SHA256SUMS" ||
                fail "gpg sign as $signer"
            if [ -n "$msigner" ]; then
                minisign -S -s "$WORK/${msigner}.key" -m "$d/SHA256SUMS" -x "$d/SHA256SUMS.minisig" >/dev/null 2>&1 ||
                    fail "minisign as $msigner"
            fi
            (
                VERIFY_GPG=true REQUIRE_MINISIGN=false
                select_trust_anchor "$tag"
                verify_signature "$d/SHA256SUMS" "$d"
            ) >/dev/null 2>&1
        }
        VERIFY_MINISIGN=false
        gpg_verify_as v0.4.11 old || fail "v0.4.11 must verify under the legacy GPG pin"
        gpg_verify_as v0.4.12 cur || fail "v0.4.12 must verify under the current GPG pin"
        if gpg_verify_as v0.4.11 cur; then fail "v0.4.11 must reject the current GPG key"; fi
        if gpg_verify_as v0.4.12 old; then fail "v0.4.12 must reject the legacy GPG key"; fi
        # Bundled key files: the pinned key plus any extra primary key is refused,
        # whichever key signed and whatever order the keys appear in.
        FPR_ATK="$(gpg_gen 'atk@test.invalid')"
        [ -n "$FPR_ATK" ] || fail "attacker key"
        gpg_bundle_as() {
            local tag="$1" signer="$2" d
            shift 2
            d="$(mktemp -d "$WORK/b.XXXXXX")"
            cp "$WORK/SHA256SUMS" "$d/SHA256SUMS"
            local k
            for k in "$@"; do
                gpg --homedir "$GH" --batch --armor --export "${k}@test.invalid" \
                    >>"$d/sfetch-release-signing-key.asc"
            done
            gpg --homedir "$GH" --batch --yes --pinentry-mode loopback --passphrase '' \
                -u "${signer}@test.invalid" --armor --detach-sign -o "$d/SHA256SUMS.asc" "$d/SHA256SUMS" ||
                fail "gpg sign as $signer"
            (
                VERIFY_GPG=true REQUIRE_MINISIGN=false
                select_trust_anchor "$tag"
                verify_signature "$d/SHA256SUMS" "$d"
            ) >/dev/null 2>&1
        }
        if gpg_bundle_as v0.4.12 atk cur atk; then fail "v0.4.12: appended attacker key must be refused"; fi
        if gpg_bundle_as v0.4.12 atk atk cur; then fail "v0.4.12: prepended attacker key must be refused"; fi
        if gpg_bundle_as v0.4.12 old cur old; then fail "v0.4.12: bundled legacy key must be refused"; fi
        if gpg_bundle_as v0.4.11 atk old atk; then fail "v0.4.11: appended attacker key must be refused"; fi
        if gpg_bundle_as v0.4.11 cur old cur; then fail "v0.4.11: bundled current key must be refused"; fi
        if gpg_bundle_as v0.4.12 cur cur atk; then fail "v0.4.12: bundle refused even when the pinned key signed"; fi
        gpg_bundle_as v0.4.12 cur cur || fail "v0.4.12: single pinned key must verify"
        # Release keys sign with a subkey: VALIDSIG's primary field must still match.
        gpg_run gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' \
            --quick-add-key "$FPR_CUR" ed25519 sign never
        SUB_CUR="$(gpg --homedir "$GH" --with-colons --list-keys "$FPR_CUR" |
            awk -F: '$1 == "sub" { s = 1; next } s && $1 == "fpr" { f = $10 } END { print f }')"
        [ -n "$SUB_CUR" ] && [ "$SUB_CUR" != "$FPR_CUR" ] || fail "signing subkey"
        d_sub="$(mktemp -d "$WORK/s.XXXXXX")"
        cp "$WORK/SHA256SUMS" "$d_sub/SHA256SUMS"
        gpg --homedir "$GH" --batch --armor --export "$FPR_CUR" >"$d_sub/sfetch-release-signing-key.asc"
        gpg --homedir "$GH" --batch --yes --pinentry-mode loopback --passphrase '' \
            -u "${SUB_CUR}!" --armor --detach-sign -o "$d_sub/SHA256SUMS.asc" "$d_sub/SHA256SUMS" ||
            fail "subkey sign"
        (
            VERIFY_GPG=true REQUIRE_MINISIGN=false
            select_trust_anchor v0.4.12
            verify_signature "$d_sub/SHA256SUMS" "$d_sub"
        ) >/dev/null 2>&1 || fail "v0.4.12: subkey signature under the pinned primary must verify"
        # Two concatenated valid signatures must be refused (exactly one VALIDSIG).
        d_two="$(mktemp -d "$WORK/two.XXXXXX")"
        cp "$d_sub/SHA256SUMS" "$d_two/SHA256SUMS"
        cp "$d_sub/sfetch-release-signing-key.asc" "$d_two/sfetch-release-signing-key.asc"
        cat "$d_sub/SHA256SUMS.asc" "$d_sub/SHA256SUMS.asc" >"$d_two/SHA256SUMS.asc"
        if (
            VERIFY_GPG=true REQUIRE_MINISIGN=false
            select_trust_anchor v0.4.12
            verify_signature "$d_two/SHA256SUMS" "$d_two"
        ) >/dev/null 2>&1; then
            fail "v0.4.12: concatenated valid signatures must be refused"
        fi
        pass "exactly one VALIDSIG required"
        # A single-key file whose signature comes from another key is refused.
        if gpg_bundle_as v0.4.12 atk cur; then fail "v0.4.12: signature from an unlisted key must be refused"; fi
        # Secret-key packets: a bundle carrying any secret primary is refused,
        # with either signer, either order, either generation.
        gpg_secret_bundle_as() {
            local tag="$1" signer="$2" pub="$3" sec="$4" order="$5" d
            d="$(mktemp -d "$WORK/k.XXXXXX")"
            cp "$WORK/SHA256SUMS" "$d/SHA256SUMS"
            local f="$d/sfetch-release-signing-key.asc"
            if [ "$order" = append ]; then
                gpg --homedir "$GH" --batch --armor --export "${pub}@test.invalid" >>"$f"
            fi
            gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' --armor \
                --export-secret-keys "${sec}@test.invalid" >>"$f" || fail "export secret $sec"
            if [ "$order" = prepend ]; then
                gpg --homedir "$GH" --batch --armor --export "${pub}@test.invalid" >>"$f"
            fi
            gpg --homedir "$GH" --batch --yes --pinentry-mode loopback --passphrase '' \
                -u "${signer}@test.invalid" --armor --detach-sign -o "$d/SHA256SUMS.asc" "$d/SHA256SUMS" ||
                fail "gpg sign as $signer"
            (
                VERIFY_GPG=true REQUIRE_MINISIGN=false
                select_trust_anchor "$tag"
                verify_signature "$d/SHA256SUMS" "$d"
            ) >/dev/null 2>&1
        }
        for order in append prepend; do
            for signer in atk cur; do
                if gpg_secret_bundle_as v0.4.12 "$signer" cur atk "$order"; then
                    fail "v0.4.12: secret-key bundle ($order, signer $signer) must be refused"
                fi
            done
            for signer in atk old; do
                if gpg_secret_bundle_as v0.4.11 "$signer" old atk "$order"; then
                    fail "v0.4.11: secret-key bundle ($order, signer $signer) must be refused"
                fi
            done
            if gpg_secret_bundle_as v0.4.12 cur cur old "$order"; then
                fail "v0.4.12: bundle with legacy secret key ($order) must be refused"
            fi
        done
        pass "gpg route: key files must hold exactly the pinned primary key"
        # A key file holding only the pinned primary as a secret key is refused
        # too, including a large listing (many user ids) that would SIGPIPE an
        # early-exiting reader.
        gpg_single_secret_as() {
            local tag="$1" who="$2" d
            d="$(mktemp -d "$WORK/x.XXXXXX")"
            cp "$WORK/SHA256SUMS" "$d/SHA256SUMS"
            gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' --armor \
                --export-secret-keys "${who}@test.invalid" >"$d/sfetch-release-signing-key.asc" ||
                fail "export secret $who"
            gpg --homedir "$GH" --batch --yes --pinentry-mode loopback --passphrase '' \
                -u "${who}@test.invalid" --armor --detach-sign -o "$d/SHA256SUMS.asc" "$d/SHA256SUMS" ||
                fail "gpg sign as $who"
            (
                VERIFY_GPG=true REQUIRE_MINISIGN=false
                select_trust_anchor "$tag"
                verify_signature "$d/SHA256SUMS" "$d"
            ) >/dev/null 2>&1
        }
        if gpg_single_secret_as v0.4.12 cur; then fail "v0.4.12: pinned key as secret key must be refused"; fi
        if gpg_single_secret_as v0.4.11 old; then fail "v0.4.11: pinned key as secret key must be refused"; fi
        pad="$(printf 'p%.0s' $(seq 1 1500))"
        for i in $(seq 1 100); do
            for k in "$FPR_CUR" "$FPR_OLD"; do
                gpg_run gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' \
                    --quick-add-uid "$k" "${i}${pad} <pad${i}@test.invalid>"
            done
        done
        new_gpg_home PROBE_HOME
        big="$(gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' --armor \
            --export-secret-keys "$FPR_CUR" | gpg --homedir "$PROBE_HOME" --batch --with-colons \
            --import-options show-only --import 2>/dev/null | wc -c)" || true
        [ "${big:-0}" -gt 131072 ] || fail "padded secret listing too small to exercise SIGPIPE (${big:-0} bytes)"
        if gpg_single_secret_as v0.4.12 cur; then fail "v0.4.12: large pinned secret listing must be refused"; fi
        if gpg_single_secret_as v0.4.11 old; then fail "v0.4.11: large pinned secret listing must be refused"; fi
        pass "gpg route: secret-key packets refused"

        # Production errexit semantics and the production EXIT trap (as main
        # sets it): unreadable key files fail closed and every GnuPG home the
        # installer passed to gpg is removed, wherever it was created.
        for kind in empty garbage; do
            d="$(mktemp -d "$WORK/e.XXXXXX")"
            cp "$WORK/SHA256SUMS" "$d/SHA256SUMS"
            : >"$d/SHA256SUMS.asc"
            case "$kind" in
                empty) : >"$d/sfetch-release-signing-key.asc" ;;
                garbage) printf 'not a key\n' >"$d/sfetch-release-signing-key.asc" ;;
            esac
            # PATH shim: record each --homedir passed to gpg, then run real gpg.
            shim="$(mktemp -d "$WORK/shim.XXXXXX")"
            homes_log="$shim/homes.log"
            : >"$homes_log"
            real_gpg="$(command -v gpg)"
            cat >"$shim/gpg" <<SHIM
#!/usr/bin/env bash
prev=""
for a in "\$@"; do
    [ "\$prev" = "--homedir" ] && printf '%s\\n' "\$a" >>"$homes_log"
    prev="\$a"
done
exec "$real_gpg" "\$@"
SHIM
            chmod +x "$shim/gpg"
            set +e
            PATH="$shim:$PATH" bash -c 'set -euo pipefail
                . "$1"
                tmpdir="$2"
                trap '"'"'gpg_cleanup; rm -rf "$tmpdir"'"'"' EXIT
                VERIFY_MINISIGN=false VERIFY_GPG=true REQUIRE_MINISIGN=false REQUIRE_SIGNATURE=true
                SFETCH_PGP_FPR="$3"
                select_trust_anchor v0.4.12
                verify_signature "$tmpdir/SHA256SUMS" "$tmpdir"' _ "$SRC_COPY" "$d" "$FPR_CUR" >/dev/null 2>&1
            rc=$?
            set -e
            [ "$rc" -ne 0 ] || fail "$kind key file must fail closed"
            [ ! -e "$d" ] || fail "$kind key file left tmpdir behind"
            # Every --homedir the installer handed to gpg must be gone.
            while IFS= read -r h; do
                [ -z "$h" ] || [ ! -e "$h" ] || fail "$kind key file leaked a GnuPG home: $h"
            done <"$homes_log"
            [ -s "$homes_log" ] || fail "$kind: gpg shim saw no --homedir (harness not exercising gpg)"
        done
        pass "gpg route: unreadable key files fail closed with cleanup"

        # A rejected minisign signature must not fall through to a valid GPG one.
        VERIFY_MINISIGN=true
        if gpg_verify_as v0.4.12 cur old; then fail "minisign reject must not fall back to gpg"; fi
        gpg_verify_as v0.4.12 cur cur || fail "v0.4.12 with valid minisign + gpg must verify"
        VERIFY_MINISIGN=true
        # Expired pinned keys must not verify even under --trust-model always.
        # Sign first, then expire, then wait: setting seconds=1 *after* the
        # wait re-validates the key and the installer would correctly accept it.
        new_gpg_home EXP_HOME
        gpg_run gpg --homedir "$EXP_HOME" --batch --pinentry-mode loopback --passphrase '' \
            --quick-gen-key 'exp@test.invalid' ed25519 sign never
        FPR_EXP="$(gpg --homedir "$EXP_HOME" --with-colons --fingerprint exp@test.invalid |
            awk -F: '/^fpr:/ {print $10; exit}')"
        [ -n "$FPR_EXP" ] || fail "expired-key fingerprint"
        d_exp="$(mktemp -d "$WORK/exp.XXXXXX")"
        cp "$WORK/SHA256SUMS" "$d_exp/SHA256SUMS"
        gpg_run gpg --homedir "$EXP_HOME" --batch --yes --pinentry-mode loopback --passphrase '' \
            -u exp@test.invalid --armor --detach-sign -o "$d_exp/SHA256SUMS.asc" "$d_exp/SHA256SUMS"
        gpg_run gpg --homedir "$EXP_HOME" --batch --yes --pinentry-mode loopback --passphrase '' \
            --quick-set-expire "$FPR_EXP" seconds=1
        sleep 2
        gpg --homedir "$EXP_HOME" --batch --armor --export exp@test.invalid \
            >"$d_exp/sfetch-release-signing-key.asc"
        new_gpg_home EXP_PROBE
        gpg_run gpg --homedir "$EXP_PROBE" --batch --import "$d_exp/sfetch-release-signing-key.asc"
        set +e
        probe_status=$(gpg --homedir "$EXP_PROBE" --batch --no-tty --trust-model always \
            --status-fd 1 --verify "$d_exp/SHA256SUMS.asc" "$d_exp/SHA256SUMS" 2>"$WORK/gpg-exp-verify.err")
        exp_rc=$?
        set -e
        if ! printf '%s\n' "$probe_status" | grep -q EXPKEYSIG; then
            echo "FAIL: fixture must emit EXPKEYSIG (gpg rc=$exp_rc)" >&2
            cat "$WORK/gpg-exp-verify.err" >&2
            printf '%s\n' "$probe_status" >&2
            fail "fixture must emit EXPKEYSIG"
        fi
        if (
            VERIFY_MINISIGN=false VERIFY_GPG=true REQUIRE_MINISIGN=false REQUIRE_SIGNATURE=true
            SFETCH_PGP_FPR="$FPR_EXP"
            select_trust_anchor v0.4.12
            verify_signature "$d_exp/SHA256SUMS" "$d_exp"
        ) >/dev/null 2>&1; then
            fail "expired pinned GPG key must be refused"
        fi
        grep -q EXPKEYSIG "$INSTALLER" || fail "installer must reject EXPKEYSIG"
        grep -q KEYEXPIRED "$INSTALLER" || fail "installer must reject KEYEXPIRED"
        pass "gpg route: expired pinned key refused"

        pass "gpg route: fingerprint pin follows the tag; minisign reject does not fall back"
    else
        [ "${CI:-}" != "true" ] || fail "gpg required in CI for the gpg half"
        echo "SKIP: gpg not installed; gpg half not run"
    fi
else
    [ "${CI:-}" != "true" ] || fail "minisign required in CI for the verification half"
    echo "SKIP: minisign not installed; verification half not run"
fi

echo "[ok] install anchor-select regression harness complete"
