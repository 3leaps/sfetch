#!/usr/bin/env bash
# Regression harness for release signature verification (installer required).
# Uses ephemeral minisign keys — no production secrets.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

command -v minisign >/dev/null 2>&1 || fail "minisign required for this harness"

WORKDIR=""
trap 'rm -rf "${WORKDIR:-}" 2>/dev/null || true' EXIT
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/sft-sig-test.XXXXXX")"

KEY="${WORKDIR}/test.key"
PUB="${WORKDIR}/test.pub"
# Non-interactive keygen (empty password via -W / force)
# minisign -G -W generates unencrypted secret key (for CI fixtures only)
minisign -G -W -p "$PUB" -s "$KEY" >/dev/null 2>&1 ||
    minisign -G -n -p "$PUB" -s "$KEY" >/dev/null 2>&1 ||
    fail "minisign keygen failed"

# --- Fixture: signed manifests + installer ---
STAGE="${WORKDIR}/stage"
mkdir -p "$STAGE"
printf 'payload\n' >"$STAGE/a.bin"
printf '#!/bin/sh\necho installer\n' >"$STAGE/install-sfetch.sh"
(
    cd "$STAGE"
    shasum -a 256 a.bin install-sfetch.sh >SHA256SUMS
    shasum -a 512 a.bin install-sfetch.sh >SHA512SUMS
)

# Sign with mocked env (sign-release-manifests.sh)
export SFETCH_MINISIGN_KEY="$KEY"
export SFETCH_MINISIGN_PUB="$PUB"
# Provide password-free path: rewrite sign to use -W keys; minisign -S without password for -W keys
minisign -S -s "$KEY" -t "test" -m "$STAGE/SHA256SUMS"
minisign -S -s "$KEY" -t "test" -m "$STAGE/SHA512SUMS"
minisign -S -s "$KEY" -t "test" -m "$STAGE/install-sfetch.sh"

# Case 1: full set verifies
if SFETCH_MINISIGN_PUB="$PUB" ./scripts/verify-signatures.sh "$STAGE"; then
    pass "full fixture verifies"
else
    fail "full fixture should verify"
fi

# Case 2: missing installer minisig ⇒ non-zero (required)
NO_INST="${WORKDIR}/no-inst"
cp -R "$STAGE/." "$NO_INST/"
rm -f "$NO_INST/install-sfetch.sh.minisig"
if SFETCH_MINISIGN_PUB="$PUB" ./scripts/verify-signatures.sh "$NO_INST"; then
    fail "missing install-sfetch.sh.minisig should exit non-zero"
else
    pass "missing install-sfetch.sh.minisig exits non-zero"
fi

# Case 3: tampered installer fails
TAMPER="${WORKDIR}/tamper"
cp -R "$STAGE/." "$TAMPER/"
echo "evil" >>"$TAMPER/install-sfetch.sh"
if SFETCH_MINISIGN_PUB="$PUB" ./scripts/verify-signatures.sh "$TAMPER"; then
    fail "tampered installer should exit non-zero"
else
    pass "tampered installer exits non-zero"
fi

# Case 4: wrong key fails
WRONG="${WORKDIR}/wrong"
cp -R "$STAGE/." "$WRONG/"
WRONG_KEY="${WORKDIR}/wrong.key"
WRONG_PUB="${WORKDIR}/wrong.pub"
minisign -G -W -p "$WRONG_PUB" -s "$WRONG_KEY" >/dev/null 2>&1 ||
    minisign -G -n -p "$WRONG_PUB" -s "$WRONG_KEY" >/dev/null 2>&1 ||
    fail "wrong keygen failed"
if SFETCH_MINISIGN_PUB="$WRONG_PUB" ./scripts/verify-signatures.sh "$WRONG"; then
    fail "wrong key should exit non-zero"
else
    pass "wrong key exits non-zero"
fi

# Case 5: sign-release-manifests produces installer minisig (and PGP not on installer)
SIGN_DIR="${WORKDIR}/sign"
mkdir -p "$SIGN_DIR"
cp "$STAGE/install-sfetch.sh" "$SIGN_DIR/"
cp "$STAGE/SHA256SUMS" "$SIGN_DIR/"
cp "$STAGE/SHA512SUMS" "$SIGN_DIR/"
SFETCH_MINISIGN_KEY="$KEY" ./scripts/sign-release-manifests.sh v0.0.0-test "$SIGN_DIR"
[ -f "$SIGN_DIR/install-sfetch.sh.minisig" ] || fail "sign-release-manifests did not produce install-sfetch.sh.minisig"
[ -f "$SIGN_DIR/SHA256SUMS.minisig" ] || fail "sign-release-manifests did not produce SHA256SUMS.minisig"
[ -f "$SIGN_DIR/SHA512SUMS.minisig" ] || fail "sign-release-manifests did not produce SHA512SUMS.minisig"
# PGP not requested → no .asc on installer
[ ! -f "$SIGN_DIR/install-sfetch.sh.asc" ] || fail "PGP must not sign installer by default"
pass "sign-release-manifests minisign targets (manifests + installer)"

# Case 6: upload script refuses missing installer minisig
UPLOAD_DIR="${WORKDIR}/upload"
mkdir -p "$UPLOAD_DIR"
cp "$STAGE/install-sfetch.sh" "$UPLOAD_DIR/"
printf '# notes\n' >"$UPLOAD_DIR/release-notes-v0.0.0-test.md"
# Fake binary so ARTIFACTS non-empty
printf 'bin\n' >"$UPLOAD_DIR/sfetch_linux_amd64.tar.gz"
cp "$STAGE/SHA256SUMS" "$UPLOAD_DIR/"
cp "$STAGE/SHA512SUMS" "$UPLOAD_DIR/"
if ./scripts/upload-release-assets.sh v0.0.0-test "$UPLOAD_DIR" 2>/dev/null; then
    fail "upload should refuse missing install-sfetch.sh.minisig"
else
    pass "upload refuses missing install-sfetch.sh.minisig"
fi

# Case 7: generate-checksums does not list .minisig
GEN="${WORKDIR}/gen"
mkdir -p "$GEN"
printf 'x\n' >"$GEN/sfetch_linux_amd64"
printf '#!/bin/sh\n' >"$GEN/install-sfetch.sh"
printf 'sig\n' >"$GEN/install-sfetch.sh.minisig"
printf 'sig\n' >"$GEN/SHA256SUMS.minisig"
go run ./scripts/cmd/generate-checksums --dir "$GEN"
if grep -q '\.minisig' "$GEN/SHA256SUMS"; then
    fail "SHA256SUMS must not contain .minisig entries"
else
    pass "SHA256SUMS has no .minisig self-reference"
fi
grep -q 'install-sfetch.sh' "$GEN/SHA256SUMS" || fail "install-sfetch.sh should still be checksummed"
pass "installer remains in checksums; minisig skipped"

# Case 8: PGP-on-manifests-only when PGP is enabled (ephemeral key; no installer .asc)
if command -v gpg >/dev/null 2>&1; then
    GPG_HOME="${WORKDIR}/gnupg"
    mkdir -p "$GPG_HOME"
    chmod 700 "$GPG_HOME"
    # Batch-generate an ephemeral RSA key (no passphrase)
    cat >"${WORKDIR}/gpg-batch" <<EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: sfetch-test
Name-Email: sfetch-test@example.invalid
Expire-Date: 0
%commit
EOF
    gpg --homedir "$GPG_HOME" --batch --gen-key "${WORKDIR}/gpg-batch" >/dev/null 2>&1 ||
        fail "ephemeral gpg keygen failed"
    PGP_ID="$(gpg --homedir "$GPG_HOME" --list-keys --with-colons 2>/dev/null | awk -F: '/^pub/{print $5; exit}')"
    [ -n "$PGP_ID" ] || fail "could not read ephemeral PGP key id"

    PGP_DIR="${WORKDIR}/pgp"
    mkdir -p "$PGP_DIR"
    cp "$STAGE/install-sfetch.sh" "$PGP_DIR/"
    cp "$STAGE/SHA256SUMS" "$PGP_DIR/"
    cp "$STAGE/SHA512SUMS" "$PGP_DIR/"
    SFETCH_MINISIGN_KEY="$KEY" \
        SFETCH_PGP_KEY_ID="$PGP_ID" \
        SFETCH_GPG_HOMEDIR="$GPG_HOME" \
        ./scripts/sign-release-manifests.sh v0.0.0-pgp-test "$PGP_DIR"

    [ -f "$PGP_DIR/SHA256SUMS.minisig" ] || fail "PGP path still needs SHA256SUMS.minisig"
    [ -f "$PGP_DIR/SHA512SUMS.minisig" ] || fail "PGP path still needs SHA512SUMS.minisig"
    [ -f "$PGP_DIR/install-sfetch.sh.minisig" ] || fail "PGP path still needs install-sfetch.sh.minisig"
    [ -f "$PGP_DIR/SHA256SUMS.asc" ] || fail "PGP should sign SHA256SUMS"
    [ -f "$PGP_DIR/SHA512SUMS.asc" ] || fail "PGP should sign SHA512SUMS"
    [ ! -f "$PGP_DIR/install-sfetch.sh.asc" ] || fail "PGP must not sign install-sfetch.sh"
    pass "PGP signs manifests only; installer minisign-only (no .asc)"
else
    pass "skip PGP target-set proof (gpg not available)"
fi

echo "[ok] release signature regression harness complete"
