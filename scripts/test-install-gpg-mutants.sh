#!/usr/bin/env bash
# Mutation tests for install-sfetch.sh GPG/minisign route.
# Applies each of the 11 listed mutants to a scratch copy and expects the
# corresponding probe to fail (kill). Never runs the installer. Never
# touches a real keyring. Throwaway minisign/GPG keys only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

INSTALLER="${ROOT}/scripts/install-sfetch.sh"
[ -f "$INSTALLER" ] || fail "installer missing"
[ "$(grep -c '^main "$@"$' "$INSTALLER")" -eq 1 ] || fail "installer entry line not exactly-once"

if ! command -v minisign >/dev/null 2>&1; then
    [ "${CI:-}" != "true" ] || fail "minisign required in CI for mutants"
    echo "SKIP: minisign not installed; mutants not run"
    exit 0
fi
if ! command -v gpg >/dev/null 2>&1; then
    [ "${CI:-}" != "true" ] || fail "gpg required in CI for mutants"
    echo "SKIP: gpg not installed; mutants not run"
    exit 0
fi
command -v python3 >/dev/null 2>&1 || fail "python3 required for mutant application"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sft-mutants.XXXXXX")"
GPG_HOMES=()
cleanup_mutants() {
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
    rm -rf "$WORK"
    for h in "${recorded[@]}"; do
        [ -n "$h" ] || continue
        if [ -e "$h" ]; then
            echo "FAIL: GnuPG home still exists after cleanup: $h" >&2
            status=1
        fi
    done
    return "$status"
}
trap cleanup_mutants EXIT
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
    local log="$WORK/gpg-fixture.err"
    if ! "$@" >"$log" 2>&1; then
        echo "FAIL: gpg fixture failed: $*" >&2
        cat "$log" >&2
        fail "gpg fixture"
    fi
}

# Revert-failing: installer must use a short /tmp GnuPG home, not TMPDIR.
grep -q 'mktemp -d /tmp/sfetch-gpg.XXXXXX' "$INSTALLER" ||
    fail "installer GnuPG home must use mktemp -d /tmp/sfetch-gpg.XXXXXX"
grep -q 'GPG_HOME="${tmpdir}/gnupg"' "$INSTALLER" &&
    fail "installer must not place GnuPG home under TMPDIR"

# Probe helper: map verify_signature rc onto the mutant oracle.
# 0 = accepted, 1 = expected verification-failure signal, other = tool error.
PROBE_VERIFY="$WORK/probe-verify.sh"
export PROBE_VERIFY
cat >"$PROBE_VERIFY" <<'EOS'
probe_run_verify() {
    set +e
    (verify_signature "$1" "$2") >/dev/null 2>&1
    _vrc=$?
    set -e
    return 0
}
# Property: input must be rejected. Accept → KILL; verify-fail → SURVIVE; else ERROR.
probe_expect_reject() {
    probe_run_verify "$1" "$2"
    case "$_vrc" in
        0) exit 1 ;;
        1) exit 0 ;;
        *) exit "$_vrc" ;;
    esac
}
# Property: input must be accepted. Accept → SURVIVE; verify-fail → KILL; else ERROR.
probe_expect_accept() {
    probe_run_verify "$1" "$2"
    case "$_vrc" in
        0) exit 0 ;;
        1) exit 1 ;;
        *) exit "$_vrc" ;;
    esac
}
EOS

# --- throwaway keys (never the operator keyring) ---
minisign -G -W -p "$WORK/cur.pub" -s "$WORK/cur.key" >/dev/null 2>&1 || fail "keygen current"
minisign -G -W -p "$WORK/old.pub" -s "$WORK/old.key" >/dev/null 2>&1 || fail "keygen legacy"
CUR_PUB="$(sed -n 2p "$WORK/cur.pub")"
OLD_PUB="$(sed -n 2p "$WORK/old.pub")"
printf 'abc  sfetch_linux_amd64.tar.gz\n' >"$WORK/SHA256SUMS"

new_gpg_home GH
[ "${#GPG_HOMES[@]}" -ge 1 ] || fail "parent GnuPG home registry empty after new_gpg_home"
gpg_gen() {
    gpg_run gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' \
        --quick-gen-key "$1" ed25519 sign never
    gpg --homedir "$GH" --with-colons --fingerprint "$1" | awk -F: '/^fpr:/ {print $10; exit}'
}
FPR_CUR="$(gpg_gen 'cur@test.invalid')"
FPR_OLD="$(gpg_gen 'old@test.invalid')"
FPR_ATK="$(gpg_gen 'atk@test.invalid')"
gpg_run gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' \
    --quick-add-key "$FPR_CUR" ed25519 sign never
SUB_CUR="$(gpg --homedir "$GH" --with-colons --list-keys "$FPR_CUR" |
    awk -F: '$1 == "sub" { s = 1; next } s && $1 == "fpr" { f = $10 } END { print f }')"
[ -n "$SUB_CUR" ] && [ "$SUB_CUR" != "$FPR_CUR" ] || fail "signing subkey"

# Pad current secret listing so mutant 9 (pipe+grep -q) can SIGPIPE.
pad="$(printf 'p%.0s' $(seq 1 1500))"
for i in $(seq 1 100); do
    gpg_run gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' \
        --quick-add-uid "$FPR_CUR" "${i}${pad} <pad${i}@test.invalid>"
done
new_gpg_home PROBE_HOME
big="$(gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' --armor \
    --export-secret-keys "$FPR_CUR" | gpg --homedir "$PROBE_HOME" --batch --with-colons \
    --import-options show-only --import 2>/dev/null | wc -c)" || true
[ "${big:-0}" -gt 131072 ] || fail "padded secret listing too small (${big:-0} bytes)"

strip_installer() {
    local src="$1" dest="$2"
    grep -v '^main "$@"$' "$src" >"$dest"
}

apply_mutant() {
    local n="$1" src="$2" dest="$3"
    python3 - "$n" "$src" "$dest" <<'PY'
import pathlib, re, sys
n, src, dest = int(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
text = src.read_text()
orig = text

def sub(pat, repl, count=1, flags=0):
    global text
    new, k = re.subn(pat, repl, text, count=count, flags=flags)
    if k == 0:
        raise SystemExit(f'mutant {n}: pattern did not match')
    text = new

if n == 1:
    # Invert tag→key selection: tags above the cutoff become legacy.
    sub(
        r'if semver_le_tag "\$version" "\$SFETCH_PREVKEY_MAX"; then',
        'if ! semver_le_tag "$version" "$SFETCH_PREVKEY_MAX"; then',
    )
elif n == 2:
    # Minisign verifies with the default (current) key, not the selected pin.
    sub(
        r'echo "\$ACTIVE_MINISIGN_PUBKEY" >>"\$pubkey_file"',
        'echo "$SFETCH_MINISIGN_PUBKEY" >>"$pubkey_file"',
    )
elif n == 3:
    # GPG fingerprint compared to the default pin, not the selected pin.
    sub(
        r'if \[ "\$fprs" != "\$ACTIVE_PGP_FPR" \]; then',
        'if [ "$fprs" != "$SFETCH_PGP_FPR" ]; then',
        count=1,
    )
elif n == 4:
    # Corrupt the legacy minisign constant with an id-preserving payload change
    # (keep the RWTAoUJ007VE3h8t key-id prefix; change the remaining blob).
    sub(
        r'SFETCH_MINISIGN_PUBKEY_LEGACY="RWTAoUJ007VE3h8tbHlBCyk2\+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC"',
        'SFETCH_MINISIGN_PUBKEY_LEGACY="RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryXXXX"',
    )
elif n == 5:
    sub(
        r'SFETCH_PGP_FPR="0CACA49B3119B6BC12B2CA11B9B485F294B9FE07"',
        'SFETCH_PGP_FPR="0000000000000000000000000000000000000000"',
    )
elif n == 6:
    sub(
        r'SFETCH_PGP_FPR_LEGACY="94BB7811D4AD49B2310E0C08FA0651DE91B828ED"',
        'SFETCH_PGP_FPR_LEGACY="0CACA49B3119B6BC12B2CA11B9B485F294B9FE07"',
    )
elif n == 7:
    sub(
        r'err "minisign signature verification failed"',
        'warn "minisign signature verification failed"',
    )
elif n == 8:
    # Remove the three overlapping checks together (secret-key reject,
    # nprimary==1, VALIDSIG primary) and revert fingerprint collection to
    # first-fpr-only — the narrow --import show-only hole those three close.
    sub(
        r'if \[ "\$has_sec" = true \]; then\n                gpg_cleanup\n                err "GPG key file must not contain secret keys"\n            fi\n            if \[ "\$nprimary" -ne 1 \]; then\n                gpg_cleanup\n                err "GPG key file must contain exactly one primary key"\n            fi\n',
        '',
        flags=re.M,
    )
    sub(
        r'if \[ "\$sig_primary" != "\$fprs" \]; then\n                gpg_cleanup\n                err "GPG signature is not from the pinned key \(got \$\{sig_primary:-none\}\)"\n            fi\n',
        '',
        flags=re.M,
    )
    sub(
        r'fprs="\$\{fprs\}\$\{fprs:\+ \}\$\{_f\[9\]:-\}"',
        'if [ -z "$fprs" ]; then fprs="${_f[9]:-}"; fi',
    )
elif n == 9:
    # Secret-key reject via printf | grep -q (SIGPIPE under pipefail on a
    # >128KB listing can skip the rest of the checks).
    sub(
        r'if \[ "\$has_sec" = true \]; then\n                gpg_cleanup\n                err "GPG key file must not contain secret keys"\n            fi\n',
        'if printf \'%s\\n\' "$listing" | grep -q \'^sec:\'; then\n'
        '                gpg_cleanup\n'
        '                err "GPG key file must not contain secret keys"\n'
        '            fi\n',
        flags=re.M,
    )
elif n == 10:
    # VALIDSIG parsed from the first fingerprint field (subkey signer) rather
    # than field 12 (primary). Field 3 is the signing-key fpr.
    sub(
        r'sig_primary="\$\(gpg_validsig_primary "\$line"\)"',
        '''sig_primary="$(awk '{print $3}' <<<"$line")"''',
    )
elif n == 11:
    # GnuPG home cleanup emptied so the private home leaks.
    sub(
        r'gpg_cleanup\(\) \{\n    if \[ -n "\$GPG_HOME" \] && \[ -d "\$GPG_HOME" \]; then\n        gpgconf --homedir "\$GPG_HOME" --kill all >/dev/null 2>&1 \|\| true\n        rm -rf "\$GPG_HOME"\n    fi\n    GPG_HOME=""\n\}',
        'gpg_cleanup() { GPG_HOME=""; }',
        flags=re.M,
    )
    sub(
        r'GPG_HOME="\$\(mktemp -d /tmp/sfetch-gpg.XXXXXX\)"',
        'GPG_HOME="$(mktemp -d)"',
    )
else:
    raise SystemExit(f'unknown mutant {n}')

if text == orig:
    raise SystemExit(f'mutant {n}: file unchanged')
dest.write_text(text)
PY
}

# Probe helpers run in a subshell against a stripped mutated copy ($1).
# Exit 0 = the security property still holds (mutant survived).
# Exit 1 = the security property is broken (mutant killed).

probe_constants() {
    local src="$1" kind="$2"
    bash -c '
set -euo pipefail
. "$1"
case "$2" in
  legacy-minisign)
    [ "$SFETCH_MINISIGN_PUBKEY_LEGACY" = "RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC" ]
    ;;
  current-gpg)
    [ "$SFETCH_PGP_FPR" = "0CACA49B3119B6BC12B2CA11B9B485F294B9FE07" ]
    ;;
  gpg-distinct)
    [ "$SFETCH_PGP_FPR_LEGACY" != "$SFETCH_PGP_FPR" ]
    ;;
  *) exit 2 ;;
esac
' _ "$src" "$kind"
}

probe_selection() {
    local src="$1"
    bash -c '
set -euo pipefail
. "$1"
select_trust_anchor v0.4.11 >/dev/null
[ "$ANCHOR_GEN" = legacy ]
[ "$ACTIVE_MINISIGN_PUBKEY" = "$SFETCH_MINISIGN_PUBKEY_LEGACY" ]
[ "$ACTIVE_PGP_FPR" = "$SFETCH_PGP_FPR_LEGACY" ]
select_trust_anchor v0.4.12 >/dev/null
[ "$ANCHOR_GEN" = current ]
[ "$ACTIVE_MINISIGN_PUBKEY" = "$SFETCH_MINISIGN_PUBKEY" ]
' _ "$src"
}

probe_minisign_cross() {
    local src="$1"
    bash -c '
set -euo pipefail
. "$1"
. "$PROBE_VERIFY"
SFETCH_MINISIGN_PUBKEY="$2"
SFETCH_MINISIGN_PUBKEY_LEGACY="$3"
d="$(mktemp -d "$4/m.XXXXXX")"
cp "$4/SHA256SUMS" "$d/SHA256SUMS"
minisign -S -s "$4/cur.key" -m "$d/SHA256SUMS" -x "$d/SHA256SUMS.minisig" >/dev/null
VERIFY_MINISIGN=true VERIFY_GPG=false REQUIRE_MINISIGN=true REQUIRE_SIGNATURE=true
# Property: a current-key signature must be rejected for a legacy tag.
select_trust_anchor v0.4.11 >/dev/null
probe_expect_reject "$d/SHA256SUMS" "$d"
' _ "$src" "$CUR_PUB" "$OLD_PUB" "$WORK"
}

probe_gpg_default_pin() {
    local src="$1"
    bash -c '
set -euo pipefail
. "$1"
. "$PROBE_VERIFY"
SFETCH_PGP_FPR="$2"
SFETCH_PGP_FPR_LEGACY="$3"
d="$(mktemp -d "$4/g.XXXXXX")"
cp "$4/SHA256SUMS" "$d/SHA256SUMS"
gpg --homedir "$5" --batch --armor --export cur@test.invalid >"$d/sfetch-release-signing-key.asc"
gpg --homedir "$5" --batch --yes --pinentry-mode loopback --passphrase "" \
    -u cur@test.invalid --armor --detach-sign -o "$d/SHA256SUMS.asc" "$d/SHA256SUMS"
VERIFY_MINISIGN=false VERIFY_GPG=true REQUIRE_MINISIGN=false REQUIRE_SIGNATURE=true
# Property: the current GPG key must be rejected for a legacy tag.
select_trust_anchor v0.4.11 >/dev/null
probe_expect_reject "$d/SHA256SUMS" "$d"
' _ "$src" "$FPR_CUR" "$FPR_OLD" "$WORK" "$GH"
}

probe_minisign_fallback() {
    local src="$1"
    bash -c '
set -euo pipefail
. "$1"
. "$PROBE_VERIFY"
SFETCH_MINISIGN_PUBKEY="$2"
SFETCH_MINISIGN_PUBKEY_LEGACY="$3"
SFETCH_PGP_FPR="$4"
d="$(mktemp -d "$5/f.XXXXXX")"
cp "$5/SHA256SUMS" "$d/SHA256SUMS"
minisign -S -s "$5/old.key" -m "$d/SHA256SUMS" -x "$d/SHA256SUMS.minisig" >/dev/null
gpg --homedir "$6" --batch --armor --export cur@test.invalid >"$d/sfetch-release-signing-key.asc"
gpg --homedir "$6" --batch --yes --pinentry-mode loopback --passphrase "" \
    -u cur@test.invalid --armor --detach-sign -o "$d/SHA256SUMS.asc" "$d/SHA256SUMS"
VERIFY_MINISIGN=true VERIFY_GPG=true REQUIRE_MINISIGN=false REQUIRE_SIGNATURE=true
# Property: a minisign reject must not fall through to a valid GPG signature.
select_trust_anchor v0.4.12 >/dev/null
probe_expect_reject "$d/SHA256SUMS" "$d"
' _ "$src" "$CUR_PUB" "$OLD_PUB" "$FPR_CUR" "$WORK" "$GH"
}

probe_bundle() {
    local src="$1"
    bash -c '
set -euo pipefail
. "$1"
. "$PROBE_VERIFY"
SFETCH_PGP_FPR="$2"
d="$(mktemp -d "$3/b.XXXXXX")"
cp "$3/SHA256SUMS" "$d/SHA256SUMS"
gpg --homedir "$4" --batch --armor --export cur@test.invalid >>"$d/sfetch-release-signing-key.asc"
gpg --homedir "$4" --batch --armor --export atk@test.invalid >>"$d/sfetch-release-signing-key.asc"
gpg --homedir "$4" --batch --yes --pinentry-mode loopback --passphrase "" \
    -u atk@test.invalid --armor --detach-sign -o "$d/SHA256SUMS.asc" "$d/SHA256SUMS"
VERIFY_MINISIGN=false VERIFY_GPG=true REQUIRE_MINISIGN=false REQUIRE_SIGNATURE=true
# Property: a bundled extra primary must be refused even when the pin is present.
select_trust_anchor v0.4.12 >/dev/null
probe_expect_reject "$d/SHA256SUMS" "$d"
' _ "$src" "$FPR_CUR" "$WORK" "$GH"
}

probe_secret_large() {
    local src="$1"
    bash -c '
set -euo pipefail
. "$1"
. "$PROBE_VERIFY"
SFETCH_PGP_FPR="$2"
d="$(mktemp -d "$3/x.XXXXXX")"
cp "$3/SHA256SUMS" "$d/SHA256SUMS"
gpg --homedir "$4" --batch --pinentry-mode loopback --passphrase "" --armor \
    --export-secret-keys cur@test.invalid >"$d/sfetch-release-signing-key.asc"
gpg --homedir "$4" --batch --yes --pinentry-mode loopback --passphrase "" \
    -u cur@test.invalid --armor --detach-sign -o "$d/SHA256SUMS.asc" "$d/SHA256SUMS"
VERIFY_MINISIGN=false VERIFY_GPG=true REQUIRE_MINISIGN=false REQUIRE_SIGNATURE=true
# Property: a secret-key listing (including >128KB) must be refused. Mutant 9
# can SIGPIPE and skip the reject.
select_trust_anchor v0.4.12 >/dev/null
probe_expect_reject "$d/SHA256SUMS" "$d"
' _ "$src" "$FPR_CUR" "$WORK" "$GH"
}

probe_subkey() {
    local src="$1"
    bash -c '
set -euo pipefail
. "$1"
. "$PROBE_VERIFY"
# Committed subkey-signature specimen: CONTROL must pass without depending on
# live keygen, and field 12 must be used (GnuPG 2.5.x puts flags in $NF).
spec="$2"
primary="$(awk -F= "/^primary=/{print \$2}" "$spec/fingerprints.txt")"
SFETCH_PGP_FPR="$primary"
d="$(mktemp -d "$3/s.XXXXXX")"
cp "$spec/SHA256SUMS" "$d/SHA256SUMS"
cp "$spec/SHA256SUMS.asc" "$d/SHA256SUMS.asc"
cp "$spec/public.asc" "$d/sfetch-release-signing-key.asc"
VERIFY_MINISIGN=false VERIFY_GPG=true REQUIRE_MINISIGN=false REQUIRE_SIGNATURE=true
# Property: a subkey signature whose VALIDSIG primary field (12) matches the
# pin must verify. Mutant 10 compares field 3 (subkey) and rejects.
select_trust_anchor v0.4.12 >/dev/null
probe_expect_accept "$d/SHA256SUMS" "$d"
' _ "$src" "$ROOT/testdata/gpg-mutants" "$WORK"
}

probe_homedir_leak() {
    local src="$1"
    bash -c '
set -euo pipefail
d="$(mktemp -d "$2/e.XXXXXX")"
cp "$2/SHA256SUMS" "$d/SHA256SUMS"
: >"$d/SHA256SUMS.asc"
: >"$d/sfetch-release-signing-key.asc"
shim="$(mktemp -d "$2/shim.XXXXXX")"
homes_log="$shim/homes.log"
: >"$homes_log"
real_gpg="$(command -v gpg)"
cat >"$shim/gpg" <<SHIM
#!/usr/bin/env bash
prev=""
for a in "\$@"; do
    [ "\$prev" = "--homedir" ] && printf "%s\\n" "\$a" >>"$homes_log"
    prev="\$a"
done
exec "$real_gpg" "\$@"
SHIM
chmod +x "$shim/gpg"
set +e
PATH="$shim:$PATH" bash -c "set -euo pipefail
    . \"\$1\"
    . \"\$4\"
    tmpdir=\"\$2\"
    trap '\''gpg_cleanup; rm -rf \"\$tmpdir\"'\'' EXIT
    VERIFY_MINISIGN=false VERIFY_GPG=true REQUIRE_MINISIGN=false REQUIRE_SIGNATURE=true
    SFETCH_PGP_FPR=\"\$3\"
    select_trust_anchor v0.4.12
    probe_run_verify \"\$tmpdir/SHA256SUMS\" \"\$tmpdir\"
    exit \"\$_vrc\"" _ "$1" "$d" "$3" "$PROBE_VERIFY" >/dev/null 2>&1
rc=$?
set -e
# Mutant 11 is killed if a GnuPG home remains after the trap.
leaked=0
while IFS= read -r h; do
    [ -z "$h" ] && continue
    if [ -e "$h" ]; then leaked=1; fi
done <"$homes_log"
if [ "$leaked" -eq 1 ]; then
    exit 1
fi
# Empty key must fail verification (1). Tool errors are not kills.
case "$rc" in
    0) exit 1 ;;
    1) ;;
    *) exit "$rc" ;;
esac
exit 0
' _ "$src" "$WORK" "$FPR_CUR"
}

# Probe convention: 0 = SURVIVE (property holds), 1 = KILL (expected
# verification failure). Any other status is a harness/tool error, not a kill.
classify_probe_rc() {
    case "$1" in
        0) printf 'SURVIVE' ;;
        1) printf 'KILL' ;;
        *) printf 'ERROR' ;;
    esac
}

run_mutant() {
    local n="$1" name="$2" probe="$3"
    local cdir="$WORK/c$n" mdir="$WORK/m$n"
    mkdir -p "$cdir" "$mdir"
    # Unmutated control must pass (property holds). A probe that reports KILL
    # on good code is a broken oracle, not a killed mutant.
    strip_installer "$INSTALLER" "$cdir/src"
    set +e
    "$probe" "$cdir/src"
    local crc=$?
    set -e
    if [ "$(classify_probe_rc "$crc")" != SURVIVE ]; then
        echo "CONTROL-FAIL  $n  $name (unmutated must pass, rc=$crc)"
        return 1
    fi
    echo "CONTROL  $n  $name"
    apply_mutant "$n" "$INSTALLER" "$mdir/install-sfetch.sh"
    strip_installer "$mdir/install-sfetch.sh" "$mdir/src"
    set +e
    "$probe" "$mdir/src"
    local rc=$?
    set -e
    local kind
    kind="$(classify_probe_rc "$rc")"
    case "$kind" in
        SURVIVE)
            echo "SURVIVE  $n  $name"
            return 1
            ;;
        KILL)
            echo "KILL     $n  $name"
            return 0
            ;;
        *)
            echo "ERROR    $n  $name (probe rc=$rc is not a kill)"
            return 1
            ;;
    esac
}

[ "$(classify_probe_rc 0)" = SURVIVE ] || fail "classify 0 must be SURVIVE"
[ "$(classify_probe_rc 1)" = KILL ] || fail "classify 1 must be KILL"
[ "$(classify_probe_rc 127)" = ERROR ] || fail "classify 127 must be ERROR, not KILL"
[ "$(classify_probe_rc 2)" = ERROR ] || fail "classify 2 must be ERROR, not KILL"
pass "harness errors are not kills"

# Identity "mutant" (unchanged installer) + broken gpg must be ERROR, not KILL.
# Replacing this probe with the old `exit 1` collapse reports a kill.
iddir="$WORK/identity"
mkdir -p "$iddir" "$WORK/broken-gpg"
strip_installer "$INSTALLER" "$iddir/src"
printf '%s\n' '#!/usr/bin/env bash' 'exit 127' >"$WORK/broken-gpg/gpg"
chmod +x "$WORK/broken-gpg/gpg"
set +e
PATH="$WORK/broken-gpg:$PATH" probe_subkey "$iddir/src"
idrc=$?
set -e
idkind="$(classify_probe_rc "$idrc")"
[ "$idkind" = ERROR ] || fail "unchanged code + gpg 127 must be ERROR not $idkind (rc=$idrc)"
pass "broken gpg is never a kill"

# Field-12 parser: $NF is the primary on 2.2/2.4 and flags on 2.5.x.
eval "$(sed -n '/^gpg_validsig_primary()/,/^}/p' "$INSTALLER")"
command -v gpg_validsig_primary >/dev/null || fail "gpg_validsig_primary not loaded"
SPEC="$ROOT/testdata/gpg-mutants"
line22="$(cat "$SPEC/validsig-2.2.status")"
line25="$(cat "$SPEC/validsig-2.5.status")"
want_primary="$(awk -F= '/^primary=/{print $2}' "$SPEC/fingerprints.txt")"
want_sub="$(awk -F= '/^signing=/{print $2}' "$SPEC/fingerprints.txt")"
[ "$(gpg_validsig_primary "$line22")" = "$want_primary" ] || fail "2.2 VALIDSIG primary"
[ "$(gpg_validsig_primary "$line25")" = "$want_primary" ] || fail "2.5 VALIDSIG primary (not \$NF)"
[ "$(awk '{print $NF}' <<<"$line25")" != "$want_primary" ] || fail "2.5 specimen \$NF should not be the primary"
[ "$(awk '{print $3}' <<<"$line22")" = "$want_sub" ] || fail "specimen field 3 is the subkey"
pass "VALIDSIG field 12 is portable across GnuPG 2.2–2.5"

killed=0
survived=0
run() {
    if run_mutant "$@"; then
        killed=$((killed + 1))
    else
        survived=$((survived + 1))
    fi
}

probe_constants_legacy() { probe_constants "$1" legacy-minisign; }
probe_constants_gpg() { probe_constants "$1" current-gpg; }
probe_constants_distinct() { probe_constants "$1" gpg-distinct; }

run 1 "inverted tag-to-key selection" probe_selection
run 2 "minisign verifies with default key" probe_minisign_cross
run 3 "GPG fingerprint compared to default pin" probe_gpg_default_pin
run 4 "legacy minisign constant corrupted (id-preserving)" probe_constants_legacy
run 5 "current GPG fingerprint zeroed" probe_constants_gpg
run 6 "legacy GPG pin equals current" probe_constants_distinct
run 7 "minisign failure falls through to GPG" probe_minisign_fallback
run 8 "VALIDSIG+secret-key+nprimary removed together" probe_bundle
run 9 "secret-key reject via printf|grep -q (SIGPIPE)" probe_secret_large
run 10 "VALIDSIG parsed from first field (subkey signer)" probe_subkey
run 11 "GnuPG home outside trapped tmpdir, cleanup off" probe_homedir_leak

echo ""
echo "mutant summary: killed=$killed survived=$survived (want killed=11 survived=0)"
[ "$killed" -eq 11 ] && [ "$survived" -eq 0 ] || fail "expected 11 kills, 0 survivors"
echo "[ok] all 11 installer GPG/minisign mutants killed"
