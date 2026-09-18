#!/usr/bin/env bash
# Unit/fixture tests for bootstrap-sfetch-verified.sh (route selection, rejects, dual-route).
# Production engine has no runtime env trust overrides; fixtures patch a temporary copy.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SCRIPT="${ROOT}/scripts/bootstrap-sfetch-verified.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

# No colocated engine under the action directory — single SSOT under scripts/.
[ ! -e "${ROOT}/.github/actions/setup-sfetch/bootstrap-sfetch-verified.sh" ] ||
    fail "colocated action engine must not exist (single SSOT under scripts/)"
# Helper removed: exact matcher lives only in the engine.
[ ! -e "${ROOT}/scripts/version-matches-pin.sh" ] ||
    fail "version-matches-pin.sh must not exist (engine is sole matcher SSOT)"
[ -x "$SCRIPT" ] || chmod +x "$SCRIPT"
# Production engine must not honor trust-weakening env seams.
grep -q 'SFETCH_BOOTSTRAP_BASE_URL' "$SCRIPT" &&
    fail "production engine must not reference SFETCH_BOOTSTRAP_BASE_URL"
grep -q 'SFETCH_BOOTSTRAP_SKIP_MINISIGN_INSTALL' "$SCRIPT" &&
    fail "production engine must not reference SFETCH_BOOTSTRAP_SKIP_MINISIGN_INSTALL"
pass "single engine SSOT; no production env trust seams"

# Load the engine's authoritative matcher for offline token unit tests.
eval "$(sed -n '/^version_output_matches_pin()/,/^}/p' "$SCRIPT")"
version_output_matches_pin "sfetch 0.4.11" "v0.4.11" || fail "should match sfetch 0.4.11"
version_output_matches_pin "sfetch version v0.4.11" "v0.4.11" || fail "should match v-prefixed"
if version_output_matches_pin "sfetch 10x4y110" "v0.4.11"; then fail "must not soft-match 10x4y110"; fi
if version_output_matches_pin "sfetch 10.4.11" "v0.4.11"; then fail "must not match inside 10.4.11"; fi
if version_output_matches_pin "sfetch 0.4.110" "v0.4.11"; then fail "must not match 0.4.110"; fi
if version_output_matches_pin "sfetch 0.4.11-rc1" "v0.4.11"; then fail "must not match suffixed 0.4.11-rc1"; fi
if version_output_matches_pin "sfetch v0.4.11-beta" "v0.4.11"; then fail "must not match v0.4.11-beta"; fi
if version_output_matches_pin "sfetch x0.4.11" "v0.4.11"; then fail "must not match prefixed x0.4.11"; fi
version_output_matches_pin "minisign 0.12" "0.12" || fail "should match minisign 0.12"
pass "engine version_output_matches_pin exact token rules"

# --- Version rejection (no network) ---
if "$SCRIPT" 2>/dev/null; then fail "should require --version"; else pass "requires --version"; fi
if "$SCRIPT" --version latest --dir /tmp 2>/dev/null; then fail "latest should fail"; else pass "rejects latest"; fi
if "$SCRIPT" --version main --dir /tmp 2>/dev/null; then fail "main should fail"; else pass "rejects main"; fi
if "$SCRIPT" --version v0.4.11-rc1 --dir /tmp 2>/dev/null; then fail "prerelease should fail"; else pass "rejects prerelease"; fi
if "$SCRIPT" --version v0.4.8 --dir /tmp 2>/dev/null; then fail "below min should fail"; else pass "rejects below min"; fi
if "$SCRIPT" --version v0.4.14 --dir /tmp 2>/dev/null; then fail "above max should fail"; else pass "rejects above max"; fi
# F2: leading-zero components must not pass range/route selection
if "$SCRIPT" --version v0.4.09 --dir /tmp 2>/dev/null; then fail "v0.4.09 leading zero should fail"; else pass "rejects v0.4.09 leading zero"; fi
if "$SCRIPT" --version v0.04.11 --dir /tmp 2>/dev/null; then fail "v0.04.11 leading zero should fail"; else pass "rejects v0.04.11 leading zero"; fi

# --- Helpers: patch temporary engines for fixtures (never production seams) ---
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/sft-boot-test.XXXXXX")"
SRV_PID=""
SRV_PID2=""
cleanup_harness() {
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
    [ -n "${SRV_PID2:-}" ] && kill "$SRV_PID2" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID2" 2>/dev/null || true
    rm -rf "${WORKDIR}"
}
trap cleanup_harness EXIT

# Rejected inputs must not create install dirs (validate-before-side-effect)
NO_SIDE="$WORKDIR/no-side"
if "$SCRIPT" --version v0.4.09 --dir "$NO_SIDE" 2>/dev/null; then fail "v0.4.09 should fail"; fi
[ ! -e "$NO_SIDE" ] || fail "rejected version must not create install dir"
pass "rejected version has no mkdir side effect"

# Huge components: both overflow faces must fail closed before route selection / network.
# Face 1: wrap-to-zero major (2^64). Face 2: wrap-into-range patch (2^64+11 → was 11 under Bash $((10#…))).
# A late 404 would also be nonzero — pin that rejection is early (no verify-route=, no fetch log, no install dir).
assert_early_version_reject() {
    local ver="$1" label="$2"
    local idir="$WORKDIR/early-reject-${label}"
    local logf="$WORKDIR/early-reject-${label}.log"
    local rc=0
    set +e
    "$SCRIPT" --version "$ver" --dir "$idir" >"$logf" 2>&1
    rc=$?
    set -e
    [ "$rc" -ne 0 ] || fail "${label}: expected nonzero exit for ${ver}"
    if grep -q 'verify-route=' "$logf"; then
        fail "${label}: must not emit verify-route= before range reject (${ver})"
    fi
    if grep -Eiq 'fetch attempt|failed to fetch|http(s)?://|curl |wget ' "$logf"; then
        fail "${label}: must not perform network/fetch before range reject (${ver})"
    fi
    [ ! -e "$idir" ] || fail "${label}: install dir must remain absent for ${ver}"
    pass "rejects ${label} early (${ver})"
}
assert_early_version_reject "v18446744073709551616.4.10" "huge-major-wrap-zero"
assert_early_version_reject "v0.4.18446744073709551627" "huge-patch-wrap-into-range"

PROD_PUBKEY="RWTqUZ/PtmfAbQ3RKIlp/YTKT6zFeNMAZ8iAMelhlmqEsVqjKj3ctSA1"
LEGACY_PUBKEY="RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC"

# Harness pins must track the engine's anchors exactly; drift fails here, loudly.
grep -q "SFETCH_MINISIGN_PUBKEY=\"$PROD_PUBKEY\"" "$SCRIPT" || fail "harness PROD_PUBKEY drifted from engine"
grep -q "SFETCH_MINISIGN_PUBKEY_LEGACY=\"$LEGACY_PUBKEY\"" "$SCRIPT" || fail "harness LEGACY_PUBKEY drifted from engine"
grep -q 'SFETCH_PREVKEY_MAX="v0.4.11"' "$SCRIPT" || fail "engine PREVKEY cutoff moved; update pin-map tests"

# Build a temporary engine: optional test pubkey + fixed BASE_URL for sfetch assets.
# Minisign always comes from the engine's pinned 0.12 download (not ambient PATH).
# CI runners often ship distro minisign 0.11; using ambient would fail the 0.12 assert
# and is not how production runs.
#
# varname selects which anchor the test pubkey replaces: pin-map tests must patch
# exactly the anchor the requested pin selects, leaving the other production
# anchor intact (patching both would mask selection bugs).
make_fixture_engine() {
    local dest="$1" base_url="$2" pubkey="${3-}" varname="${4-}"
    local src="$SCRIPT"
    cp "$src" "$dest"
    # Fixed download base → fixture URL (literal, no env).
    # shellcheck disable=SC2016
    sed -i.bak \
        's|BASE_URL="https://github.com/${REPO}/releases/download"|BASE_URL="'"${base_url}"'"|' \
        "$dest"
    if [ -n "$pubkey" ]; then
        [ -n "$varname" ] || fail "make_fixture_engine: varname required with pubkey"
        local old other
        case "$varname" in
            SFETCH_MINISIGN_PUBKEY)
                old="$PROD_PUBKEY"
                other="$LEGACY_PUBKEY"
                ;;
            SFETCH_MINISIGN_PUBKEY_LEGACY)
                old="$LEGACY_PUBKEY"
                other="$PROD_PUBKEY"
                ;;
            *)
                fail "make_fixture_engine: unknown anchor var $varname"
                ;;
        esac
        sed -i.bak "s|${old}|${pubkey}|g" "$dest"
        grep -q "$pubkey" "$dest" || fail "patched engine missing test pubkey"
        grep -q "$old" "$dest" && fail "patched engine still has production $varname"
        grep -q "$other" "$dest" || fail "patched engine lost the other anchor (must patch exactly one var)"
    fi
    rm -f "${dest}.bak"
    chmod +x "$dest"
}

# --- Route selection via fixture engines with dead base URL ---
ROUTE_ENG="$WORKDIR/route-engine.sh"
make_fixture_engine "$ROUTE_ENG" "file://${WORKDIR}/empty"

set +e
OUT1040="$WORKDIR/out410.txt"
"$ROUTE_ENG" --version v0.4.10 --dir "$WORKDIR/d410" >"$OUT1040" 2>&1
set -e
grep -Eq 'verify-route=sha256sums' "$OUT1040" || fail "v0.4.10 should select sha256sums (log: $(cat "$OUT1040"))"
grep -Eq 'anchor=legacy' "$OUT1040" || fail "v0.4.10 should select legacy anchor (log: $(cat "$OUT1040"))"
pass "v0.4.10 → verify-route=sha256sums"

set +e
OUT411="$WORKDIR/out411.txt"
"$ROUTE_ENG" --version v0.4.11 --dir "$WORKDIR/d411" >"$OUT411" 2>&1
set -e
grep -Eq 'verify-route=minisig' "$OUT411" || fail "v0.4.11 should select minisig (log: $(cat "$OUT411"))"
grep -Eq 'anchor=legacy' "$OUT411" || fail "v0.4.11 should select legacy anchor (log: $(cat "$OUT411"))"
pass "v0.4.11 → verify-route=minisig"

# Production engine ignores inherited BASE_URL / SKIP env (no seams).
export SFETCH_BOOTSTRAP_BASE_URL="http://evil.example/should-not-be-used"
export SFETCH_BOOTSTRAP_SKIP_MINISIGN_INSTALL=1
set +e
OUT_IGN="$WORKDIR/out-ignore-env.txt"
"$SCRIPT" --version v0.4.10 --dir "$WORKDIR/d-ign" >"$OUT_IGN" 2>&1
set -e
# Should attempt real GitHub URL (or fail fetching), not evil.example
if grep -q 'evil.example' "$OUT_IGN"; then
    fail "production engine honored SFETCH_BOOTSTRAP_BASE_URL"
fi
# With SKIP set, production still must not prefer ambient-only short-circuit via that var
# (it will try to download pinned minisign or fetch assets from real GitHub).
pass "production engine ignores inherited BASE_URL/SKIP env vars"
unset SFETCH_BOOTSTRAP_BASE_URL SFETCH_BOOTSTRAP_SKIP_MINISIGN_INSTALL

# --- Local dual-route fixtures with ephemeral minisign ---
command -v minisign >/dev/null 2>&1 || fail "minisign required"
command -v python3 >/dev/null 2>&1 || fail "python3 required for local HTTP fixture"

KEY="$WORKDIR/k.key"
PUB="$WORKDIR/k.pub"
minisign -G -W -p "$PUB" -s "$KEY" >/dev/null 2>&1 ||
    minisign -G -n -p "$PUB" -s "$KEY" >/dev/null 2>&1 ||
    fail "keygen"

TEST_PUBKEY="$(grep -E '^RW' "$PUB" | head -n1 | tr -d '\r\n')"
[ -n "$TEST_PUBKEY" ] || fail "could not read test pubkey"

# Second ephemeral pair: post-cutover selection tests need distinct legacy/current keys.
OLDKEY="$WORKDIR/old.key"
OLDPUB="$WORKDIR/old.pub"
minisign -G -W -p "$OLDPUB" -s "$OLDKEY" >/dev/null 2>&1 ||
    minisign -G -n -p "$OLDPUB" -s "$OLDKEY" >/dev/null 2>&1 ||
    fail "keygen (legacy stand-in)"
NEWKEY="$WORKDIR/new.key"
NEWPUB="$WORKDIR/new.pub"
minisign -G -W -p "$NEWPUB" -s "$NEWKEY" >/dev/null 2>&1 ||
    minisign -G -n -p "$NEWPUB" -s "$NEWKEY" >/dev/null 2>&1 ||
    fail "keygen (current stand-in)"
OLD_EPHEMERAL_PUBKEY="$(grep -E '^RW' "$OLDPUB" | head -n1 | tr -d '\r\n')"
NEW_EPHEMERAL_PUBKEY="$(grep -E '^RW' "$NEWPUB" | head -n1 | tr -d '\r\n')"
[ -n "$OLD_EPHEMERAL_PUBKEY" ] || fail "could not read legacy stand-in pubkey"
[ -n "$NEW_EPHEMERAL_PUBKEY" ] || fail "could not read current stand-in pubkey"
[ "$OLD_EPHEMERAL_PUBKEY" != "$NEW_EPHEMERAL_PUBKEY" ] || fail "stand-in keys must differ"

SRV_ROOT="$WORKDIR/www"
mkdir -p "$SRV_ROOT/v0.4.11" "$SRV_ROOT/v0.4.10" "$SRV_ROOT/v0.4.13"

make_stub_installer() {
    local dest="$1"
    cat >"$dest" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
DIR=""
TAG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --yes|--require-minisign) shift ;;
    *) shift ;;
  esac
done
: "${DIR:?}"
mkdir -p "${DIR}"
VER="${TAG#v}"
cat >"${DIR}/sfetch" <<EOF
#!/usr/bin/env bash
echo "sfetch ${VER}"
EOF
chmod +x "${DIR}/sfetch"
echo "STUB_RAN" >"${DIR}/.stub-ran"
STUB
    chmod +x "$dest"
}

make_stub_installer "$SRV_ROOT/v0.4.11/install-sfetch.sh"
make_stub_installer "$SRV_ROOT/v0.4.10/install-sfetch.sh"
make_stub_installer "$SRV_ROOT/v0.4.13/install-sfetch.sh"

minisign -S -s "$KEY" -t "test-v0.4.11" -m "$SRV_ROOT/v0.4.11/install-sfetch.sh"
(
    cd "$SRV_ROOT/v0.4.10"
    shasum -a 256 install-sfetch.sh >SHA256SUMS
)
minisign -S -s "$KEY" -t "test-v0.4.10" -m "$SRV_ROOT/v0.4.10/SHA256SUMS"

start_http_fixture() {
    local root="$1" portfile="$2"
    rm -f "$portfile"
    python3 - "$root" "$portfile" <<'PY' &
import http.server, socketserver, sys, pathlib
root = pathlib.Path(sys.argv[1])
portfile = pathlib.Path(sys.argv[2])
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=str(root), **k)
    def log_message(self, *args):
        pass
with socketserver.TCPServer(("127.0.0.1", 0), H) as httpd:
    portfile.write_text(str(httpd.server_address[1]))
    httpd.serve_forever()
PY
}

PORTFILE="$WORKDIR/port"
start_http_fixture "$SRV_ROOT" "$PORTFILE"
SRV_PID=$!
for _ in $(seq 1 50); do
    [ -f "$PORTFILE" ] && break
    sleep 0.05
done
[ -f "$PORTFILE" ] || fail "HTTP fixture server failed to start"
PORT="$(cat "$PORTFILE")"
BASE="http://127.0.0.1:${PORT}"

PATCHED="$WORKDIR/bootstrap-patched.sh"
make_fixture_engine "$PATCHED" "$BASE" "$TEST_PUBKEY" "SFETCH_MINISIGN_PUBKEY_LEGACY"

# Positive: v0.4.11 minisig route
GOOD411="$WORKDIR/good411"
mkdir -p "$GOOD411"
set +e
OUT_GOOD="$WORKDIR/out-good411.txt"
"$PATCHED" --version v0.4.11 --dir "$GOOD411" >"$OUT_GOOD" 2>&1
RC=$?
set -e
[ "$RC" -eq 0 ] || fail "positive v0.4.11 minisig should succeed (log: $(cat "$OUT_GOOD"))"
ROUTE_LINES="$(awk 'BEGIN{c=0} /^route=/{c++} END{print c}' "$OUT_GOOD")"
[ "$ROUTE_LINES" -eq 1 ] || fail "expected exactly one stdout route= field, got ${ROUTE_LINES}"
grep -q '^route=minisig$' "$OUT_GOOD" || fail "positive minisig machine route missing"
grep -Eq 'anchor=legacy' "$OUT_GOOD" || fail "positive v0.4.11 should log anchor=legacy"
[ -f "$GOOD411/.stub-ran" ] || fail "installer should execute after successful verify"
[ -x "$GOOD411/sfetch" ] || fail "sfetch binary should be installed"
version_output_matches_pin "$("$GOOD411/sfetch" --version 2>&1)" "v0.4.11" || fail "stub sfetch version"
pass "positive v0.4.11 minisig route (patched ephemeral key)"

# Positive: v0.4.10 sha256sums route
GOOD410="$WORKDIR/good410"
mkdir -p "$GOOD410"
set +e
OUT_GOOD410="$WORKDIR/out-good410.txt"
"$PATCHED" --version v0.4.10 --dir "$GOOD410" >"$OUT_GOOD410" 2>&1
RC=$?
set -e
[ "$RC" -eq 0 ] || fail "positive v0.4.10 sha256sums should succeed (log: $(cat "$OUT_GOOD410"))"
[ "$(awk 'BEGIN{c=0} /^route=/{c++} END{print c}' "$OUT_GOOD410")" -eq 1 ] || fail "expected one route= field"
grep -q '^route=sha256sums$' "$OUT_GOOD410" || fail "positive sha256sums machine route missing"
grep -Eq 'anchor=legacy' "$OUT_GOOD410" || fail "positive v0.4.10 should log anchor=legacy"
[ -f "$GOOD410/.stub-ran" ] || fail "installer should execute after sha256sums verify"
pass "positive v0.4.10 sha256sums route (patched ephemeral key)"

# Negative: old pin must NOT use the current anchor (pin map, not fallback).
# Fixtures are TEST_PUBKEY-signed; patching only the current anchor leaves the
# selected legacy anchor at its production value, so verify must fail.
CURONLY_ENG="$WORKDIR/current-only-engine.sh"
make_fixture_engine "$CURONLY_ENG" "$BASE" "$TEST_PUBKEY" "SFETCH_MINISIGN_PUBKEY"
CURONLY_DIR="$WORKDIR/curonly"
mkdir -p "$CURONLY_DIR"
set +e
OUT_CURONLY="$WORKDIR/out-curonly.txt"
"$CURONLY_ENG" --version v0.4.11 --dir "$CURONLY_DIR" >"$OUT_CURONLY" 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "v0.4.11 against current-only patched engine must fail"
[ ! -f "$CURONLY_DIR/.stub-ran" ] || fail "installer must not run when pin selects unpatched anchor"
[ ! -f "$CURONLY_DIR/sfetch" ] || fail "sfetch must not be installed on failed verify"
grep -Eq 'anchor=legacy' "$OUT_CURONLY" || fail "expected anchor=legacy selection for v0.4.11"
if grep -q '^route=' "$OUT_CURONLY"; then fail "failed run must not emit machine route="; fi
pass "old pin ignores current anchor (no fallback)"

# Post-cutover selection: v0.4.13 is the production engine's accepted ceiling.
# Stand-in keys prove the rule: new pins use current, previous-key sigs fail.
NEWENG="$WORKDIR/newpin-engine.sh"
make_fixture_engine "$NEWENG" "$BASE" "$OLD_EPHEMERAL_PUBKEY" "SFETCH_MINISIGN_PUBKEY_LEGACY"
sed -i.bak "s|${PROD_PUBKEY}|${NEW_EPHEMERAL_PUBKEY}|g" "$NEWENG"
grep -q "$NEW_EPHEMERAL_PUBKEY" "$NEWENG" || fail "new-pin engine missing current stand-in"
grep -q "$PROD_PUBKEY" "$NEWENG" && fail "new-pin engine still has production current key"
grep -q "$OLD_EPHEMERAL_PUBKEY" "$NEWENG" || fail "new-pin engine lost legacy stand-in"
grep -q 'SFETCH_BOOTSTRAP_MAX="v0.4.13"' "$NEWENG" || fail "new-pin engine MAX drifted"

# Positive: post-cutover pin verifies against the current anchor.
minisign -S -s "$NEWKEY" -t "test-v0.4.13-new" -m "$SRV_ROOT/v0.4.13/install-sfetch.sh"
NEWGOOD_DIR="$WORKDIR/newgood"
mkdir -p "$NEWGOOD_DIR"
set +e
OUT_NEWGOOD="$WORKDIR/out-newgood.txt"
"$NEWENG" --version v0.4.13 --dir "$NEWGOOD_DIR" >"$OUT_NEWGOOD" 2>&1
RC=$?
set -e
[ "$RC" -eq 0 ] || fail "positive v0.4.13 should succeed (log: $(cat "$OUT_NEWGOOD"))"
[ "$(awk 'BEGIN{c=0} /^route=/{c++} END{print c}' "$OUT_NEWGOOD")" -eq 1 ] || fail "expected one route= field"
grep -q '^route=minisig$' "$OUT_NEWGOOD" || fail "positive v0.4.13 machine route missing"
grep -Eq 'anchor=current' "$OUT_NEWGOOD" || fail "positive v0.4.13 should log anchor=current"
[ -f "$NEWGOOD_DIR/.stub-ran" ] || fail "installer should execute after successful verify"
[ -x "$NEWGOOD_DIR/sfetch" ] || fail "sfetch binary should be installed"
version_output_matches_pin "$("$NEWGOOD_DIR/sfetch" --version 2>&1)" "v0.4.13" || fail "stub sfetch version"
pass "post-cutover pin uses current anchor"

# Negative: previous-key signature must fail for a post-cutover pin (no downgrade).
minisign -S -s "$OLDKEY" -t "test-v0.4.13-old" -m "$SRV_ROOT/v0.4.13/install-sfetch.sh"
NEWDOWNGRADE_DIR="$WORKDIR/newdowngrade"
mkdir -p "$NEWDOWNGRADE_DIR"
set +e
OUT_DOWNGRADE="$WORKDIR/out-downgrade.txt"
"$NEWENG" --version v0.4.13 --dir "$NEWDOWNGRADE_DIR" >"$OUT_DOWNGRADE" 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "previous-key signature for v0.4.13 must fail"
[ ! -f "$NEWDOWNGRADE_DIR/.stub-ran" ] || fail "installer must not run on downgrade attempt"
[ ! -f "$NEWDOWNGRADE_DIR/sfetch" ] || fail "sfetch must not be installed on failed verify"
grep -Eq 'anchor=current' "$OUT_DOWNGRADE" || fail "expected anchor=current selection for v0.4.13"
if grep -q '^route=' "$OUT_DOWNGRADE"; then fail "failed run must not emit machine route="; fi
pass "post-cutover pin rejects previous-key signature (no downgrade)"

# Negative: wrong-key minisig (production anchors engine against test-key sig)
WRONG_ENG="$WORKDIR/wrong-key-engine.sh"
make_fixture_engine "$WRONG_ENG" "$BASE" # keep production anchors
BAD_DIR="$WORKDIR/bad"
mkdir -p "$BAD_DIR"
set +e
OUTBAD="$WORKDIR/outbad.txt"
"$WRONG_ENG" --version v0.4.11 --dir "$BAD_DIR" >"$OUTBAD" 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "wrong-key minisig should fail"
[ ! -f "$BAD_DIR/.stub-ran" ] || fail "installer must not run before verify"
[ ! -f "$BAD_DIR/sfetch" ] || fail "sfetch must not be installed on failed verify"
grep -Eq 'verify-route=minisig' "$OUTBAD" || fail "expected minisig verify-route in log"
if grep -q '^route=' "$OUTBAD"; then fail "failed run must not emit machine route="; fi
pass "wrong-key minisig fails closed without executing installer"

# Negative: missing signature
NOSIG_ROOT="$WORKDIR/www-nosig"
mkdir -p "$NOSIG_ROOT/v0.4.11"
cp "$SRV_ROOT/v0.4.11/install-sfetch.sh" "$NOSIG_ROOT/v0.4.11/"
PORTFILE2="$WORKDIR/port2"
start_http_fixture "$NOSIG_ROOT" "$PORTFILE2"
SRV_PID2=$!
for _ in $(seq 1 50); do
    [ -f "$PORTFILE2" ] && break
    sleep 0.05
done
[ -f "$PORTFILE2" ] || fail "second HTTP fixture server failed to start"
PORT2="$(cat "$PORTFILE2")"
NOSIG_ENG="$WORKDIR/nosig-engine.sh"
make_fixture_engine "$NOSIG_ENG" "http://127.0.0.1:${PORT2}" "$TEST_PUBKEY" "SFETCH_MINISIGN_PUBKEY_LEGACY"
NOSIG_DIR="$WORKDIR/nosig"
mkdir -p "$NOSIG_DIR"
set +e
OUTNOSIG="$WORKDIR/out-nosig.txt"
"$NOSIG_ENG" --version v0.4.11 --dir "$NOSIG_DIR" >"$OUTNOSIG" 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "missing minisig should fail"
[ ! -f "$NOSIG_DIR/.stub-ran" ] || fail "installer must not run when sig missing"
pass "missing install-sfetch.sh.minisig fails closed"

# --- Action engine resolution: package root scripts/, never GITHUB_WORKSPACE ---
FAKE_PKG="$WORKDIR/fake-action-repo"
mkdir -p "$FAKE_PKG/.github/actions/setup-sfetch" "$FAKE_PKG/scripts"
cp "$SCRIPT" "$FAKE_PKG/scripts/bootstrap-sfetch-verified.sh"
chmod +x "$FAKE_PKG/scripts/bootstrap-sfetch-verified.sh"
HOSTILE_WS="$WORKDIR/hostile-ws"
mkdir -p "$HOSTILE_WS/scripts"
cat >"$HOSTILE_WS/scripts/bootstrap-sfetch-verified.sh" <<'HOSTILE'
#!/usr/bin/env bash
echo "HOSTILE_ENGINE_EXECUTED" >&2
printf 'route=minisig\n'
printf 'sfetch-bin=/tmp/evil\n'
exit 0
HOSTILE
chmod +x "$HOSTILE_WS/scripts/bootstrap-sfetch-verified.sh"

resolve_engine() {
    local GITHUB_ACTION_PATH="$1"
    local GITHUB_WORKSPACE="${2-}"
    local PACKAGE_ROOT ENGINE
    PACKAGE_ROOT="$(cd "${GITHUB_ACTION_PATH}/../../.." && pwd)"
    ENGINE="${PACKAGE_ROOT}/scripts/bootstrap-sfetch-verified.sh"
    if [ ! -f "${ENGINE}" ] || [ ! -r "${ENGINE}" ]; then
        echo "error: action-repo engine missing" >&2
        return 1
    fi
    ENGINE="$(cd "$(dirname "${ENGINE}")" && pwd)/$(basename "${ENGINE}")"
    case "${ENGINE}" in
        "${PACKAGE_ROOT}"/*) ;;
        *)
            echo "error: engine outside package root" >&2
            return 1
            ;;
    esac
    if [ -n "${GITHUB_WORKSPACE}" ]; then
        local WS_REAL
        WS_REAL="$(cd "${GITHUB_WORKSPACE}" && pwd)"
        if [ "${PACKAGE_ROOT}" != "${WS_REAL}" ]; then
            case "${ENGINE}" in
                "${WS_REAL}"/*)
                    echo "error: engine in consumer workspace" >&2
                    return 1
                    ;;
            esac
        fi
    fi
    printf '%s\n' "$ENGINE"
}

RESOLVED="$(resolve_engine "$FAKE_PKG/.github/actions/setup-sfetch" "$HOSTILE_WS")" ||
    fail "package-root resolve failed"
case "$RESOLVED" in
    *hostile*) fail "resolved engine under hostile workspace: $RESOLVED" ;;
esac
[ "$RESOLVED" = "$(cd "$FAKE_PKG/scripts" && pwd)/bootstrap-sfetch-verified.sh" ] ||
    fail "unexpected resolve path: $RESOLVED"
if resolve_engine "$WORKDIR/missing-action/nested/deep" "$HOSTILE_WS" 2>/dev/null; then
    fail "missing package engine must fail"
fi
pass "action resolves package-root scripts/ engine (hostile workspace ignored)"

# --- Action wrapper simulation: parse real successful engine stdout ---
SIM_OUT="$WORKDIR/sim-out.txt"
SIM_ERR="$WORKDIR/sim-err.txt"
"$PATCHED" --version v0.4.10 --dir "$WORKDIR/sim-install" >"$SIM_OUT" 2>"$SIM_ERR"
SIM_ROUTE_COUNT="$(awk 'BEGIN{c=0} /^route=/{c++} END{print c}' "$SIM_OUT")"
[ "$SIM_ROUTE_COUNT" -eq 1 ] || fail "action sim: expected one route= on stdout, got ${SIM_ROUTE_COUNT}"
SIM_ROUTE="$(awk -F= '/^route=/{print $2; exit}' "$SIM_OUT")"
[ "$SIM_ROUTE" = "sha256sums" ] || fail "action sim: route=$SIM_ROUTE"
SIM_BIN="$(awk -F= '/^sfetch-bin=/{print $2; exit}' "$SIM_OUT")"
[ -n "$SIM_BIN" ] && [ -f "$SIM_BIN" ] || fail "action sim: sfetch-bin missing"
grep -Eq 'verify-route=sha256sums' "$SIM_ERR" || fail "action sim: expected human verify-route log"
# Confirm action has no executable || true soft suppressions (comments OK).
if grep -n '|| true' "${ROOT}/.github/actions/setup-sfetch/action.yml" | grep -v '^\s*[0-9]*:\s*#'; then
    fail "action.yml must not contain || true outside comments"
fi
pass "action wrapper parses single stdout route= from successful engine run"

# Cleanup primary servers before goneat offline fixture
kill "$SRV_PID" 2>/dev/null || true
kill "$SRV_PID2" 2>/dev/null || true
wait "$SRV_PID" 2>/dev/null || true
wait "$SRV_PID2" 2>/dev/null || true
SRV_PID=""
SRV_PID2=""

# Negative: requested goneat fails closed
if [ "${SFETCH_BOOTSTRAP_LIVE:-0}" = "1" ] || [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    GONEAT_FAIL_DIR="$WORKDIR/goneat-fail"
    mkdir -p "$GONEAT_FAIL_DIR"
    set +e
    OUT_GF="$WORKDIR/out-goneat-fail.txt"
    "$SCRIPT" --version v0.4.10 --dir "$GONEAT_FAIL_DIR" --goneat-version v0.0.0 >"$OUT_GF" 2>&1
    RC=$?
    set -e
    [ "$RC" -ne 0 ] || fail "requested unavailable goneat must fail closed"
    pass "requested goneat v0.0.0 fails closed"
else
    make_stub_installer_fail_goneat() {
        local dest="$1"
        cat >"$dest" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
DIR=""
TAG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --yes|--require-minisign) shift ;;
    *) shift ;;
  esac
done
mkdir -p "${DIR}"
VER="${TAG#v}"
cat >"${DIR}/sfetch" <<EOF
#!/usr/bin/env bash
if [ "\${1-}" = "--version" ]; then
  echo "sfetch ${VER}"
  exit 0
fi
echo "stub sfetch: refusing non-version command" >&2
exit 1
EOF
chmod +x "${DIR}/sfetch"
STUB
        chmod +x "$dest"
    }
    GONEROOT="$WORKDIR/www-goneat"
    mkdir -p "$GONEROOT/v0.4.11"
    make_stub_installer_fail_goneat "$GONEROOT/v0.4.11/install-sfetch.sh"
    minisign -S -s "$KEY" -t "g" -m "$GONEROOT/v0.4.11/install-sfetch.sh"
    PORTFILE3="$WORKDIR/port3"
    start_http_fixture "$GONEROOT" "$PORTFILE3"
    SRV_PID=$!
    for _ in $(seq 1 50); do
        [ -f "$PORTFILE3" ] && break
        sleep 0.05
    done
    [ -f "$PORTFILE3" ] || fail "goneat HTTP fixture server failed to start"
    PORT3="$(cat "$PORTFILE3")"
    GONEAT_ENG="$WORKDIR/goneat-engine.sh"
    make_fixture_engine "$GONEAT_ENG" "http://127.0.0.1:${PORT3}" "$TEST_PUBKEY" "SFETCH_MINISIGN_PUBKEY_LEGACY"
    GONEAT_DIR="$WORKDIR/goneat-offline"
    mkdir -p "$GONEAT_DIR"
    set +e
    OUT_GO="$WORKDIR/out-goneat-offline.txt"
    "$GONEAT_ENG" --version v0.4.11 --dir "$GONEAT_DIR" --goneat-version v0.6.0 >"$OUT_GO" 2>&1
    RC=$?
    set -e
    [ "$RC" -ne 0 ] || fail "goneat install failure must fail closed (log: $(cat "$OUT_GO"))"
    pass "requested goneat fails closed when sfetch install of goneat fails"
fi

# Live install against published v0.4.10 when explicitly enabled or in GHA.
if [ "${SFETCH_BOOTSTRAP_LIVE:-0}" = "1" ] || [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    LIVE_DIR="$WORKDIR/live"
    mkdir -p "$LIVE_DIR"
    if "$SCRIPT" --version v0.4.10 --dir "$LIVE_DIR"; then
        version_output_matches_pin "$("$LIVE_DIR/sfetch" --version 2>&1)" "v0.4.10" || fail "live v0.4.10 version"
        pass "live v0.4.10 sha256sums route install"
    else
        fail "live v0.4.10 install failed"
    fi
else
    pass "skip live install (set SFETCH_BOOTSTRAP_LIVE=1 or GITHUB_ACTIONS=true to enable)"
fi

echo "[ok] bootstrap-sfetch-verified regression harness complete"
