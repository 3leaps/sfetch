#!/usr/bin/env bash
# Unit/fixture tests for bootstrap-sfetch-verified.sh (route selection, rejects, dual-route).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SCRIPT="${ROOT}/scripts/bootstrap-sfetch-verified.sh"
ACTION_ENGINE="${ROOT}/.github/actions/setup-sfetch/bootstrap-sfetch-verified.sh"
VERSION_MATCH="${ROOT}/scripts/version-matches-pin.sh"
[ -x "$SCRIPT" ] || chmod +x "$SCRIPT"
[ -x "$VERSION_MATCH" ] || chmod +x "$VERSION_MATCH"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

# --- Engine copy identity (action-owned must match scripts/ SSOT) ---
[ -f "$ACTION_ENGINE" ] || fail "action-owned engine missing: $ACTION_ENGINE"
cmp -s "$SCRIPT" "$ACTION_ENGINE" || fail "action engine diverged from scripts/bootstrap-sfetch-verified.sh"
pass "action engine identical to scripts SSOT"

# --- version-matches-pin exact token semantics ---
"$VERSION_MATCH" "sfetch 0.4.11" "v0.4.11" || fail "should match sfetch 0.4.11"
"$VERSION_MATCH" "sfetch version v0.4.11" "v0.4.11" || fail "should match v-prefixed"
if "$VERSION_MATCH" "sfetch 10x4y110" "v0.4.11"; then fail "must not soft-match 10x4y110"; fi
if "$VERSION_MATCH" "sfetch 10.4.11" "v0.4.11"; then fail "must not match inside 10.4.11"; fi
if "$VERSION_MATCH" "sfetch 0.4.110" "v0.4.11"; then fail "must not match 0.4.110"; fi
pass "version-matches-pin exact token rules"

# --- Version rejection (no network) ---
if "$SCRIPT" 2>/dev/null; then fail "should require --version"; else pass "requires --version"; fi
if "$SCRIPT" --version latest --dir /tmp 2>/dev/null; then fail "latest should fail"; else pass "rejects latest"; fi
if "$SCRIPT" --version main --dir /tmp 2>/dev/null; then fail "main should fail"; else pass "rejects main"; fi
if "$SCRIPT" --version v0.4.11-rc1 --dir /tmp 2>/dev/null; then fail "prerelease should fail"; else pass "rejects prerelease"; fi
if "$SCRIPT" --version v0.4.8 --dir /tmp 2>/dev/null; then fail "below min should fail"; else pass "rejects below min"; fi
if "$SCRIPT" --version v0.4.12 --dir /tmp 2>/dev/null; then fail "above max should fail"; else pass "rejects above max"; fi

# --- Route selection logging via dry parse ---
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

set +e
OUT1040="$WORKDIR/out410.txt"
SFETCH_BOOTSTRAP_BASE_URL="file://${WORKDIR}/empty" \
    "$SCRIPT" --version v0.4.10 --dir "$WORKDIR/d410" >"$OUT1040" 2>&1
set -e
grep -q 'route=sha256sums' "$OUT1040" || fail "v0.4.10 should select sha256sums route (log: $(cat "$OUT1040"))"
pass "v0.4.10 → route=sha256sums"

set +e
OUT411="$WORKDIR/out411.txt"
SFETCH_BOOTSTRAP_BASE_URL="file://${WORKDIR}/empty" \
    "$SCRIPT" --version v0.4.11 --dir "$WORKDIR/d411" >"$OUT411" 2>&1
set -e
grep -q 'route=minisig' "$OUT411" || fail "v0.4.11 should select minisig route (log: $(cat "$OUT411"))"
pass "v0.4.11 → route=minisig"

# --- Local dual-route fixtures with ephemeral minisign ---
command -v minisign >/dev/null 2>&1 || fail "minisign required"
command -v python3 >/dev/null 2>&1 || fail "python3 required for local HTTP fixture"

KEY="$WORKDIR/k.key"
PUB="$WORKDIR/k.pub"
minisign -G -W -p "$PUB" -s "$KEY" >/dev/null 2>&1 ||
    minisign -G -n -p "$PUB" -s "$KEY" >/dev/null 2>&1 ||
    fail "keygen"

# Extract the RW... public key line for embedding
TEST_PUBKEY="$(grep -E '^RW' "$PUB" | head -n1 | tr -d '\r\n')"
[ -n "$TEST_PUBKEY" ] || fail "could not read test pubkey"

# Patch a temporary engine copy: replace production trust anchor with test key
# (no production override seam — ephemeral patched copy only).
PROD_PUBKEY="RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC"
PATCHED="$WORKDIR/bootstrap-patched.sh"
sed "s|${PROD_PUBKEY}|${TEST_PUBKEY}|g" "$SCRIPT" >"$PATCHED"
chmod +x "$PATCHED"
grep -q "$TEST_PUBKEY" "$PATCHED" || fail "patched engine missing test pubkey"
grep -q "$PROD_PUBKEY" "$PATCHED" && fail "patched engine still has production pubkey"

# Local HTTP server root
SRV_ROOT="$WORKDIR/www"
mkdir -p "$SRV_ROOT/v0.4.11" "$SRV_ROOT/v0.4.10"

# Stub installer that creates a fake sfetch reporting the harness version
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

# Sign v0.4.11 installer with test key (minisig route)
minisign -S -s "$KEY" -t "test-v0.4.11" -m "$SRV_ROOT/v0.4.11/install-sfetch.sh"

# Sign v0.4.10 via SHA256SUMS route
(
    cd "$SRV_ROOT/v0.4.10"
    shasum -a 256 install-sfetch.sh >SHA256SUMS
)
minisign -S -s "$KEY" -t "test-v0.4.10" -m "$SRV_ROOT/v0.4.10/SHA256SUMS"

# Start HTTP fixture server without command substitution (bash subshells wait
# on background children, which would hang on serve_forever).
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
    # Caller reads $! after this function returns in the same shell.
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

# Positive: v0.4.11 minisig route with patched trust anchor
GOOD411="$WORKDIR/good411"
mkdir -p "$GOOD411"
set +e
OUT_GOOD="$WORKDIR/out-good411.txt"
SFETCH_BOOTSTRAP_BASE_URL="$BASE" \
    SFETCH_BOOTSTRAP_SKIP_MINISIGN_INSTALL=1 \
    "$PATCHED" --version v0.4.11 --dir "$GOOD411" >"$OUT_GOOD" 2>&1
RC=$?
set -e
[ "$RC" -eq 0 ] || fail "positive v0.4.11 minisig should succeed (log: $(cat "$OUT_GOOD"))"
grep -q 'route=minisig' "$OUT_GOOD" || fail "positive minisig route log missing"
[ -f "$GOOD411/.stub-ran" ] || fail "installer should execute after successful verify"
[ -x "$GOOD411/sfetch" ] || fail "sfetch binary should be installed"
"$GOOD411/sfetch" --version | grep -q '0.4.11' || fail "stub sfetch version"
pass "positive v0.4.11 minisig route (patched ephemeral key)"

# Positive: v0.4.10 sha256sums route with patched trust anchor
GOOD410="$WORKDIR/good410"
mkdir -p "$GOOD410"
set +e
OUT_GOOD410="$WORKDIR/out-good410.txt"
SFETCH_BOOTSTRAP_BASE_URL="$BASE" \
    SFETCH_BOOTSTRAP_SKIP_MINISIGN_INSTALL=1 \
    "$PATCHED" --version v0.4.10 --dir "$GOOD410" >"$OUT_GOOD410" 2>&1
RC=$?
set -e
[ "$RC" -eq 0 ] || fail "positive v0.4.10 sha256sums should succeed (log: $(cat "$OUT_GOOD410"))"
grep -q 'route=sha256sums' "$OUT_GOOD410" || fail "positive sha256sums route log missing"
[ -f "$GOOD410/.stub-ran" ] || fail "installer should execute after sha256sums verify"
pass "positive v0.4.10 sha256sums route (patched ephemeral key)"

# Negative: wrong-key minisig fails closed without executing installer
# Serve production-key-expected path: use UNPATCHED script against test-key sig
BAD_DIR="$WORKDIR/bad"
mkdir -p "$BAD_DIR"
set +e
OUTBAD="$WORKDIR/outbad.txt"
SFETCH_BOOTSTRAP_BASE_URL="$BASE" \
    SFETCH_BOOTSTRAP_SKIP_MINISIGN_INSTALL=1 \
    "$SCRIPT" --version v0.4.11 --dir "$BAD_DIR" >"$OUTBAD" 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "wrong-key minisig should fail"
[ ! -f "$BAD_DIR/.stub-ran" ] || fail "installer must not run before verify"
[ ! -f "$BAD_DIR/sfetch" ] || fail "sfetch must not be installed on failed verify"
grep -q 'route=minisig' "$OUTBAD" || fail "expected minisig route in log"
pass "wrong-key minisig fails closed without executing installer"

# Negative: missing signature asset fails closed
mkdir -p "$SRV_ROOT/v0.4.11-nosig"
cp "$SRV_ROOT/v0.4.11/install-sfetch.sh" "$SRV_ROOT/v0.4.11-nosig/"
# No .minisig
# Re-map by using a version that selects minisig but only has installer —
# supported max is v0.4.11 only, so use empty BASE subdir via another port root.
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
NOSIG_DIR="$WORKDIR/nosig"
mkdir -p "$NOSIG_DIR"
set +e
OUTNOSIG="$WORKDIR/out-nosig.txt"
SFETCH_BOOTSTRAP_BASE_URL="http://127.0.0.1:${PORT2}" \
    SFETCH_BOOTSTRAP_SKIP_MINISIGN_INSTALL=1 \
    "$PATCHED" --version v0.4.11 --dir "$NOSIG_DIR" >"$OUTNOSIG" 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "missing minisig should fail"
[ ! -f "$NOSIG_DIR/.stub-ran" ] || fail "installer must not run when sig missing"
pass "missing install-sfetch.sh.minisig fails closed"

# --- Action engine resolution simulation (no GITHUB_WORKSPACE fallback) ---
# Simulate: GITHUB_ACTION_PATH has real engine; workspace has hostile same-named script.
HOSTILE_WS="$WORKDIR/hostile-ws"
mkdir -p "$HOSTILE_WS/scripts" "$WORKDIR/action-path"
cp "$ACTION_ENGINE" "$WORKDIR/action-path/bootstrap-sfetch-verified.sh"
cat >"$HOSTILE_WS/scripts/bootstrap-sfetch-verified.sh" <<'HOSTILE'
#!/usr/bin/env bash
echo "HOSTILE_ENGINE_EXECUTED" >&2
echo "route=minisig" >&2
echo "sfetch-bin=/tmp/evil"
exit 0
HOSTILE
chmod +x "$HOSTILE_WS/scripts/bootstrap-sfetch-verified.sh" \
    "$WORKDIR/action-path/bootstrap-sfetch-verified.sh"

# Resolution logic mirrored from action.yml (must only use ACTION_PATH)
resolve_engine() {
    local ACTION_ROOT="$1"
    local ENGINE="${ACTION_ROOT}/bootstrap-sfetch-verified.sh"
    if [ ! -f "${ENGINE}" ] || [ ! -r "${ENGINE}" ]; then
        echo "error: action-owned engine missing" >&2
        return 1
    fi
    ENGINE="$(cd "$(dirname "${ENGINE}")" && pwd)/$(basename "${ENGINE}")"
    case "${ENGINE}" in
        "${ACTION_ROOT}"/* | "$(cd "${ACTION_ROOT}" && pwd)"/*) ;;
        *)
            echo "error: engine outside ACTION_PATH" >&2
            return 1
            ;;
    esac
    printf '%s\n' "$ENGINE"
}

RESOLVED="$(resolve_engine "$WORKDIR/action-path")" || fail "action-path resolve failed"
case "$RESOLVED" in
    *hostile*) fail "resolved engine under hostile workspace: $RESOLVED" ;;
esac
# Confirm hostile would not be chosen even if WORKSPACE were preferred by old bug
[ -f "$HOSTILE_WS/scripts/bootstrap-sfetch-verified.sh" ] || fail "hostile fixture missing"
# If we only resolve under action path, running it must not print HOSTILE
OUT_RES="$WORKDIR/resolve-out.txt"
# Don't actually run full bootstrap — just confirm path identity
[ "$RESOLVED" = "$(cd "$WORKDIR/action-path" && pwd)/bootstrap-sfetch-verified.sh" ] ||
    fail "unexpected resolve path: $RESOLVED"
# Missing action engine must fail (no workspace fallback)
if resolve_engine "$WORKDIR/missing-action" 2>/dev/null; then
    fail "missing action engine must fail"
fi
pass "action engine resolves only under GITHUB_ACTION_PATH (hostile workspace ignored)"

# Cleanup servers
kill "$SRV_PID" 2>/dev/null || true
kill "$SRV_PID2" 2>/dev/null || true
wait "$SRV_PID" 2>/dev/null || true
wait "$SRV_PID2" 2>/dev/null || true

# Negative: requested goneat with impossible tag fails closed (no soft skip).
# Uses live N-1 sfetch install then fails on goneat — only when network allowed.
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
    # Offline unit: install stub sfetch then invoke goneat path by re-using stub dir
    # with a fake sfetch that fails on goneat fetch — covered by engine's || die path.
    # Explicit offline simulation: engine with BASE_URL fixture installs sfetch stub,
    # then fails when goneat install is requested (sfetch binary is a stub that exits 1).
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
# Fake sfetch: report version OK; any other invocation fails (goneat install).
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
    SRV_PID3=$!
    for _ in $(seq 1 50); do
        [ -f "$PORTFILE3" ] && break
        sleep 0.05
    done
    [ -f "$PORTFILE3" ] || fail "goneat HTTP fixture server failed to start"
    PORT3="$(cat "$PORTFILE3")"
    GONEAT_DIR="$WORKDIR/goneat-offline"
    mkdir -p "$GONEAT_DIR"
    set +e
    OUT_GO="$WORKDIR/out-goneat-offline.txt"
    SFETCH_BOOTSTRAP_BASE_URL="http://127.0.0.1:${PORT3}" \
        SFETCH_BOOTSTRAP_SKIP_MINISIGN_INSTALL=1 \
        "$PATCHED" --version v0.4.11 --dir "$GONEAT_DIR" --goneat-version v0.5.15 >"$OUT_GO" 2>&1
    RC=$?
    set -e
    kill "$SRV_PID3" 2>/dev/null || true
    wait "$SRV_PID3" 2>/dev/null || true
    [ "$RC" -ne 0 ] || fail "goneat install failure must fail closed (log: $(cat "$OUT_GO"))"
    pass "requested goneat fails closed when sfetch install of goneat fails"
fi

# Live install against published v0.4.10 when explicitly enabled or in GHA.
if [ "${SFETCH_BOOTSTRAP_LIVE:-0}" = "1" ] || [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    LIVE_DIR="$WORKDIR/live"
    mkdir -p "$LIVE_DIR"
    if "$SCRIPT" --version v0.4.10 --dir "$LIVE_DIR"; then
        "$VERSION_MATCH" "$("$LIVE_DIR/sfetch" --version 2>&1)" "v0.4.10" || fail "live v0.4.10 version"
        pass "live v0.4.10 sha256sums route install"
    else
        fail "live v0.4.10 install failed"
    fi
else
    pass "skip live install (set SFETCH_BOOTSTRAP_LIVE=1 or GITHUB_ACTIONS=true to enable)"
fi

echo "[ok] bootstrap-sfetch-verified regression harness complete"
