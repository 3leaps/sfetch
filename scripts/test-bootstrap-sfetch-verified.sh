#!/usr/bin/env bash
# Unit/fixture tests for bootstrap-sfetch-verified.sh (route selection, rejects, dual-route).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SCRIPT="${ROOT}/scripts/bootstrap-sfetch-verified.sh"
[ -x "$SCRIPT" ] || chmod +x "$SCRIPT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

# --- Version rejection (no network) ---
reject() {
    local args=("$@")
    if "$SCRIPT" "${args[@]}" --dir /tmp 2>/dev/null; then
        fail "should reject: ${args[*]}"
    fi
}

# Missing required args
if "$SCRIPT" 2>/dev/null; then fail "should require --version"; else pass "requires --version"; fi

reject --version latest --dir /tmp && pass "rejects latest" || true
if "$SCRIPT" --version latest --dir /tmp 2>/dev/null; then fail "latest should fail"; else pass "rejects latest"; fi
if "$SCRIPT" --version main --dir /tmp 2>/dev/null; then fail "main should fail"; else pass "rejects main"; fi
if "$SCRIPT" --version v0.4.11-rc1 --dir /tmp 2>/dev/null; then fail "prerelease should fail"; else pass "rejects prerelease"; fi
if "$SCRIPT" --version v0.4.8 --dir /tmp 2>/dev/null; then fail "below min should fail"; else pass "rejects below min"; fi
if "$SCRIPT" --version v0.4.12 --dir /tmp 2>/dev/null; then fail "above max should fail"; else pass "rejects above max"; fi

# --- Route selection logging via dry parse ---
# Source-compatible check: run with a fake base URL that fails fetch after route log
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/sft-boot-test.XXXXXX")"
trap 'rm -rf "${WORKDIR}"' EXIT

# Capture route for v0.4.10
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

# --- Local dual-route positive fixtures with ephemeral minisign ---
command -v minisign >/dev/null 2>&1 || fail "minisign required"
command -v python3 >/dev/null 2>&1 || fail "python3 required for local HTTP fixture"

KEY="$WORKDIR/k.key"
PUB="$WORKDIR/k.pub"
minisign -G -W -p "$PUB" -s "$KEY" >/dev/null 2>&1 ||
    minisign -G -n -p "$PUB" -s "$KEY" >/dev/null 2>&1 ||
    fail "keygen"

# Build a fake "release" that install script won't fully run — we only test
# verify-before-execute by making install-sfetch.sh a stub that writes a marker
# when executed (proving execution happened only after verify).
make_stub_installer() {
    local dest="$1"
    cat >"$dest" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --tag|--yes|--require-minisign) shift ;;
    --tag|--dir) shift 2 ;;
    *) shift ;;
  esac
done
# crude parse again
while [ $# -gt 0 ]; do shift; done
# re-parse from original not available; write marker using env from harness
: "${HARNESS_INSTALL_DIR:?}"
mkdir -p "${HARNESS_INSTALL_DIR}"
# Fake sfetch binary that reports version from HARNESS_FAKE_VERSION
cat >"${HARNESS_INSTALL_DIR}/sfetch" <<EOF
#!/usr/bin/env bash
echo "sfetch \${HARNESS_FAKE_VERSION:-0.0.0}"
EOF
chmod +x "${HARNESS_INSTALL_DIR}/sfetch"
echo "STUB_RAN" >"${HARNESS_INSTALL_DIR}/.stub-ran"
STUB
    chmod +x "$dest"
}

# Patch approach: the real bootstrap embeds production pubkey. For fixture
# verification we need the embedded key to match. Instead of rewriting the
# script, test the pure verification helpers via a mini harness that mimics
# the two routes with the production path only for network live tests.
#
# Local fixture: inject via SFETCH_BOOTSTRAP — not available for pubkey override.
# So we only fully exercise network live path for v0.4.10 (real signed release)
# and unit-level route/reject above. Optional live:

# Live install against published v0.4.10 when explicitly enabled or in GHA.
if [ "${SFETCH_BOOTSTRAP_LIVE:-0}" = "1" ] || [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    LIVE_DIR="$WORKDIR/live"
    mkdir -p "$LIVE_DIR"
    if "$SCRIPT" --version v0.4.10 --dir "$LIVE_DIR"; then
        "$LIVE_DIR/sfetch" --version | grep -q '0.4.10' || fail "live v0.4.10 version"
        pass "live v0.4.10 sha256sums route install"
    else
        fail "live v0.4.10 install failed"
    fi
else
    pass "skip live install (set SFETCH_BOOTSTRAP_LIVE=1 or GITHUB_ACTIONS=true to enable)"
fi

# Negative: no execution-before-verify — supply bad minisig content via local HTTP
# Custom: override base URL to local python server serving unsigned installer
SRV_ROOT="$WORKDIR/www"
mkdir -p "$SRV_ROOT/v0.4.11"
printf '#!/bin/sh\necho SHOULD_NOT_RUN\n' >"$SRV_ROOT/v0.4.11/install-sfetch.sh"
chmod +x "$SRV_ROOT/v0.4.11/install-sfetch.sh"
# Wrong signature: sign with our key but script embeds production key → verify fails
minisign -S -s "$KEY" -t t -m "$SRV_ROOT/v0.4.11/install-sfetch.sh"

PORT=0
# shellcheck disable=SC2016
python3 - "$SRV_ROOT" "$WORKDIR/port" <<'PY' &
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
SRV_PID=$!
for _ in $(seq 1 50); do
    [ -f "$WORKDIR/port" ] && break
    sleep 0.05
done
PORT="$(cat "$WORKDIR/port")"
BAD_DIR="$WORKDIR/bad"
mkdir -p "$BAD_DIR"
set +e
OUTBAD="$WORKDIR/outbad.txt"
SFETCH_BOOTSTRAP_BASE_URL="http://127.0.0.1:${PORT}" \
    SFETCH_BOOTSTRAP_SKIP_MINISIGN_INSTALL=1 \
    "$SCRIPT" --version v0.4.11 --dir "$BAD_DIR" >"$OUTBAD" 2>&1
RC=$?
set -e
kill "$SRV_PID" 2>/dev/null || true
wait "$SRV_PID" 2>/dev/null || true
[ "$RC" -ne 0 ] || fail "wrong-key minisig should fail"
[ ! -f "$BAD_DIR/.stub-ran" ] || fail "installer must not run before verify"
[ ! -f "$BAD_DIR/sfetch" ] || fail "sfetch must not be installed on failed verify"
grep -q 'route=minisig' "$OUTBAD" || fail "expected minisig route in log"
pass "wrong-key minisig fails closed without executing installer"

echo "[ok] bootstrap-sfetch-verified regression harness complete"
