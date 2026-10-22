#!/usr/bin/env bash
# Regression: Makefile LDFLAGS inject version/commit into the binary.
# Copies the artifact outside the repo, sets cwd+HOME to that dir, and
# asserts `version`, `--version`, and `version --extended`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

VERSION="$(tr -d '[:space:]' < VERSION)"
[[ -n "$VERSION" && "$VERSION" != "dev" ]] || fail "VERSION file is ${VERSION:-empty}"

GOOS="$(go env GOOS)"
GOARCH="$(go env GOARCH)"
EXT=""
if [[ "$GOOS" == "windows" ]]; then
    EXT=".exe"
fi

BIN=""
PACKAGED=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin)
            [[ $# -ge 2 ]] || fail "--bin requires a path"
            BIN="$2"
            shift 2
            ;;
        --packaged)
            PACKAGED=1
            shift
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

if [[ -z "$BIN" ]]; then
    make -s build
    BIN="bin/sfetch_${GOOS}_${GOARCH}${EXT}"
fi
[[ -f "$BIN" ]] || fail "binary not found: $BIN"

ISOLATED="$(mktemp -d)"
trap 'rm -rf "$ISOLATED"' EXIT
HOME_DIR="$ISOLATED/home"
mkdir -p "$HOME_DIR"

if [[ "$PACKAGED" -eq 1 ]]; then
    STAGE="$ISOLATED/pkg"
    mkdir -p "$STAGE"
    cp "$BIN" "$STAGE/sfetch${EXT}"
    chmod +x "$STAGE/sfetch${EXT}"
    ARCHIVE="$ISOLATED/sfetch_${GOOS}_${GOARCH}"
    if [[ "$GOOS" == "windows" ]]; then
        ARCHIVE="${ARCHIVE}.zip"
        if command -v zip >/dev/null 2>&1; then
            (cd "$STAGE" && zip -q "$ARCHIVE" "sfetch${EXT}")
        else
            python3 -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w",zipfile.ZIP_DEFLATED); z.write(sys.argv[2], sys.argv[3]); z.close()' \
                "$ARCHIVE" "$STAGE/sfetch${EXT}" "sfetch${EXT}"
        fi
        EXTRACT="$ISOLATED/extract"
        mkdir -p "$EXTRACT"
        python3 -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$ARCHIVE" "$EXTRACT"
    else
        ARCHIVE="${ARCHIVE}.tar.gz"
        tar -czf "$ARCHIVE" -C "$STAGE" "sfetch${EXT}"
        EXTRACT="$ISOLATED/extract"
        mkdir -p "$EXTRACT"
        tar -xzf "$ARCHIVE" -C "$EXTRACT"
    fi
    RUN_BIN="$EXTRACT/sfetch${EXT}"
    RUN_DIR="$EXTRACT"
    pass "packaged $(basename "$ARCHIVE")"
else
    RUN_DIR="$ISOLATED/bin"
    mkdir -p "$RUN_DIR"
    cp "$BIN" "$RUN_DIR/sfetch${EXT}"
    chmod +x "$RUN_DIR/sfetch${EXT}"
    RUN_BIN="$RUN_DIR/sfetch${EXT}"
fi

[[ -x "$RUN_BIN" || -f "$RUN_BIN" ]] || fail "run binary missing: $RUN_BIN"

run_cmd() {
    local errf out
    errf="$(mktemp "$ISOLATED/err.XXXXXX")"
    out="$(cd "$RUN_DIR" && HOME="$HOME_DIR" USERPROFILE="$HOME_DIR" "$RUN_BIN" "$@" 2>"$errf")" || {
        fail "$* failed: $(cat "$errf") stdout=$out"
    }
    if [[ -s "$errf" ]]; then
        fail "$* wrote stderr: $(cat "$errf")"
    fi
    printf '%s' "$out"
}

check_short() {
    local label="$1"
    shift
    local out
    out="$(run_cmd "$@")"
    [[ "$out" == "sfetch ${VERSION}" || "$out" == "sfetch ${VERSION}"$'\n' || "$out" == "sfetch ${VERSION}"$'\r\n' ]] ||
        fail "$label stdout=$out want 'sfetch ${VERSION}'"
    [[ "$out" != *'sfetch dev'* ]] || fail "$label output is uninjected dev"
    pass "$label contains ${VERSION} on stdout"
}

check_short "version" version
check_short "--version" --version

EXTENDED="$(run_cmd version --extended)"
[[ "$EXTENDED" == *"sfetch ${VERSION}"* ]] || fail "extended missing version: $EXTENDED"
[[ "$EXTENDED" != *'sfetch dev'* ]] || fail "extended output is uninjected dev"
[[ "$EXTENDED" == *'git commit:'* ]] || fail "extended missing git commit: $EXTENDED"
[[ "$EXTENDED" != *'git commit: unknown'* ]] || fail "commit is unknown: $EXTENDED"
[[ "$EXTENDED" == *'build time:'* ]] || fail "extended missing build time: $EXTENDED"
[[ "$EXTENDED" == *'go version:'* ]] || fail "extended missing go version: $EXTENDED"
[[ "$EXTENDED" == *'os/arch:'* ]] || fail "extended missing os/arch: $EXTENDED"
pass "version --extended commit is not unknown"
