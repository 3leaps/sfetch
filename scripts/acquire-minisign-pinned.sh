#!/usr/bin/env bash
# acquire-minisign-pinned.sh — install official minisign 0.12 with hash verification.
#
# Usage: acquire-minisign-pinned.sh --dir PATH
# Installs minisign (or minisign.exe on Windows) into PATH directory.
# Always downloads the pinned upstream archive; never prefers ambient PATH tools.
#
# Constants must stay aligned with scripts/bootstrap-sfetch-verified.sh.
set -euo pipefail

readonly MINISIGN_VERSION_EXPECTED="0.12"
readonly MINISIGN_WIN_URL="https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-win64.zip"
readonly MINISIGN_WIN_SHA256="37b600344e20c19314b2e82813db2bfdcc408b77b876f7727889dbd46d539479"
readonly MINISIGN_MAC_URL="https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-macos.zip"
readonly MINISIGN_MAC_SHA256="89000b19535765f9cffc65a65d64a820f433ef6db8020667f7570e06bf6aac63"
readonly MINISIGN_LINUX_URL="https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-linux.tar.gz"
readonly MINISIGN_LINUX_SHA256="9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73"

DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --dir)
            [ $# -ge 2 ] || {
                echo "error: --dir requires an argument" >&2
                exit 1
            }
            DIR="$2"
            shift 2
            ;;
        -h | --help)
            echo "Usage: acquire-minisign-pinned.sh --dir PATH" >&2
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            exit 1
            ;;
    esac
done

[ -n "$DIR" ] || {
    echo "error: --dir is required" >&2
    exit 1
}
mkdir -p "$DIR"
DIR="$(cd "$DIR" && pwd)"

die() {
    echo "error: $*" >&2
    exit 1
}
log() { printf '%s\n' "$*" >&2; }

detect_os() {
    case "$(uname -s 2>/dev/null || echo unknown)" in
        Linux*) echo linux ;;
        Darwin*) echo darwin ;;
        MINGW* | MSYS* | CYGWIN* | Windows_NT) echo windows ;;
        *)
            if [ -n "${RUNNER_OS:-}" ]; then
                case "${RUNNER_OS}" in
                    Windows) echo windows ;;
                    Linux) echo linux ;;
                    macOS) echo darwin ;;
                    *) die "unsupported OS: ${RUNNER_OS}" ;;
                esac
            else
                die "unsupported OS: $(uname -s 2>/dev/null || echo unknown)"
            fi
            ;;
    esac
}

detect_arch() {
    if [ -n "${RUNNER_ARCH:-}" ]; then
        case "${RUNNER_ARCH}" in
            X64 | x64 | AMD64 | amd64)
                echo x86_64
                return
                ;;
            ARM64 | arm64)
                echo aarch64
                return
                ;;
            *) die "unsupported RUNNER_ARCH: ${RUNNER_ARCH}" ;;
        esac
    fi
    local m
    m="$(uname -m 2>/dev/null || echo unknown)"
    case "$m" in
        x86_64 | amd64) echo x86_64 ;;
        aarch64 | arm64) echo aarch64 ;;
        *) die "unsupported architecture: $m" ;;
    esac
}

http_get() {
    local url="$1" out="$2"
    local attempt=1 max=4
    while [ "$attempt" -le "$max" ]; do
        if command -v curl >/dev/null 2>&1; then
            if curl -fsSL --retry 2 --retry-delay 1 --connect-timeout 15 --max-time 120 \
                -o "$out" "$url"; then
                return 0
            fi
        elif command -v wget >/dev/null 2>&1; then
            if wget -q -O "$out" "$url"; then
                return 0
            fi
        else
            die "curl or wget is required"
        fi
        log "fetch attempt ${attempt}/${max} failed: $url"
        attempt=$((attempt + 1))
        sleep 1
    done
    die "failed to fetch after ${max} attempts: $url"
}

sha256_file() {
    local f="$1"
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$f" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$f" | awk '{print $1}'
    else
        die "shasum or sha256sum required"
    fi
}

assert_sha256() {
    local f="$1" expect="$2"
    local got
    got="$(sha256_file "$f")"
    if [ "$got" != "$expect" ]; then
        die "SHA-256 mismatch for $(basename "$f"): expected ${expect}, got ${got}"
    fi
}

OS="$(detect_os)"
ARCH="$(detect_arch)"

if [ "$OS" = "darwin" ] && [ "$ARCH" = "x86_64" ]; then
    die "macOS x86_64 is not supported by the pinned minisign 0.12 macOS archive (arm64-only)"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/minisign-acquire.XXXXXX")"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

case "$OS" in
    windows)
        zip="${WORK}/minisign-win.zip"
        http_get "$MINISIGN_WIN_URL" "$zip"
        assert_sha256 "$zip" "$MINISIGN_WIN_SHA256"
        if command -v unzip >/dev/null 2>&1; then
            unzip -q -o "$zip" -d "${WORK}/extract"
        else
            powershell.exe -NoProfile -Command \
                "Expand-Archive -LiteralPath '$zip' -DestinationPath '${WORK}/extract' -Force" ||
                die "failed to extract minisign zip"
        fi
        case "$ARCH" in
            x86_64) sub="x86_64" ;;
            aarch64) sub="aarch64" ;;
            *) die "unsupported Windows arch: $ARCH" ;;
        esac
        src="${WORK}/extract/minisign-win64/${sub}/minisign.exe"
        [ -f "$src" ] || die "minisign.exe not found at $src"
        cp "$src" "${DIR}/minisign.exe"
        BIN="${DIR}/minisign.exe"
        ;;
    darwin)
        zip="${WORK}/minisign-mac.zip"
        http_get "$MINISIGN_MAC_URL" "$zip"
        assert_sha256 "$zip" "$MINISIGN_MAC_SHA256"
        unzip -q -o "$zip" -d "${WORK}/extract"
        [ -f "${WORK}/extract/minisign" ] || die "minisign binary missing from macOS archive"
        cp "${WORK}/extract/minisign" "${DIR}/minisign"
        chmod 0755 "${DIR}/minisign"
        BIN="${DIR}/minisign"
        ;;
    linux)
        tgz="${WORK}/minisign-linux.tar.gz"
        http_get "$MINISIGN_LINUX_URL" "$tgz"
        assert_sha256 "$tgz" "$MINISIGN_LINUX_SHA256"
        mkdir -p "${WORK}/extract"
        tar -xzf "$tgz" -C "${WORK}/extract"
        case "$ARCH" in
            x86_64) sub="x86_64" ;;
            aarch64) sub="aarch64" ;;
            *) die "unsupported Linux arch: $ARCH" ;;
        esac
        src="${WORK}/extract/minisign-linux/${sub}/minisign"
        [ -f "$src" ] || die "minisign not found at $src"
        cp "$src" "${DIR}/minisign"
        chmod 0755 "${DIR}/minisign"
        BIN="${DIR}/minisign"
        ;;
    *)
        die "unsupported OS for minisign install: $OS"
        ;;
esac

out="$("$BIN" -v 2>&1 | head -n1 || true)"
# Exact token match for version (not substring)
esc="$(printf '%s' "$MINISIGN_VERSION_EXPECTED" | sed 's/\./\\./g')"
printf '%s\n' "$out" | grep -Eq "(^|[^0-9])${esc}([^0-9]|$)" ||
    die "minisign version assertion failed (want exact ${MINISIGN_VERSION_EXPECTED}): ${out}"

log "minisign ready: ${BIN} (${out})"
printf 'minisign-bin=%s\n' "$BIN"
