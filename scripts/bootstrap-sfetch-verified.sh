#!/usr/bin/env bash
# bootstrap-sfetch-verified.sh — verified sfetch install for Makefile / CI
#
# Fail-closed dual-route bootstrap:
#   - v0.4.11+  → detached install-sfetch.sh.minisig (3-step)
#   - earlier   → SHA256SUMS + SHA256SUMS.minisig + installer hash (5-step)
#
# Never falls back from a failed .minisig attempt to checksums.
# Never accepts "latest", branches, or floating refs.
# Trust anchor is embedded here — never fetched from the release being authenticated.
#
# Usage:
#   bootstrap-sfetch-verified.sh --version v0.4.11 --dir ~/.local/bin
#   bootstrap-sfetch-verified.sh --version v0.4.10 --dir ./bin --goneat-version v0.5.15
#   bootstrap-sfetch-verified.sh --acquire-minisign-only --dir PATH
#
# No runtime env overrides for trust-critical paths (download base, minisign
# acquisition). Production always uses GitHub release URLs and always downloads
# the hash-pinned official minisign 0.12 archive. Local harnesses patch a
# temporary copy of this script for fixture URLs / ambient minisign.
#
# Makefile consumers outside this repo should retrieve this script at an
# immutable git SHA and verify a pinned SHA-256 of the script before executing
# it (see docs/cicd-usage-guide.md). The composite action is a thin wrapper:
# it resolves this single canonical engine from the action repository checkout
# at scripts/bootstrap-sfetch-verified.sh (never from the consumer workspace).
#
set -euo pipefail

# -----------------------------------------------------------------------------
# Contract constants (bump deliberately when expanding support)
# -----------------------------------------------------------------------------
# Supported sfetch-version range for THIS script revision. Outside range ⇒ fail.
# Action SHA identifies this contract; consumers pin the action/script, then a
# version within the range it declares.
readonly SFETCH_BOOTSTRAP_MIN="v0.4.9"
readonly SFETCH_BOOTSTRAP_MAX="v0.4.11"
# First release that publishes install-sfetch.sh.minisig
readonly SFETCH_MINISIG_SINCE="v0.4.11"

# Embedded trust anchor — must match EmbeddedMinisignPubkey in main.go and
# scripts/install-sfetch.sh. Do NOT fetch sfetch-minisign.pub from the release
# for authentication (circular: same origin as the artifact under test).
# The published .pub is for human out-of-band comparison only.
readonly SFETCH_MINISIGN_PUBKEY="RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC"

readonly MINISIGN_VERSION_EXPECTED="0.12"
readonly MINISIGN_WIN_URL="https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-win64.zip"
readonly MINISIGN_WIN_SHA256="37b600344e20c19314b2e82813db2bfdcc408b77b876f7727889dbd46d539479"
readonly MINISIGN_MAC_URL="https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-macos.zip"
readonly MINISIGN_MAC_SHA256="89000b19535765f9cffc65a65d64a820f433ef6db8020667f7570e06bf6aac63"
readonly MINISIGN_LINUX_URL="https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-linux.tar.gz"
readonly MINISIGN_LINUX_SHA256="9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73"

readonly SFETCH_REPO_DEFAULT="3leaps/sfetch"

# -----------------------------------------------------------------------------
# Logging / errors
# -----------------------------------------------------------------------------
log() { printf '%s\n' "$*" >&2; }
die() {
    log "error: $*"
    exit 1
}

# -----------------------------------------------------------------------------
# Semver helpers (tags must be vMAJOR.MINOR.PATCH, optional -prerelease rejected)
# -----------------------------------------------------------------------------
is_exact_semver_tag() {
    case "$1" in
        v[0-9]*.[0-9]*.[0-9]*)
            # Reject extra suffix (pre-release / build) and non-numeric parts
            [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
            ;;
        *) return 1 ;;
    esac
}

# Compare two vX.Y.Z tags: echo -1 / 0 / 1 for a<b / a==b / a>b
semver_cmp() {
    local a="${1#v}" b="${2#v}"
    local a1 a2 a3 b1 b2 b3
    IFS=. read -r a1 a2 a3 <<<"$a"
    IFS=. read -r b1 b2 b3 <<<"$b"
    if ((a1 != b1)); then
        if ((a1 < b1)); then echo -1; else echo 1; fi
        return
    fi
    if ((a2 != b2)); then
        if ((a2 < b2)); then echo -1; else echo 1; fi
        return
    fi
    if ((a3 != b3)); then
        if ((a3 < b3)); then echo -1; else echo 1; fi
        return
    fi
    echo 0
}

semver_ge() { [[ "$(semver_cmp "$1" "$2")" != "-1" ]]; }
semver_le() { [[ "$(semver_cmp "$1" "$2")" != "1" ]]; }

# -----------------------------------------------------------------------------
# Args
# -----------------------------------------------------------------------------
VERSION=""
INSTALL_DIR=""
GONEAT_VERSION=""
REPO="${SFETCH_REPO_DEFAULT}"
ACQUIRE_MINISIGN_ONLY=0
usage() {
    cat <<'EOF' >&2
Usage: bootstrap-sfetch-verified.sh --version vX.Y.Z --dir PATH [options]
   or: bootstrap-sfetch-verified.sh --acquire-minisign-only --dir PATH

Required (install mode):
  --version TAG     Exact immutable tag (e.g. v0.4.11). Rejects latest/branches.
  --dir PATH        Install directory for sfetch (and optional goneat)

Required (acquire-minisign-only mode):
  --dir PATH        Directory to install pinned minisign 0.12 into

Optional:
  --goneat-version TAG   Exact goneat tag to install via verified sfetch
  --repo owner/name      GitHub repo (default: 3leaps/sfetch)
  --yes                  Non-interactive (always on for this script; accepted for CLI parity)
  --acquire-minisign-only  Only install pinned minisign (shared acquisition path for CI)
  -h, --help             Show help
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            [ $# -ge 2 ] || die "--version requires an argument"
            VERSION="$2"
            shift 2
            ;;
        --dir)
            [ $# -ge 2 ] || die "--dir requires an argument"
            INSTALL_DIR="$2"
            shift 2
            ;;
        --goneat-version)
            [ $# -ge 2 ] || die "--goneat-version requires an argument"
            GONEAT_VERSION="$2"
            shift 2
            ;;
        --repo)
            [ $# -ge 2 ] || die "--repo requires an argument"
            REPO="$2"
            shift 2
            ;;
        --acquire-minisign-only)
            ACQUIRE_MINISIGN_ONLY=1
            shift
            ;;
        --yes)
            # Accepted for CLI parity with install-sfetch.sh (always non-interactive).
            shift
            ;;
        -h | --help)
            usage
            ;;
        *)
            die "unknown option: $1 (see --help)"
            ;;
    esac
done

[ -n "$INSTALL_DIR" ] || die "--dir is required"

# -----------------------------------------------------------------------------
# Platform
# -----------------------------------------------------------------------------
detect_os() {
    case "$(uname -s 2>/dev/null || echo unknown)" in
        Linux*) echo linux ;;
        Darwin*) echo darwin ;;
        MINGW* | MSYS* | CYGWIN* | Windows_NT) echo windows ;;
        *)
            # GitHub Actions Windows often reports MINGW via bash
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
    # Prefer GitHub runner arch when present (handles Windows ARM64 host quirks)
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

OS="$(detect_os)"
ARCH="$(detect_arch)"
log "platform: os=${OS} arch=${ARCH}"

# macOS Intel: upstream 0.12 macOS archive is arm64-only — fail closed.
if [ "$OS" = "darwin" ] && [ "$ARCH" = "x86_64" ]; then
    die "macOS x86_64 is not supported by the pinned minisign 0.12 macOS archive (arm64-only); use an arm64 runner"
fi

# -----------------------------------------------------------------------------
# Temp workspace (private; cleaned on exit)
# -----------------------------------------------------------------------------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sfetch-bootstrap.XXXXXX")"
cleanup() {
    rm -rf "${WORK}"
}
trap cleanup EXIT

mkdir -p "$INSTALL_DIR"
INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd)"

# Install mode continues below; acquire-minisign-only jumps after helpers load.

# -----------------------------------------------------------------------------
# HTTPS fetch with bounded retries
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Minisign acquisition (pinned official archive only; never prefer ambient PATH)
# -----------------------------------------------------------------------------
MINISIGN_BIN=""

# Exact whitespace-delimited version token match (authoritative for this engine).
# Rejects substring soft matches and suffix/prefix extensions (e.g. 0.4.11-rc1).
version_output_matches_pin() {
    local out="$1" pin="$2"
    local want="${pin#v}"
    local tok
    [ -n "$want" ] || return 1
    while IFS= read -r tok; do
        [ -n "$tok" ] || continue
        case "$tok" in
            v*)
                if [ "${tok#v}" = "$want" ]; then
                    return 0
                fi
                ;;
        esac
        if [ "$tok" = "$want" ]; then
            return 0
        fi
    done <<EOF
$(printf '%s\n' "$out" | tr -s '[:space:]' '\n')
EOF
    return 1
}

# Destination for pinned minisign binary (override for --acquire-minisign-only).
MINISIGN_INSTALL_DIR="${WORK}/tools"

ensure_minisign() {
    # Always download + hash-verify the pinned upstream archive.
    # Do not prefer ambient PATH minisign (PATH shims must not become the verifier).
    # No runtime env seam: fixture tests patch a temporary engine copy.
    local tools="${MINISIGN_INSTALL_DIR}"
    mkdir -p "$tools"
    case "$OS" in
        windows)
            local zip="${WORK}/minisign-win.zip"
            http_get "$MINISIGN_WIN_URL" "$zip"
            assert_sha256 "$zip" "$MINISIGN_WIN_SHA256"
            if command -v unzip >/dev/null 2>&1; then
                unzip -q -o "$zip" -d "${WORK}/minisign-extract"
            else
                # PowerShell Expand-Archive on Windows runners
                powershell.exe -NoProfile -Command \
                    "Expand-Archive -LiteralPath '$zip' -DestinationPath '${WORK}/minisign-extract' -Force" ||
                    die "failed to extract minisign zip"
            fi
            local sub
            case "$ARCH" in
                x86_64) sub="x86_64" ;;
                aarch64) sub="aarch64" ;;
                *) die "unsupported Windows arch: $ARCH" ;;
            esac
            local src="${WORK}/minisign-extract/minisign-win64/${sub}/minisign.exe"
            [ -f "$src" ] || die "minisign.exe not found at $src"
            cp "$src" "${tools}/minisign.exe"
            MINISIGN_BIN="${tools}/minisign.exe"
            ;;
        darwin)
            local zip="${WORK}/minisign-mac.zip"
            http_get "$MINISIGN_MAC_URL" "$zip"
            assert_sha256 "$zip" "$MINISIGN_MAC_SHA256"
            unzip -q -o "$zip" -d "${WORK}/minisign-extract"
            [ -f "${WORK}/minisign-extract/minisign" ] || die "minisign binary missing from macOS archive"
            cp "${WORK}/minisign-extract/minisign" "${tools}/minisign"
            chmod 0755 "${tools}/minisign"
            MINISIGN_BIN="${tools}/minisign"
            ;;
        linux)
            local tgz="${WORK}/minisign-linux.tar.gz"
            http_get "$MINISIGN_LINUX_URL" "$tgz"
            assert_sha256 "$tgz" "$MINISIGN_LINUX_SHA256"
            mkdir -p "${WORK}/minisign-extract"
            tar -xzf "$tgz" -C "${WORK}/minisign-extract"
            local sub
            case "$ARCH" in
                x86_64) sub="x86_64" ;;
                aarch64) sub="aarch64" ;;
                *) die "unsupported Linux arch: $ARCH" ;;
            esac
            local src="${WORK}/minisign-extract/minisign-linux/${sub}/minisign"
            [ -f "$src" ] || die "minisign not found at $src"
            cp "$src" "${tools}/minisign"
            chmod 0755 "${tools}/minisign"
            MINISIGN_BIN="${tools}/minisign"
            ;;
        *)
            die "unsupported OS for minisign install: $OS"
            ;;
    esac
    assert_minisign_version
    log "minisign ready (pinned archive): ${MINISIGN_BIN}"
}

assert_minisign_version() {
    local out first
    # Fail closed if the verifier cannot report a version (no || true).
    out="$("$MINISIGN_BIN" -v 2>&1)" ||
        die "minisign -v failed (cannot assert pinned version ${MINISIGN_VERSION_EXPECTED})"
    first="$(printf '%s\n' "$out" | head -n1)"
    version_output_matches_pin "$first" "$MINISIGN_VERSION_EXPECTED" ||
        die "minisign version assertion failed (want exact ${MINISIGN_VERSION_EXPECTED}): ${first}"
}

# --acquire-minisign-only: shared acquisition path for CI Windows dogfood etc.
if [ "$ACQUIRE_MINISIGN_ONLY" = "1" ]; then
    MINISIGN_INSTALL_DIR="$INSTALL_DIR"
    ensure_minisign
    printf 'minisign-bin=%s\n' "$MINISIGN_BIN"
    exit 0
fi

# -----------------------------------------------------------------------------
# Install mode: version / route validation
# -----------------------------------------------------------------------------
[ -n "$VERSION" ] || die "--version is required"

# Reject floating / non-immutable refs (CI and Makefile must never use latest).
case "$VERSION" in
    "" | latest | LATEST | main | master | HEAD)
        die "refusing floating version ${VERSION:-<empty>}; pin an exact tag (e.g. v0.4.11)"
        ;;
esac
if ! is_exact_semver_tag "$VERSION"; then
    die "version must be exact vMAJOR.MINOR.PATCH (got: $VERSION)"
fi
if [ -n "$GONEAT_VERSION" ]; then
    case "$GONEAT_VERSION" in
        "" | latest | LATEST | main | master | HEAD)
            die "refusing floating goneat-version: ${GONEAT_VERSION:-<empty>}"
            ;;
    esac
    if ! is_exact_semver_tag "$GONEAT_VERSION"; then
        die "goneat-version must be exact vMAJOR.MINOR.PATCH (got: $GONEAT_VERSION)"
    fi
fi

if ! semver_ge "$VERSION" "$SFETCH_BOOTSTRAP_MIN" || ! semver_le "$VERSION" "$SFETCH_BOOTSTRAP_MAX"; then
    die "sfetch-version $VERSION outside supported range ${SFETCH_BOOTSTRAP_MIN}..${SFETCH_BOOTSTRAP_MAX} for this bootstrap revision"
fi

# Fixed download base (no env override — fixtures patch a temporary copy).
BASE_URL="https://github.com/${REPO}/releases/download"
ASSET_BASE="${BASE_URL}/${VERSION}"

# Route selection (human log on stderr; machine field on stdout at end only).
ROUTE=""
if semver_ge "$VERSION" "$SFETCH_MINISIG_SINCE"; then
    ROUTE="minisig"
else
    ROUTE="sha256sums"
fi
log "bootstrap-sfetch-verified: version=${VERSION} verify-route=${ROUTE} range=${SFETCH_BOOTSTRAP_MIN}..${SFETCH_BOOTSTRAP_MAX}"

write_pubkey() {
    local path="$1"
    # minisign -p expects a file with optional comment + RW... key line
    {
        echo "untrusted comment: sfetch release signing key (embedded trust anchor)"
        echo "${SFETCH_MINISIGN_PUBKEY}"
    } >"$path"
}

# -----------------------------------------------------------------------------
# Verification routes
# -----------------------------------------------------------------------------
verify_installer_minisig() {
    local script="$1"
    local _sig="$2"
    local pub="$3"
    log "verify verify-route=minisig: minisign -Vm install-sfetch.sh"
    if ! "$MINISIGN_BIN" -Vm "$script" -p "$pub" -x "$_sig" >/dev/null; then
        die "install-sfetch.sh.minisig verification failed (verify-route=minisig; no fallback)"
    fi
    log "install-sfetch.sh.minisig: OK"
}

verify_installer_sha256sums() {
    local script="$1" sums="$2" sums_sig="$3" pub="$4"
    log "verify verify-route=sha256sums: minisign -Vm SHA256SUMS then hash install-sfetch.sh"
    if ! "$MINISIGN_BIN" -Vm "$sums" -p "$pub" -x "$sums_sig" >/dev/null; then
        die "SHA256SUMS.minisig verification failed (verify-route=sha256sums; no fallback)"
    fi
    local expect got
    expect="$(awk '$2 == "install-sfetch.sh" { print $1; exit }' "$sums")"
    [ -n "$expect" ] || die "install-sfetch.sh not listed in SHA256SUMS"
    got="$(sha256_file "$script")"
    if [ "$got" != "$expect" ]; then
        die "install-sfetch.sh SHA-256 mismatch: expected ${expect}, got ${got}"
    fi
    log "install-sfetch.sh SHA-256 via signed SHA256SUMS: OK"
}

# -----------------------------------------------------------------------------
# Install sfetch
# -----------------------------------------------------------------------------
ensure_minisign

PUB="${WORK}/sfetch-minisign.pub"
write_pubkey "$PUB"

SCRIPT="${WORK}/install-sfetch.sh"
http_get "${ASSET_BASE}/install-sfetch.sh" "$SCRIPT"
chmod 0755 "$SCRIPT"

case "$ROUTE" in
    minisig)
        SIG="${WORK}/install-sfetch.sh.minisig"
        http_get "${ASSET_BASE}/install-sfetch.sh.minisig" "$SIG"
        verify_installer_minisig "$SCRIPT" "$SIG" "$PUB"
        ;;
    sha256sums)
        SUMS="${WORK}/SHA256SUMS"
        SUMS_SIG="${WORK}/SHA256SUMS.minisig"
        http_get "${ASSET_BASE}/SHA256SUMS" "$SUMS"
        http_get "${ASSET_BASE}/SHA256SUMS.minisig" "$SUMS_SIG"
        verify_installer_sha256sums "$SCRIPT" "$SUMS" "$SUMS_SIG" "$PUB"
        ;;
    *)
        die "internal error: unknown route $ROUTE"
        ;;
esac

# Execute only after verification (never pipe curl | bash)
log "executing verified installer for ${VERSION} → ${INSTALL_DIR}"
# shellcheck disable=SC2086
bash "$SCRIPT" --tag "$VERSION" --dir "$INSTALL_DIR" --yes --require-minisign

SFETCH_BIN="${INSTALL_DIR}/sfetch"
if [ "$OS" = "windows" ]; then
    if [ -f "${INSTALL_DIR}/sfetch.exe" ]; then
        SFETCH_BIN="${INSTALL_DIR}/sfetch.exe"
    fi
fi
[ -x "$SFETCH_BIN" ] || [ -f "$SFETCH_BIN" ] || die "sfetch binary missing after install: $SFETCH_BIN"

# Exact version assertion (token boundary; not soft substring/regex)
REPORT="$("$SFETCH_BIN" --version 2>&1)" || die "sfetch --version failed after install"
log "sfetch reports: ${REPORT}"
version_output_matches_pin "$REPORT" "$VERSION" ||
    die "sfetch version assertion failed: expected ${VERSION}, got: ${REPORT}"

# Optional goneat via verified sfetch (no Go toolchain). Fail closed: any
# install or version failure is non-zero (no soft skip when requested).
if [ -n "$GONEAT_VERSION" ]; then
    log "installing goneat ${GONEAT_VERSION} via verified sfetch"
    "$SFETCH_BIN" --repo fulmenhq/goneat --tag "$GONEAT_VERSION" \
        --dest-dir "$INSTALL_DIR" --require-minisign ||
        die "goneat install failed for ${GONEAT_VERSION} (requested; fail closed)"
    GONEAT_BIN="${INSTALL_DIR}/goneat"
    if [ "$OS" = "windows" ] && [ -f "${INSTALL_DIR}/goneat.exe" ]; then
        GONEAT_BIN="${INSTALL_DIR}/goneat.exe"
    fi
    [ -f "$GONEAT_BIN" ] || die "goneat binary missing after install"
    GREP="$("$GONEAT_BIN" version 2>&1 | head -n1)" || die "goneat version command failed"
    version_output_matches_pin "$GREP" "$GONEAT_VERSION" ||
        die "goneat version assertion failed: expected ${GONEAT_VERSION}, got: ${GREP}"
    log "goneat OK: ${GREP}"
fi

log "bootstrap-sfetch-verified complete: sfetch=${VERSION} verify-route=${ROUTE} dir=${INSTALL_DIR}"
# Machine-readable fields on stdout only (exactly one route= line for the action).
printf 'route=%s\n' "$ROUTE"
printf 'sfetch-bin=%s\n' "$SFETCH_BIN"
if [ -n "$GONEAT_VERSION" ]; then
    printf 'goneat-bin=%s\n' "$GONEAT_BIN"
fi
