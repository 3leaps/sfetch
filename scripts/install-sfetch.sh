#!/usr/bin/env bash
#
# install-sfetch.sh - Bootstrap installer for sfetch
#
# Usage:
#   curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
#
# Options:
#   --tag vX.Y.Z         Install specific version (default: latest)
#   --dir PATH           Install directory (default: ~/.local/bin, or ~/bin on Windows)
#   --yes                Skip confirmation prompts
#   --dry-run            Download and verify, but don't install
#   --allow-checksum-only  Allow install without signature verification (NOT recommended)
#   --require-signature    Require signature verification (default: true)
#   --require-minisign     Require minisign verification (default: true)
#   --help                 Show this help
#
# Verification:
#   Default: minisign verification is REQUIRED (embedded trust anchor).
#   - minisign: verifies SHA256SUMS.minisig using pinned key (preferred)
#   - gpg: optional fallback if fingerprint matches pinned FPR
#   - checksum-only: only when --allow-checksum-only is passed (warns loudly)
#
# Repository: https://github.com/3leaps/sfetch
#

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SFETCH_REPO="3leaps/sfetch"
SFETCH_API="https://api.github.com/repos/${SFETCH_REPO}/releases"

# Embedded trust anchor - minisign public key for verifying releases
# This key is pinned here to prevent TOCTOU attacks where an attacker
# could replace both the release artifacts and the verification key.
#
# IMPORTANT: This key must match EmbeddedMinisignPubkey in main.go
# Update both when rotating keys (see docs/security/signing-runbook.md)
SFETCH_MINISIGN_PUBKEY="RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC"
# Pinned PGP fingerprint (for optional fallback)
SFETCH_PGP_FPR="94BB7811D4AD49B2310E0C08FA0651DE91B828ED"
TRUST_LEVEL="unknown"

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

log() { echo "==> $*" >&2; }
warn() { echo "warning: $*" >&2; }
err() {
    echo "error: $*" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "required command not found: $1"
    fi
}

read_release_tag_name() {
    local release_json_file="$1"
    local version=""

    # Prefer jq when available (more robust than grep on JSON), but keep a
    # dependency-free fallback for minimal bootstrap environments.
    if command -v jq >/dev/null 2>&1; then
        version=$(jq -r '.tag_name // empty' "$release_json_file" 2>/dev/null || true)
    fi

    if [ -z "$version" ]; then
        version=$(grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$release_json_file" | head -1 | cut -d'"' -f4 || true)
    fi

    if [ -z "$version" ]; then
        err "failed to parse release tag from GitHub API response"
    fi

    echo "$version"
}

print_verifier_help() {
    echo "To verify signatures, install one of:"
    case "$(uname -s)" in
        Darwin*)
            echo "  minisign (recommended): brew install minisign"
            echo "  gpg (fallback):        brew install gnupg"
            ;;
        Linux*)
            echo "  minisign (recommended): apt install minisign    # Debian/Ubuntu"
            echo "                          brew install minisign   # if using Homebrew"
            echo "  gpg (fallback):        apt install gnupg"
            ;;
        MINGW* | MSYS* | CYGWIN*)
            echo "  minisign (recommended): scoop bucket add main && scoop install main/minisign"
            echo "  gpg (fallback):         scoop install gpg"
            ;;
    esac
    echo "If you cannot install a verifier here, verify on a trusted machine and copy the binary, or pass --allow-checksum-only (NOT recommended; no authenticity)."
}

# -----------------------------------------------------------------------------
# Platform detection
# -----------------------------------------------------------------------------

detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux*) os="linux" ;;
        Darwin*) os="darwin" ;;
        MINGW* | MSYS* | CYGWIN*) os="windows" ;;
        *) err "unsupported OS: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
        x86_64 | amd64) arch="amd64" ;;
        arm64 | aarch64) arch="arm64" ;;
        *) err "unsupported architecture: $(uname -m)" ;;
    esac

    echo "${os}_${arch}"
}

# -----------------------------------------------------------------------------
# Verification tool detection
# -----------------------------------------------------------------------------

check_verification_tools() {
    local has_minisign=false
    local has_gpg=false

    if command -v minisign >/dev/null 2>&1; then
        has_minisign=true
    fi

    if command -v gpg >/dev/null 2>&1; then
        has_gpg=true
    fi

    if [ "$has_minisign" = false ] && [ "$has_gpg" = false ]; then
        warn "no signature verification tools found"
        echo ""
        echo "For signature verification, install one of:"
        echo ""
        case "$(uname -s)" in
            Darwin*)
                echo "  minisign (recommended):"
                echo "    brew install minisign"
                echo ""
                echo "  gpg:"
                echo "    brew install gnupg"
                ;;
            Linux*)
                echo "  minisign (recommended):"
                echo "    brew install minisign        # if using Homebrew"
                echo "    apt install minisign         # Debian/Ubuntu"
                echo ""
                echo "  gpg:"
                echo "    apt install gnupg            # Debian/Ubuntu"
                ;;
            MINGW* | MSYS* | CYGWIN*)
                echo "  minisign (recommended):"
                echo "    scoop bucket add main"
                echo "    scoop install main/minisign"
                echo ""
                echo "  gpg:"
                echo "    scoop install gpg"
                ;;
        esac
        echo ""
    fi

    VERIFY_MINISIGN=$has_minisign
    VERIFY_GPG=$has_gpg
}

# -----------------------------------------------------------------------------
# Download helpers
# -----------------------------------------------------------------------------

fetch() {
    local url="$1"
    local dest="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -sSfL -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url"
    else
        err "curl or wget required"
    fi
}

fetch_json() {
    local url="$1"

    if command -v curl >/dev/null 2>&1; then
        curl -sSfL -H "Accept: application/vnd.github.v3+json" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O - --header="Accept: application/vnd.github.v3+json" "$url"
    else
        err "curl or wget required"
    fi
}

# -----------------------------------------------------------------------------
# Checksum verification
# -----------------------------------------------------------------------------

verify_checksum() {
    local file="$1"
    local expected="$2"
    local actual

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$file" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$file" | cut -d' ' -f1)
    else
        err "sha256sum or shasum required"
    fi

    if [ "$actual" != "$expected" ]; then
        err "checksum mismatch for $(basename "$file")"
    fi
}

# -----------------------------------------------------------------------------
# Signature verification
# -----------------------------------------------------------------------------

verify_signature() {
    local sums_file="$1"
    local tmpdir="$2"
    local verified=false
    TRUST_LEVEL="checksum-only"

    # Try minisign first (preferred - uses embedded trust anchor)
    if [ "$VERIFY_MINISIGN" = true ] && [ -f "${sums_file}.minisig" ]; then
        local pubkey_file="${tmpdir}/sfetch-minisign.pub"
        echo "untrusted comment: sfetch release signing key" >"$pubkey_file"
        echo "$SFETCH_MINISIGN_PUBKEY" >>"$pubkey_file"

        log "Verifying signature with minisign (embedded trust anchor)..."
        if minisign -Vm "$sums_file" -p "$pubkey_file" >/dev/null 2>&1; then
            log "Minisign signature verified"
            verified=true
            TRUST_LEVEL="high (minisign)"
        else
            err "minisign signature verification failed"
        fi
    fi

    if [ "$verified" = false ] && [ "$REQUIRE_MINISIGN" = true ]; then
        if [ "$VERIFY_MINISIGN" = false ]; then
            err "minisign is required; install minisign or pass --allow-checksum-only (not recommended)"
        fi
        if [ ! -f "${sums_file}.minisig" ]; then
            err "SHA256SUMS.minisig missing; cannot verify (pass --allow-checksum-only to override)"
        fi
    fi

    # Try GPG if minisign didn't verify and minisign is not required
    if [ "$verified" = false ] && [ "$REQUIRE_MINISIGN" = false ] && [ "$VERIFY_GPG" = true ] && [ -f "${sums_file}.asc" ]; then
        local gpg_key="${tmpdir}/sfetch-release-signing-key.asc"
        if [ -f "$gpg_key" ]; then
            local fpr
            fpr=$(gpg --with-colons --import-options show-only --fingerprint "$gpg_key" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}')
            if [ "$fpr" != "$SFETCH_PGP_FPR" ]; then
                err "GPG key fingerprint mismatch (expected ${SFETCH_PGP_FPR}, got ${fpr:-unknown})"
            fi
            log "Verifying signature with gpg (pinned fingerprint)..."
            local gpg_home
            gpg_home=$(mktemp -d)
            if gpg --batch --no-tty --homedir "$gpg_home" --import "$gpg_key" 2>/dev/null &&
                gpg --batch --no-tty --homedir "$gpg_home" --trust-model always \
                    --verify "${sums_file}.asc" "$sums_file" 2>/dev/null; then
                log "GPG signature verified"
                verified=true
                TRUST_LEVEL="medium (gpg, pinned key)"
            else
                err "GPG signature verification failed"
            fi
            rm -rf "$gpg_home"
        else
            warn "GPG public key not found in release"
        fi
    fi

    if [ "$verified" = false ]; then
        if [ "$REQUIRE_SIGNATURE" = true ]; then
            err "signature verification required; install minisign (recommended) or use --allow-checksum-only to bypass (NOT recommended)"
        fi
        warn "no signature verified - proceeding with checksum only (trust: low)"
        TRUST_LEVEL="low (checksum-only)"
    fi
}

# -----------------------------------------------------------------------------
# Installation
# -----------------------------------------------------------------------------

install_binary() {
    local src="$1"
    local dest_dir="$2"
    local platform="$3"
    local binary_name="sfetch"

    # Windows needs .exe extension
    if [[ "$platform" == windows_* ]]; then
        binary_name="sfetch.exe"
    fi

    local dest="${dest_dir}/${binary_name}"

    # Create destination directory
    mkdir -p "$dest_dir"

    # Copy binary
    cp "$src" "$dest"
    chmod +x "$dest"

    log "Installed ${binary_name} to ${dest}"
    log "Trust: ${TRUST_LEVEL}"
    log "To verify this installation later: sfetch --self-verify"

    # Path advice
    case ":$PATH:" in
        *":${dest_dir}:"*) ;;
        *)
            echo ""
            echo "Add to your PATH:"
            if [[ "$platform" == windows_* ]]; then
                echo "  setx PATH \"%PATH%;${dest_dir}\""
            else
                echo "  export PATH=\"${dest_dir}:\$PATH\""
            fi
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    local tag="latest"
    local install_dir=""
    local dry_run=false
    local yes=false
    local require_signature=true
    local require_minisign=true

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --tag)
                tag="$2"
                shift 2
                ;;
            --dir)
                install_dir="$2"
                shift 2
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --yes)
                yes=true
                shift
                ;;
            --allow-checksum-only)
                require_signature=false
                require_minisign=false
                shift
                ;;
            --require-signature)
                require_signature=true
                shift
                ;;
            --require-minisign)
                require_minisign=true
                shift
                ;;
            --no-require-signature)
                require_signature=false
                shift
                ;;
            --no-require-minisign)
                require_minisign=false
                shift
                ;;
            --help | -h)
                head -25 "$0" | tail -20
                exit 0
                ;;
            *)
                err "unknown option: $1"
                ;;
        esac
    done

    REQUIRE_SIGNATURE=$require_signature
    REQUIRE_MINISIGN=$require_minisign

    # Detect platform
    local platform
    platform=$(detect_platform)
    log "Detected platform: ${platform}"

    # Set default install directory
    if [ -z "$install_dir" ]; then
        if [[ "$platform" == windows_* ]]; then
            install_dir="${USERPROFILE:-$HOME}/bin"
        else
            install_dir="${HOME}/.local/bin"
        fi
    fi

    # Check verification tools
    check_verification_tools
    if [ "$REQUIRE_MINISIGN" = true ] && [ "${VERIFY_MINISIGN:-false}" = false ]; then
        print_verifier_help
        err "minisign is required; install minisign or pass --allow-checksum-only (NOT recommended)"
    fi
    if [ "$REQUIRE_SIGNATURE" = true ] && [ "${VERIFY_MINISIGN:-false}" = false ] && [ "${VERIFY_GPG:-false}" = false ]; then
        print_verifier_help
        err "signature verification required; install minisign (recommended) or gpg, or pass --allow-checksum-only to bypass (NOT recommended)"
    fi

    # Create temp directory (not local - needed for EXIT trap)
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    # Fetch release info
    local release_url
    if [ "$tag" = "latest" ]; then
        release_url="${SFETCH_API}/latest"
    else
        release_url="${SFETCH_API}/tags/${tag}"
    fi

    log "Fetching release info..."
    local release_json="${tmpdir}/release.json"
    fetch_json "$release_url" >"$release_json"

    local version
    version=$(read_release_tag_name "$release_json")
    log "Installing sfetch ${version}"

    # Determine archive name
    local archive_name="sfetch_${platform}"
    if [[ "$platform" == windows_* ]]; then
        archive_name="${archive_name}.zip"
    else
        archive_name="${archive_name}.tar.gz"
    fi

    # Download assets
    local base_url="https://github.com/${SFETCH_REPO}/releases/download/${version}"

    log "Downloading assets..."
    fetch "${base_url}/SHA256SUMS" "${tmpdir}/SHA256SUMS"
    fetch "${base_url}/${archive_name}" "${tmpdir}/${archive_name}"

    # Download signature files (optional)
    # Note: minisign pubkey is embedded in this script (trust anchor), not fetched
    fetch "${base_url}/SHA256SUMS.minisig" "${tmpdir}/SHA256SUMS.minisig" 2>/dev/null || true
    fetch "${base_url}/SHA256SUMS.asc" "${tmpdir}/SHA256SUMS.asc" 2>/dev/null || true
    fetch "${base_url}/sfetch-release-signing-key.asc" "${tmpdir}/sfetch-release-signing-key.asc" 2>/dev/null || true

    # Verify signature on SHA256SUMS
    verify_signature "${tmpdir}/SHA256SUMS" "$tmpdir"

    # Verify archive checksum
    log "Verifying checksum..."
    local expected_hash
    expected_hash=$(grep "${archive_name}" "${tmpdir}/SHA256SUMS" | cut -d' ' -f1)
    if [ -z "$expected_hash" ]; then
        err "archive not found in SHA256SUMS: ${archive_name}"
    fi
    verify_checksum "${tmpdir}/${archive_name}" "$expected_hash"
    log "Checksum verified"

    # Dry run stops here
    if [ "$dry_run" = true ]; then
        log "Dry run complete - verification passed"
        exit 0
    fi

    # Extract
    log "Extracting..."
    local extract_dir="${tmpdir}/extract"
    mkdir -p "$extract_dir"

    # List archive entries to guard against zip-slip/path traversal.
    # Reject absolute paths, Windows drive-letter paths, and parent-dir traversal segments.
    # This runs BEFORE extraction so a malicious archive cannot write outside $extract_dir.
    local entry
    local list_cmd=()

    if [[ "$archive_name" == *.zip ]]; then
        need_cmd unzip
        if unzip -Z1 "${tmpdir}/${archive_name}" >/dev/null 2>&1; then
            list_cmd=(unzip -Z1 "${tmpdir}/${archive_name}")
        else
            # Portability: some unzip builds lack `-Z1`; fall back to parsing `unzip -l` output.
            # We treat this as an internal listing mechanism only; extraction still uses unzip itself.
            list_cmd=(sh -c "unzip -l \"${tmpdir}/${archive_name}\" | awk 'NR>3 {print \$NF}' | sed '/^$/d'")
        fi
    else
        need_cmd tar
        list_cmd=(tar -tzf "${tmpdir}/${archive_name}")
    fi

    while IFS= read -r entry; do
        # Normalize any leading "./" segments (tar often prefixes paths).
        while [[ "$entry" == ./* ]]; do
            entry="${entry#./}"
        done
        if [[ -z "$entry" ]]; then
            continue
        fi

        # Absolute paths (POSIX/Windows) and drive-letter paths.
        if [[ "$entry" == /* ]] || [[ "$entry" == \\* ]] || [[ "$entry" =~ ^[A-Za-z]: ]]; then
            err "unsafe path in archive entry: $entry"
        fi

        # Parent directory traversal (POSIX style)
        if [[ "$entry" == ".." ]] || [[ "$entry" == ../* ]] || [[ "$entry" == */../* ]] || [[ "$entry" == */.. ]]; then
            err "unsafe path in archive entry: $entry"
        fi

        # Parent directory traversal (Windows style)
        if [[ "$entry" == ..\\* ]] || [[ "$entry" == *"\\..\\"* ]] || [[ "$entry" == *"\\.." ]]; then
            err "unsafe path in archive entry: $entry"
        fi
    done < <("${list_cmd[@]}")

    if [[ "$archive_name" == *.zip ]]; then
        unzip -q "${tmpdir}/${archive_name}" -d "$extract_dir"
    else
        tar -xzf "${tmpdir}/${archive_name}" -C "$extract_dir"
    fi

    # Find binary
    local binary
    binary=$(find "$extract_dir" -type f -name "sfetch*" | head -1)
    if [ -z "$binary" ]; then
        err "binary not found in archive"
    fi

    # Confirm installation
    if [ "$yes" = false ] && [ -t 0 ]; then
        echo ""
        echo "Ready to install sfetch ${version} to ${install_dir}"
        echo "Verification: ${TRUST_LEVEL}"
        printf "Continue? [Y/n] "
        read -r confirm
        case "$confirm" in
            [nN]*)
                echo "Aborted."
                exit 1
                ;;
        esac
    fi

    # Install
    install_binary "$binary" "$install_dir" "$platform"

    echo ""
    log "Done! Run 'sfetch --help' to get started."
}

main "$@"
