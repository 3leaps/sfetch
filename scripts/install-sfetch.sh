#!/usr/bin/env bash
#
# install-sfetch.sh - Bootstrap installer for sfetch
#
# Usage:
#   curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
#
# Options:
#   --tag vX.Y.Z     Install specific version (default: latest)
#   --dir PATH       Install directory (default: ~/.local/bin, or ~/bin on Windows)
#   --yes            Skip confirmation prompts
#   --dry-run        Download and verify, but don't install
#   --help           Show this help
#
# Verification:
#   The script checks for minisign and gpg to verify SHA256SUMS signatures.
#   - With minisign: verifies SHA256SUMS.minisig (recommended)
#   - With gpg: verifies SHA256SUMS.asc
#   - With neither: verifies checksum only (warns user)
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
SFETCH_MINISIGN_PUBKEY="RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC"

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
		echo "Continuing with checksum verification only..."
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

	# Try minisign first (preferred - uses embedded trust anchor)
	if [ "$VERIFY_MINISIGN" = true ] && [ -f "${sums_file}.minisig" ]; then
		# Write embedded public key to temp file for minisign
		local pubkey_file="${tmpdir}/sfetch-minisign.pub"
		echo "untrusted comment: sfetch release signing key" >"$pubkey_file"
		echo "$SFETCH_MINISIGN_PUBKEY" >>"$pubkey_file"

		log "Verifying signature with minisign (embedded trust anchor)..."
		if minisign -Vm "$sums_file" -p "$pubkey_file" >/dev/null 2>&1; then
			log "Minisign signature verified"
			verified=true
		else
			err "minisign signature verification failed"
		fi
	fi

	# Try GPG if minisign didn't verify
	if [ "$verified" = false ] && [ "$VERIFY_GPG" = true ] && [ -f "${sums_file}.asc" ]; then
		local gpg_key="${tmpdir}/sfetch-release-signing-key.asc"
		if [ -f "$gpg_key" ]; then
			log "Verifying signature with gpg..."
			local gpg_home
			gpg_home=$(mktemp -d)
			if gpg --batch --no-tty --homedir "$gpg_home" --import "$gpg_key" 2>/dev/null &&
				gpg --batch --no-tty --homedir "$gpg_home" --trust-model always \
					--verify "${sums_file}.asc" "$sums_file" 2>/dev/null; then
				log "GPG signature verified"
				verified=true
			else
				err "GPG signature verification failed"
			fi
			rm -rf "$gpg_home"
		else
			warn "GPG public key not found in release"
		fi
	fi

	if [ "$verified" = false ]; then
		warn "no signature verified - proceeding with checksum only"
		echo ""
		echo "To enable signature verification, install minisign or gpg."
		echo "See options above or visit: https://github.com/3leaps/sfetch"
		echo ""
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
		--help | -h)
			head -25 "$0" | tail -20
			exit 0
			;;
		*)
			err "unknown option: $1"
			;;
		esac
	done

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
	version=$(grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$release_json" | head -1 | cut -d'"' -f4)
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

	if [[ "$archive_name" == *.zip ]]; then
		need_cmd unzip
		unzip -q "${tmpdir}/${archive_name}" -d "$extract_dir"
	else
		need_cmd tar
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
