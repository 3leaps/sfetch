#!/usr/bin/env bash
set -euo pipefail

# Package unversioned sfetch archives (one .tar.gz / .zip per OS/arch).
# Archive names must match install-sfetch.sh: sfetch_${os}_${arch}.tar.gz|.zip
#
# Checksums and signing are the release ceremony (make release-checksums /
# release-sign), not this script.
#
# Expects binaries already built in ./bin as sfetch_${os}_${arch}[.exe]
# (the layout `make build` produces when GOOS/GOARCH are set).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PROJECT="${BINARY_NAME:-sfetch}"
BIN_DIR="bin"
OUT_DIR="dist/release"
OUT_DIR_ABS="$(mkdir -p "${OUT_DIR}" && cd "${OUT_DIR}" && pwd)"

package() {
    local os="$1" arch="$2"
    local ext="" archive_ext="tar.gz"
    local bin="${BIN_DIR}/${PROJECT}_${os}_${arch}"

    if [[ "${os}" == "windows" ]]; then
        ext=".exe"
        bin="${bin}${ext}"
        archive_ext="zip"
    fi

    local archive_name="${PROJECT}_${os}_${arch}.${archive_ext}"

    if [[ ! -f "${bin}" ]]; then
        echo "error: binary not found: ${bin} (build with GOOS=${os} GOARCH=${arch})" >&2
        exit 1
    fi

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "${tmpdir}"' RETURN

    local bin_name="${PROJECT}${ext}"
    cp "${bin}" "${tmpdir}/${bin_name}"
    chmod +x "${tmpdir}/${bin_name}"

    case "${archive_ext}" in
        tar.gz)
            (cd "${tmpdir}" && tar -czf "${OUT_DIR_ABS}/${archive_name}" "${bin_name}")
            ;;
        zip)
            if command -v zip >/dev/null 2>&1; then
                (cd "${tmpdir}" && zip -q "${OUT_DIR_ABS}/${archive_name}" "${bin_name}")
            elif command -v python3 >/dev/null 2>&1; then
                (cd "${tmpdir}" && python3 -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w",zipfile.ZIP_DEFLATED); z.write(sys.argv[2]); z.close()' "${OUT_DIR_ABS}/${archive_name}" "${bin_name}")
            else
                echo "Neither zip nor python3 available to create ${archive_name}" >&2
                exit 1
            fi
            ;;
    esac

    echo "Packaged ${archive_name}"
}

package linux amd64
package linux arm64
package windows amd64
package windows arm64
package darwin arm64

cp scripts/install-sfetch.sh "${OUT_DIR_ABS}/install-sfetch.sh"
echo "Copied install-sfetch.sh"

echo "Artifacts in ${OUT_DIR_ABS}:"
ls -lh "${OUT_DIR_ABS}"
