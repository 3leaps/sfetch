#!/bin/sh
set -e
VERSION=v2025.12.20
GOOS=$(uname -s | tr '[:upper:]' '[:lower:]')
GOARCH=$(uname -m)
ARCHIVE="sfetch_${GOOS}_${GOARCH}.tar.gz"
BINARY="sfetch_${GOOS}_${GOARCH}"
DEST=${DEST:-/usr/local/bin/sfetch}

curl -fsSL "https://github.com/3leaps/sfetch/releases/download/${VERSION}/${ARCHIVE}" -o "${ARCHIVE}"
tar xzf "${ARCHIVE}"
chmod +x "${BINARY}"
"./${BINARY}" --self-verify
sudo mv "${BINARY}" "${DEST}"
"${DEST}" --version
