#!/usr/bin/env bash
# acquire-minisign-pinned.sh — thin wrapper over the shared bootstrap engine.
#
# Usage: acquire-minisign-pinned.sh --dir PATH
# Installs official minisign 0.12 (hash-verified) into PATH.
# Single authoritative acquisition path: bootstrap-sfetch-verified.sh
# --acquire-minisign-only (constants + download live only there).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ENGINE="${ROOT}/bootstrap-sfetch-verified.sh"
if [ ! -f "$ENGINE" ] || [ ! -x "$ENGINE" ]; then
    if [ -f "$ENGINE" ]; then
        chmod +x "$ENGINE"
    else
        echo "error: shared engine missing: $ENGINE" >&2
        exit 1
    fi
fi
exec "$ENGINE" --acquire-minisign-only "$@"
