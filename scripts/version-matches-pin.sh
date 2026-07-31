#!/usr/bin/env bash
# version-matches-pin.sh — exact version token match for tool --version output.
#
# Usage: version-matches-pin.sh <command-output> <pin-tag>
#   pin-tag: vMAJOR.MINOR.PATCH (leading v optional in output)
# Exit 0 if output contains an exact version token equal to the pin.
# Exit 1 otherwise.
#
# Rejects substring/regex soft matches (e.g. "10x4y110" must not match v0.4.11;
# "10.4.11" must not match v0.4.11).
set -euo pipefail

out="${1-}"
pin="${2-}"

if [ -z "$pin" ]; then
    echo "usage: version-matches-pin.sh <command-output> <pin-tag>" >&2
    exit 2
fi

ver="${pin#v}"
case "$ver" in
    [0-9]*.[0-9]*.[0-9]*)
        if ! [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "error: pin must be exact vMAJOR.MINOR.PATCH (got: $pin)" >&2
            exit 2
        fi
        ;;
    *)
        echo "error: pin must be exact vMAJOR.MINOR.PATCH (got: $pin)" >&2
        exit 2
        ;;
esac

# Escape dots for fixed-token regex; require non-digit boundaries.
esc="$(printf '%s' "$ver" | sed 's/\./\\./g')"
printf '%s\n' "$out" | grep -Eq "(^|[^0-9])v?${esc}([^0-9]|$)"
