#!/usr/bin/env bash
# version-matches-pin.sh — exact whitespace-delimited version token match.
#
# Usage: version-matches-pin.sh <command-output> <pin>
#   pin: vMAJOR.MINOR.PATCH (sfetch/goneat) or MAJOR.MINOR / MAJOR.MINOR.PATCH
# Exit 0 if any whitespace-delimited token equals the pin (optional leading v).
# Exit 1 otherwise.
#
# Rejects:
#   - substring soft matches (10x4y110 vs 0.4.11)
#   - parent versions inside longer numbers (10.4.11 vs 0.4.11)
#   - suffixed/prefixed prerelease tokens (0.4.11-rc1 vs 0.4.11)
set -euo pipefail

out="${1-}"
pin="${2-}"

if [ -z "$pin" ]; then
    echo "usage: version-matches-pin.sh <command-output> <pin>" >&2
    exit 2
fi

want="${pin#v}"
if [ -z "$want" ]; then
    echo "error: empty pin after stripping optional v" >&2
    exit 2
fi

# Normalize whitespace → tokens; compare exact equality after optional leading v.
while IFS= read -r tok; do
    [ -n "$tok" ] || continue
    # Strip a single leading v only when the remainder matches the pin form.
    case "$tok" in
        v*)
            if [ "${tok#v}" = "$want" ]; then
                exit 0
            fi
            ;;
    esac
    if [ "$tok" = "$want" ]; then
        exit 0
    fi
done <<EOF
$(printf '%s\n' "$out" | tr -s '[:space:]' '\n')
EOF

exit 1
