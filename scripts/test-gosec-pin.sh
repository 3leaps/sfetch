#!/usr/bin/env bash
# Regression: gosec stays version-pinned and gosec-high fails closed when missing.
#
# Asserts committed Makefile/CI/tools.yaml, then mutates scratch copies so
# dropping the pin or the command -v guard cannot pass this check.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

MAKEFILE="${ROOT}/Makefile"
CI="${ROOT}/.github/workflows/ci.yml"
TOOLS="${ROOT}/.goneat/tools.yaml"

extract_target() {
    local file="$1"
    local name="$2"
    awk -v name="$name" '
        $0 ~ "^" name ":" { p=1; print; next }
        p && /^[^[:space:]#]/ { exit }
        p { print }
    ' "$file"
}

# Returns 0 if the files satisfy the pin + fail-closed contract.
validate() {
    local makefile="$1"
    local ci="$2"
    local tools="$3"
    local err=""
    local pin=""
    local pin_ver=""
    local gosec_high=""
    local gosec_install=""
    local precommit=""

    pin="$(grep -E '^GOSEC_VERSION \?= v[0-9]+\.[0-9]+\.[0-9]+$' "$makefile" | head -n1 || true)"
    if [ -z "$pin" ]; then
        echo "missing GOSEC_VERSION ?= vMAJOR.MINOR.PATCH pin"
        return 1
    fi
    pin_ver="${pin#GOSEC_VERSION ?= }"
    case "$pin_ver" in
        latest | *@latest | *latest*)
            echo "GOSEC_VERSION must not be latest (got: $pin_ver)"
            return 1
            ;;
    esac

    gosec_install="$(extract_target "$makefile" gosec-install)"
    [ -n "$gosec_install" ] || {
        echo "gosec-install target missing"
        return 1
    }
    # Literal Makefile tokens — do not expand here.
    # shellcheck disable=SC2016
    printf '%s\n' "$gosec_install" | grep -Fq 'GOBIN=$(BIN_DIR)' ||
        err="${err}gosec-install must set GOBIN=\$(BIN_DIR); "
    # shellcheck disable=SC2016
    printf '%s\n' "$gosec_install" | grep -Fq 'go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)' ||
        err="${err}gosec-install must go install ...@\$(GOSEC_VERSION); "
    printf '%s\n' "$gosec_install" | grep -Fq 'go version -m' ||
        err="${err}gosec-install must assert installed version via go version -m; "
    printf '%s\n' "$gosec_install" | grep -Fq 'exit 1' ||
        err="${err}gosec-install must exit 1 on version mismatch; "

    gosec_high="$(extract_target "$makefile" gosec-high)"
    [ -n "$gosec_high" ] || {
        echo "gosec-high target missing"
        return 1
    }
    printf '%s\n' "$gosec_high" | grep -Fq 'command -v gosec' ||
        err="${err}gosec-high must check command -v gosec; "
    printf '%s\n' "$gosec_high" | grep -Fq 'exit 1' ||
        err="${err}gosec-high must exit 1 when gosec is missing; "

    precommit="$(extract_target "$makefile" precommit)"
    printf '%s\n' "$precommit" | grep -Eq '\$\(MAKE\)[[:space:]]+gosec-high' ||
        err="${err}precommit must still run gosec-high; "

    grep -Fq 'make gosec-install' "$ci" ||
        err="${err}CI must run make gosec-install; "
    grep -Fq -- '--no-cooling' "$ci" &&
        err="${err}CI must not pass --no-cooling; "

    grep -Fq "github.com/securego/gosec/v2/cmd/gosec@${pin_ver}" "$tools" ||
        err="${err}tools.yaml gosec install_package must match GOSEC_VERSION (${pin_ver}); "
    grep -E 'install_package:.*gosec.*@latest' "$tools" >/dev/null &&
        err="${err}tools.yaml gosec must not use @latest; "

    if [ -n "$err" ]; then
        echo "$err"
        return 1
    fi
    return 0
}

scratch=""
trap 'rm -rf "${scratch:-}" 2>/dev/null || true' EXIT
scratch="$(mktemp -d "${TMPDIR:-/tmp}/sft-gosec-pin.XXXXXX")"

msg="$(validate "$MAKEFILE" "$CI" "$TOOLS" || true)"
if [ -n "$msg" ]; then
    fail "committed files rejected: $msg"
fi
pass "committed pin, gosec-install, command -v guard, and CI install"

# --- Mutant: pin removed ---
sed '/^GOSEC_VERSION /d' "$MAKEFILE" >"$scratch/Makefile"
if msg="$(validate "$scratch/Makefile" "$CI" "$TOOLS")"; then
    fail "validator accepted Makefile with GOSEC_VERSION removed"
fi
pass "validator rejects missing pin"

# --- Mutant: pin floated to latest ---
sed 's/^GOSEC_VERSION ?= .*/GOSEC_VERSION ?= latest/' "$MAKEFILE" >"$scratch/Makefile"
if msg="$(validate "$scratch/Makefile" "$CI" "$TOOLS")"; then
    fail "validator accepted GOSEC_VERSION ?= latest"
fi
pass "validator rejects latest pin"

# --- Mutant: fail-closed command -v guard removed ---
awk '
    BEGIN { skip=0 }
    /^gosec-high:/ { print; skip=1; next }
    skip && /^[^[:space:]#]/ { skip=0 }
    skip { next }
    { print }
' "$MAKEFILE" >"$scratch/Makefile"
printf '%s\n' 'gosec-high: ## Run gosec (high confidence only)' >>"$scratch/Makefile"
printf '\t%s\n' 'gosec -confidence high -exclude G301,G302,G107,G304 ./...' >>"$scratch/Makefile"
if msg="$(validate "$scratch/Makefile" "$CI" "$TOOLS")"; then
    fail "validator accepted gosec-high without command -v guard"
fi
pass "validator rejects missing command -v guard"

# --- Mutant: gosec-high dropped from precommit ---
awk '
    /\$\(MAKE\)[[:space:]]+gosec-high/ { next }
    { print }
' "$MAKEFILE" >"$scratch/Makefile"
if msg="$(validate "$scratch/Makefile" "$CI" "$TOOLS")"; then
    fail "validator accepted precommit without gosec-high"
fi
pass "validator rejects gosec-high dropped from precommit"

# --- Mutant: CI pinned install removed ---
grep -v 'make gosec-install' "$CI" >"$scratch/ci.yml"
if msg="$(validate "$MAKEFILE" "$scratch/ci.yml" "$TOOLS")"; then
    fail "validator accepted CI without make gosec-install"
fi
pass "validator rejects CI without pinned gosec install"

# --- Behavioral: gosec-high fail-closed when gosec is absent ---
# Guard must exit 1 with the pin error, not a raw 127 from a missing binary.
# Override BIN_DIR so a previously installed repo-local gosec cannot hide a
# missing command -v check. Keep PATH to make(1) + POSIX shell only.
empty_bin="$(mktemp -d "${scratch}/empty-bin.XXXXXX")"
oldpath="$PATH"
export PATH="/bin:/usr/bin"
set +e
out="$(make -s -C "$ROOT" gosec-high BIN_DIR="$empty_bin" 2>&1)"
status=$?
set -e
export PATH="$oldpath"
if [ "$status" -eq 0 ]; then
    fail "gosec-high exited 0 with gosec missing from PATH"
fi
printf '%s\n' "$out" | grep -Fq 'gosec not found on PATH' ||
    fail "gosec-high missing-binary error was not clear (exit $status): $out"
[ "$status" -eq 127 ] &&
    fail "gosec-high exited 127 (unguarded missing binary) instead of fail-closed: $out"
pass "gosec-high fails closed with a clear error when gosec is missing"
