#!/usr/bin/env bash
# Regression harness for make release-verify-checksums (fail-closed).
# Asserts exit status only (zero vs non-zero) — not make-specific codes or
# presence/absence of success strings. Cover both SHA256SUMS and SHA512SUMS.
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

run_verify() {
	local dir="$1"
	# Force /bin/sh so Linux CI (dash) is exercised even on bash hosts.
	make -s release-verify-checksums DIST_RELEASE="$dir" SHELL="${MAKE_SHELL:-/bin/sh}"
}

# Initialize before trap so early exit never hits unbound variables under set -u.
valid=""
corrupt=""
absent256=""
absent512=""
empty256=""
empty512=""
trap 'rm -rf "${valid:-}" "${corrupt:-}" "${absent256:-}" "${absent512:-}" "${empty256:-}" "${empty512:-}" 2>/dev/null || true' EXIT

# --- Case 1: valid fixture exits 0 ---
valid="$(mktemp -d "${TMPDIR:-/tmp}/sft-rv-valid.XXXXXX")"

printf 'payload-a\n' >"$valid/a.bin"
printf 'payload-b\n' >"$valid/b.bin"
(
	cd "$valid"
	shasum -a 256 a.bin b.bin >SHA256SUMS
	shasum -a 512 a.bin b.bin >SHA512SUMS
)
if run_verify "$valid"; then
	pass "valid fixture exits 0"
else
	fail "valid fixture should exit 0"
fi

# --- Case 2: corrupted checksum exits non-zero ---
corrupt="$(mktemp -d "${TMPDIR:-/tmp}/sft-rv-corrupt.XXXXXX")"
cp -R "$valid/." "$corrupt/"
python3 - "$corrupt/SHA256SUMS" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
lines = p.read_text().splitlines(True)
c = lines[0][0]
lines[0] = ('0' if c != '0' else '1') + lines[0][1:]
p.write_text(''.join(lines))
PY
if run_verify "$corrupt"; then
	fail "corrupted checksum should exit non-zero"
else
	pass "corrupted checksum exits non-zero"
fi

# --- Case 3: absent SHA256SUMS exits non-zero ---
absent256="$(mktemp -d "${TMPDIR:-/tmp}/sft-rv-absent256.XXXXXX")"
cp "$valid/a.bin" "$absent256/"
cp "$valid/b.bin" "$absent256/"
cp "$valid/SHA512SUMS" "$absent256/"
if run_verify "$absent256"; then
	fail "absent SHA256SUMS should exit non-zero"
else
	pass "absent SHA256SUMS exits non-zero"
fi

# --- Case 4: absent SHA512SUMS exits non-zero ---
absent512="$(mktemp -d "${TMPDIR:-/tmp}/sft-rv-absent512.XXXXXX")"
cp "$valid/a.bin" "$absent512/"
cp "$valid/b.bin" "$absent512/"
cp "$valid/SHA256SUMS" "$absent512/"
if run_verify "$absent512"; then
	fail "absent SHA512SUMS should exit non-zero"
else
	pass "absent SHA512SUMS exits non-zero"
fi

# --- Case 5: empty SHA256SUMS exits non-zero ---
empty256="$(mktemp -d "${TMPDIR:-/tmp}/sft-rv-empty256.XXXXXX")"
cp -R "$valid/." "$empty256/"
: >"$empty256/SHA256SUMS"
if run_verify "$empty256"; then
	fail "empty SHA256SUMS should exit non-zero"
else
	pass "empty SHA256SUMS exits non-zero"
fi

# --- Case 6: empty SHA512SUMS exits non-zero ---
empty512="$(mktemp -d "${TMPDIR:-/tmp}/sft-rv-empty512.XXXXXX")"
cp -R "$valid/." "$empty512/"
: >"$empty512/SHA512SUMS"
if run_verify "$empty512"; then
	fail "empty SHA512SUMS should exit non-zero"
else
	pass "empty SHA512SUMS exits non-zero"
fi

echo "[ok] release-verify-checksums regression harness complete"
