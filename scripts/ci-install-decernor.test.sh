#!/usr/bin/env bash
# ci-install-decernor.sh must print only the binary path on stdout.
# sha256sum --check "file: OK" on stdout makes GITHUB_ENV assignment invalid.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

dest="$(mktemp -d "${TMPDIR:-/tmp}/decernor-ci-test.XXXXXX")"
trap 'rm -rf "$dest"' EXIT
err="$dest/stderr"
set +e
out="$("$root/scripts/ci-install-decernor.sh" "$dest" 2>"$err")"
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "ci-install-decernor.sh exited $rc: $(cat "$err")"
n="$(printf '%s\n' "$out" | wc -l)"
[ "$n" -eq 1 ] || fail "stdout must be exactly one line (got $n): $(printf '%s' "$out" | od -An -tx1)"
[[ "$out" == /*/decernor ]] || fail "stdout must be an absolute path ending in /decernor: $out"
[ -x "$out" ] && [ ! -L "$out" ] || fail "installed binary is not a regular executable: $out"
grep -q ': OK' <<<"$out" && fail "sha256sum --check wrote to stdout (GITHUB_ENV would reject this)"
echo "[ok] Decernor CI install stdout is a single path"
