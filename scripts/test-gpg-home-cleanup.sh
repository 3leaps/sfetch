#!/usr/bin/env bash
# Revert-failing: GnuPG test homes must be registered in the parent shell.
# Command substitution loses GPG_HOMES+=. Cleanup may only remove this run's
# homes; never glob /tmp/sfetch-gpg.*.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
pass() { echo "PASS: $*"; }

suites=(
	"$root/scripts/test-install-gpg-mutants.sh"
	"$root/scripts/test-install-anchor-select.sh"
)
for suite in "${suites[@]}"; do
	grep -nE '\$\(new_gpg_home\)' "$suite" &&
		fail "$suite still captures new_gpg_home with command substitution"
	grep -q 'printf -v "$dest"' "$suite" ||
		fail "$suite new_gpg_home must write the dest var in the parent shell"
	grep -nE 'rm[[:space:]]+-rf[[:space:]]+["'\'']?/tmp/sfetch-gpg' "$suite" &&
		fail "$suite must not broadly remove /tmp/sfetch-gpg.*"
	grep -q 'GnuPG home still exists after cleanup' "$suite" ||
		fail "$suite must assert this-run homes are gone after cleanup"
	grep -q 'parent GnuPG home registry empty' "$suite" ||
		fail "$suite must fail when the parent registry is empty"
done
pass "both GPG suites register dest-var homes and refuse glob cleanup"

# Runtime: dest-var registration is visible; command substitution is not.
GPG_HOMES=()
fail() { echo "FAIL: $*" >&2; exit 1; }
new_gpg_home() {
	local dest="${1:?new_gpg_home dest var}"
	local d
	d="$(mktemp -d /tmp/sfetch-gpg.XXXXXX)" || fail "mktemp GnuPG home"
	chmod 700 "$d" || fail "chmod GnuPG home"
	GPG_HOMES+=("$d")
	printf -v "$dest" '%s' "$d"
}
decoy="$(mktemp -d /tmp/sfetch-gpg.XXXXXX)" || fail "decoy mktemp"
new_gpg_home got
[ -n "$got" ] && [ -d "$got" ] || fail "dest-var home missing"
[ "${#GPG_HOMES[@]}" -eq 1 ] || fail "parent registry empty after dest-var call"
[ "${GPG_HOMES[0]}" = "$got" ] || fail "parent registry does not match dest-var"

# Negative: the old calling convention loses the append.
GPG_HOMES=()
_subshell_only() {
	local d
	d="$(mktemp -d /tmp/sfetch-gpg.XXXXXX)" || fail "mktemp"
	GPG_HOMES+=("$d")
	printf '%s' "$d"
}
lost="$(_subshell_only)"
[ "${#GPG_HOMES[@]}" -eq 0 ] || fail "negative control: subshell += was visible"
[ -d "$lost" ] || fail "negative control home missing"
# Empty parent cleanup must not remove it, and must not glob.
for h in "${GPG_HOMES[@]+"${GPG_HOMES[@]}"}"; do
	rm -rf "$h"
done
[ -d "$lost" ] || fail "empty parent registry must not remove the subshell home"
[ -d "$decoy" ] || fail "cleanup must not remove other /tmp/sfetch-gpg.* directories"
rm -rf "$lost"
[ ! -e "$lost" ] || fail "this-run home still exists after explicit cleanup"
[ -d "$decoy" ] || fail "this-run cleanup removed the decoy"
gpgconf --homedir "$got" --kill all >/dev/null 2>&1 || true
rm -rf "$got"
[ ! -e "$got" ] || fail "dest-var home still exists after cleanup"
[ -d "$decoy" ] || fail "dest-var cleanup removed the decoy"
rm -rf "$decoy"
pass "dest-var registers; command substitution does not; no glob cleanup"

# Failure-path: EXIT trap removes only this child run's homes.
fail_dir="$(mktemp -d /tmp/sft-gpg-failpath.XXXXXX)"
decoy2="$(mktemp -d /tmp/sfetch-gpg.XXXXXX)" || fail "failure-path decoy"
set +e
bash -c '
set -euo pipefail
GPG_HOMES=()
fail() { echo "FAIL: $*" >&2; exit 1; }
new_gpg_home() {
	local dest="${1:?dest}" d
	d="$(mktemp -d /tmp/sfetch-gpg.XXXXXX)" || fail "mktemp"
	chmod 700 "$d"
	GPG_HOMES+=("$d")
	printf -v "$dest" "%s" "$d"
}
cleanup() {
	local h recorded=("${GPG_HOMES[@]+"${GPG_HOMES[@]}"}")
	printf "%s\n" "${recorded[@]}" >"$1/homes"
	for h in "${recorded[@]}"; do
		[ -n "$h" ] || continue
		gpgconf --homedir "$h" --kill all >/dev/null 2>&1 || true
		rm -rf "$h"
	done
	for h in "${recorded[@]}"; do
		[ -n "$h" ] || continue
		[ ! -e "$h" ] || { echo "FAIL: leaked $h" >&2; exit 1; }
	done
}
trap "cleanup \"$1\"" EXIT
new_gpg_home h
printf "%s\n" "$h" >"$1/created"
exit 1
' _ "$fail_dir"
child_rc=$?
set -e
[ "$child_rc" -ne 0 ] || fail "failure-path child must exit non-zero"
created="$(cat "$fail_dir/created")"
[ -n "$created" ] || fail "failure-path did not record a home"
[ ! -e "$created" ] || fail "failure-path leaked GnuPG home $created"
[ -d "$decoy2" ] || fail "failure-path cleanup removed another /tmp/sfetch-gpg.* directory"
rm -rf "$fail_dir" "$decoy2"
pass "failure-path EXIT trap removes only this-run homes"

echo "[ok] GnuPG home parent-shell cleanup"
