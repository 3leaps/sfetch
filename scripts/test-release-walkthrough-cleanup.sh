#!/usr/bin/env bash
# Revert-failing: walkthrough temps are registered in the parent shell and
# removed on EXIT after success and after a forced failure. Never glob
# /tmp/sft-walk* or /tmp/sfetch-*. An unrelated decoy in the same prefix survives.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
pass() { echo "PASS: $*"; }

walk="$root/scripts/test-release-walkthrough.sh"
[[ -x "$walk" ]] || fail "missing $walk"

grep -nE '\$\(register_dir\)' "$walk" &&
	fail "walkthrough still captures register_dir with command substitution"
grep -q 'printf -v "$dest"' "$walk" ||
	fail "walkthrough register_dir must write the dest var in the parent shell"
grep -q 'CLEANUP_DIRS+=' "$walk" ||
	fail "walkthrough must append registered dirs in the parent shell"
grep -q 'trap cleanup EXIT' "$walk" ||
	fail "walkthrough must arm an EXIT trap that removes registered temps"
if grep -nE 'rm[[:space:]]+-rf[[:space:]]+["'"'"']?/tmp/sfetch' "$walk"; then
	fail "walkthrough must not broadly remove /tmp/sfetch-*"
fi
if grep -nE 'rm[[:space:]]+-rf[[:space:]]+["'"'"']?/tmp/sft-walk\*' "$walk"; then
	fail "walkthrough must not broadly remove /tmp/sft-walk*"
fi
pass "walkthrough registers dest-var temps and refuses glob cleanup"

snapshot_tmp() {
	python3 - <<'PY'
import glob
patterns = (
    "/tmp/sft-walk*",
    "/tmp/sfetch-tag-gnupg.*",
    "/tmp/sfetch-tag-sign-gnupg.*",
)
for p in patterns:
    for m in glob.glob(p):
        print(m)
PY
}

assert_gone() {
	local record="$1" decoy="$2" before="$3"
	local kind path
	[[ -s "$record" ]] || fail "walkthrough did not record registered temps"
	while read -r kind path; do
		[[ -n "$path" ]] || continue
		[[ ! -e "$path" ]] || fail "leaked $kind $path"
	done <"$record"
	[[ -d "$decoy" ]] || fail "cleanup removed the unrelated decoy $decoy"
	python3 - "$before" "$decoy" <<'PY' || fail "walkthrough leaked tmp dirs outside its registry"
import glob, pathlib, sys
before = set(pathlib.Path(sys.argv[1]).read_text().splitlines()) - {""}
decoy = sys.argv[2]
now = set()
for p in ("/tmp/sft-walk*", "/tmp/sfetch-tag-gnupg.*", "/tmp/sfetch-tag-sign-gnupg.*"):
    now.update(glob.glob(p))
leaked = sorted(now - before - {decoy})
if leaked:
    raise SystemExit("leaked: " + " ".join(leaked))
if decoy not in now:
    raise SystemExit("decoy missing")
PY
}

decoy="$(mktemp -d /tmp/sft-walk.XXXXXX)" || fail "decoy mktemp"
before="$(mktemp)"
record_ok="$(mktemp)"
record_fail="$(mktemp)"
trap 'rm -rf "$decoy"; rm -f "$before" "$record_ok" "$record_fail"' EXIT
snapshot_tmp >"$before"
printf '%s\n' "$decoy" >>"$before"

echo "running walkthrough (success)..."
if ! SFETCH_WALKTHROUGH_RECORD="$record_ok" "$walk"; then
	fail "walkthrough success path must pass"
fi
assert_gone "$record_ok" "$decoy" "$before"
pass "success path removes only this-run temps; decoy survives"

echo "running walkthrough (forced failure at release-tag)..."
set +e
SFETCH_WALKTHROUGH_RECORD="$record_fail" SFETCH_WALKTHROUGH_FAIL_AT=release-tag "$walk"
child_rc=$?
set -e
[[ "$child_rc" -ne 0 ]] || fail "forced-failure walkthrough must exit non-zero"
assert_gone "$record_fail" "$decoy" "$before"
pass "failure-path EXIT trap removes only this-run temps; decoy survives"

echo "[ok] walkthrough parent-shell cleanup"
