#!/usr/bin/env bash
# Stubbed maintainer-ceremony walkthrough: documented order, no remote write
# or signing before create-draft, create-draft refuses a signed directory.
# Mocked stubs plus one native refuse path. Does not build
# verify-package-manager-handoff.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
pass() { echo "PASS: $*"; }

docs=(
	"$root/README.md"
	"$root/docs/security.md"
	"$root/RELEASE_CHECKLIST.md"
)
inputs=(
	SFETCH_RELEASE_TAG
	SFETCH_MINISIGN_KEY
	SFETCH_MINISIGN_PUB
	SFETCH_PGP_KEY_ID
	SFETCH_GPG_HOMEDIR
	SFETCH_GPG_SIGNING_FINGERPRINT
	SFETCH_DECERNOR_BIN
	SFETCH_TAGGER_NAME
	SFETCH_TAGGER_EMAIL
	SFETCH_TAG_MESSAGE_DIR
	RELEASE_RUN_ID
	RELEASE_RUN_ATTEMPT
)
order=(
	release-preflight
	release-tag
	release-push-tag
	release-download
	release-checksums
	release-create-draft
	release-sign
	release-export-keys
	release-verify
	release-notes
	release-upload
	release-publish
	update-scoop-manifest
)
fingerprint=0CACA49B3119B6BC12B2CA11B9B485F294B9FE07

for doc in "${docs[@]}"; do
	for key in "${inputs[@]}"; do
		grep -q "$key" "$doc" || fail "$doc missing input $key"
	done
	grep -q "$fingerprint" "$doc" || fail "$doc missing approved primary fingerprint"
	python3 - "$doc" "${order[@]}" <<'PY' || fail "$doc ceremony order"
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
keys = sys.argv[2:]
pos = 0
for k in keys:
    i = text.find(k, pos)
    if i < 0:
        raise SystemExit(f"{k} missing or out of order after pos={pos}")
    pos = i + len(k)
PY
	# Bare RELEASE_TAG= is the rejected alias; SFETCH_RELEASE_TAG= is required.
	if grep -nE '(^|[^A-Z_])RELEASE_TAG=' "$doc" | grep -v SFETCH_RELEASE_TAG; then
		fail "$doc still documents bare RELEASE_TAG="
	fi
	if grep -nE 'gh release edit.*draft=false' "$doc" | grep -v 'Do not run' | grep -v 'never gh release edit'; then
		fail "$doc instructs gh release edit --draft=false"
	fi
done
pass "docs share one input block and ordered sequence"

grep -q 'verify-package-manager-handoff' "$root/Makefile" &&
	fail "do not add verify-package-manager-handoff yet"
pass "no verify-package-manager-handoff target"

scratch="$(mktemp -d /tmp/sft-walk.XXXXXX)"
trap 'rm -rf "$scratch"' EXIT
seq_log="$scratch/seq.log"
: >"$seq_log"
export SEQ_LOG="$seq_log" SEQ_PHASE_FILE="$scratch/phase"
printf '0\n' >"$SEQ_PHASE_FILE"
mkdir -p "$scratch/bin"

cat >"$scratch/bin/gh" <<'SH'
#!/usr/bin/env bash
echo "gh $*" >>"${SEQ_LOG:?}"
phase="$(cat "${SEQ_PHASE_FILE:?}")"
case "$*" in
*"release create"*|*"release upload"*|*"release edit"*|*"release publish"*)
	if [[ "$phase" -lt 5 ]]; then
		echo "error: remote write before create-draft" >&2
		exit 1
	fi
	;;
esac
case "$*" in
*"release edit"*draft=false*)
	echo "error: gh release edit --draft=false is not allowed" >&2
	exit 1
	;;
esac
exit 0
SH
cat >"$scratch/bin/minisign" <<'SH'
#!/usr/bin/env bash
echo "minisign $*" >>"${SEQ_LOG:?}"
phase="$(cat "${SEQ_PHASE_FILE:?}")"
if [[ "$*" == *-S* && "$phase" -lt 6 ]]; then
	echo "error: signing before create-draft" >&2
	exit 1
fi
exit 0
SH
cat >"$scratch/bin/gpg" <<'SH'
#!/usr/bin/env bash
echo "gpg $*" >>"${SEQ_LOG:?}"
phase="$(cat "${SEQ_PHASE_FILE:?}")"
if [[ "$*" == *detach-sign* && "$phase" -lt 6 ]]; then
	echo "error: signing before create-draft" >&2
	exit 1
fi
exit 0
SH
chmod +x "$scratch/bin/gh" "$scratch/bin/minisign" "$scratch/bin/gpg"
export PATH="$scratch/bin:$PATH"

# Native: create-draft refuses a directory that already contains signatures.
# gh is stubbed so the unexpected-file check is reached.
signed="$scratch/signed"
mkdir -p "$signed"
for name in sfetch_linux_amd64.tar.gz sfetch_linux_arm64.tar.gz \
	sfetch_windows_amd64.zip sfetch_windows_arm64.zip \
	sfetch_darwin_arm64.tar.gz install-sfetch.sh SHA256SUMS SHA512SUMS \
	SHA256SUMS.minisig; do
	printf 'x\n' >"$signed/$name"
done
if "$root/scripts/release-create-draft.sh" v1.2.3 "$signed" >/dev/null 2>"$scratch/create.err"; then
	fail "create-draft must refuse a directory containing SHA256SUMS.minisig"
fi
grep -q 'unexpected file' "$scratch/create.err" || {
	cat "$scratch/create.err" >&2
	fail "create-draft refuse path must name the extra signature file"
}
pass "create-draft refuses SHA256SUMS.minisig (native refuse path)"

run_phase() {
	local n="$1" cmd="$2"
	printf '%s\n' "$n" >"$SEQ_PHASE_FILE"
	eval "$cmd"
	echo "phase $n $cmd" >>"$seq_log"
}

# Negative control: signing or remote write while still in checksums (phase 4).
printf '4\n' >"$SEQ_PHASE_FILE"
if minisign -S -m SHA256SUMS >/dev/null 2>&1; then
	fail "minisign -S must be refused before create-draft"
fi
if gpg --detach-sign SHA256SUMS >/dev/null 2>&1; then
	fail "gpg --detach-sign must be refused before create-draft"
fi
if gh release create v1.2.3 --draft >/dev/null 2>&1; then
	fail "gh release create must be refused before create-draft"
fi
if gh release edit v1.2.3 --draft=false >/dev/null 2>&1; then
	fail "gh release edit --draft=false must always be refused"
fi
pass "negative control: no remote write or signing before create-draft"

: >"$seq_log"
run_phase 1 'true # preflight/message/tag'
run_phase 2 'true # select CI run+attempt'
run_phase 3 'true # download'
run_phase 4 'true # checksums'
run_phase 5 'gh release create v1.2.3 --draft --verify-tag'
run_phase 6 'minisign -S -m SHA256SUMS; gpg --detach-sign SHA256SUMS'
run_phase 7 'true # stage tagged keys'
run_phase 8 'true # verify'
run_phase 9 'gh release upload v1.2.3 SHA256SUMS.minisig'
run_phase 10 'true # verified publish (release-publish.sh, not gh edit)'
run_phase 11 'true # package-manager handoff'
grep -q 'release create' "$seq_log" || fail "walkthrough must record draft create"
grep -q 'minisign -S' "$seq_log" || fail "walkthrough must record signing after draft"
if grep -n 'minisign -S' "$seq_log" | head -n1 | awk -F: '{print $1}' >/dev/null; then
	python3 - "$seq_log" <<'PY' || fail "signing must follow create-draft in the log"
from pathlib import Path
import sys
lines = Path(sys.argv[1]).read_text().splitlines()
create = next(i for i, l in enumerate(lines) if "release create" in l)
sign = next(i for i, l in enumerate(lines) if "minisign -S" in l)
if not (create < sign):
    raise SystemExit(f"create={create} sign={sign}")
PY
fi
if grep -q 'draft=false' "$seq_log"; then
	fail "walkthrough must not invoke gh release edit --draft=false"
fi
pass "stubbed sequence: draft, then sign, no unverified publish"

echo "[ok] release ceremony walkthrough"
