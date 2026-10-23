#!/usr/bin/env bash
# Maintainer-ceremony walkthrough: documented order, real Make entrypoints,
# stubs only at the gh / signing / network boundary. No remote write or
# signing before create-draft. Does not build verify-package-manager-handoff.
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
	release-prepare-tag-message
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
view_fields=conclusion,headSha,status,attempt,event

check_doc() {
	local doc="$1"
	python3 - "$doc" "$view_fields" "${order[@]}" <<'PY' || return 1
import pathlib, re, sys
path = pathlib.Path(sys.argv[1])
want_fields = sys.argv[2]
text = path.read_text()
keys = sys.argv[3:]
pos = 0
for k in keys:
    i = text.find(k, pos)
    if i < 0:
        raise SystemExit(f"{k} missing or out of order after pos={pos}")
    pos = i + len(k)
msg = text.find("release-prepare-tag-message")
tag = text.find("release-tag")
if msg < 0 or tag < 0 or not (msg < tag):
    raise SystemExit("release-prepare-tag-message must appear before release-tag")
if re.search(r"--json[^\n]*runAttempt", text):
    raise SystemExit("runAttempt is not a gh run view field; use attempt")
if re.search(r"gh run view[^\n]*--json[^\n]*\bpath\b", text):
    raise SystemExit("gh run view does not support path; use the REST attempt resource")
if want_fields not in text:
    raise SystemExit(f"missing gh run view fields {want_fields}")
if "actions/runs/" not in text or "attempts/" not in text:
    raise SystemExit("workflow path must come from the REST attempt resource")
if "release-prepare-tag-message" not in text:
    raise SystemExit("missing make release-prepare-tag-message")
PY
}

for doc in "${docs[@]}"; do
	for key in "${inputs[@]}"; do
		grep -q "$key" "$doc" || fail "$doc missing input $key"
	done
	grep -q "$fingerprint" "$doc" || fail "$doc missing approved primary fingerprint"
	check_doc "$doc" || fail "$doc ceremony order / run-inspection fields"
	if grep -nE '(^|[^A-Z_])RELEASE_TAG=' "$doc" | grep -v SFETCH_RELEASE_TAG; then
		fail "$doc still documents bare RELEASE_TAG="
	fi
	if grep -nE 'gh release edit.*draft=false' "$doc" | grep -v 'Do not run' | grep -v 'never gh release edit'; then
		fail "$doc instructs gh release edit --draft=false"
	fi
done
pass "docs share one input block, message step, attempt fields, and ordered sequence"

# Revert-failing: restoring runAttempt or dropping the message step must fail.
mut="$(mktemp)"
trap 'rm -f "$mut"' EXIT
sed 's/status,attempt,event/status,runAttempt,event,path/' "$root/RELEASE_CHECKLIST.md" >"$mut"
if check_doc "$mut" 2>/dev/null; then
	fail "checker must reject restored runAttempt/path fields"
fi
sed '/release-prepare-tag-message/d' "$root/RELEASE_CHECKLIST.md" >"$mut"
if check_doc "$mut" 2>/dev/null; then
	fail "checker must reject a sequence that omits release-prepare-tag-message"
fi
rm -f "$mut"
trap - EXIT
pass "negative control: invalid gh fields and missing message step fail"

grep -q 'verify-package-manager-handoff' "$root/Makefile" &&
	fail "do not add verify-package-manager-handoff yet"
pass "no verify-package-manager-handoff target"

# This file must invoke real Make entrypoints, not placeholder phases.
if grep -nE 'true[[:space:]]*#' "$root/scripts/test-release-walkthrough.sh"; then
	fail "walkthrough still has true placeholder phases"
fi
grep -q 'make release-prepare-tag-message' "$root/scripts/test-release-walkthrough.sh" ||
	fail "walkthrough must invoke make release-prepare-tag-message"
grep -q 'make release-create-draft' "$root/scripts/test-release-walkthrough.sh" ||
	fail "walkthrough must invoke make release-create-draft"

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
json=""
prev=""
for a in "$@"; do
	if [[ "$prev" == "--json" ]]; then json="$a"; fi
	prev="$a"
done
if [[ -n "$json" ]]; then
	IFS=',' read -r -a fs <<<"$json"
	for f in "${fs[@]}"; do
		case "$f" in
		conclusion | headSha | status | attempt | event) ;;
		*)
			echo "Unknown JSON field: \"$f\"" >&2
			exit 1
			;;
		esac
	done
	printf '%s\n' '{"conclusion":"success","headSha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"completed","attempt":1,"event":"push"}'
	exit 0
fi
case "$*" in
*"release view"*) exit 1 ;;
*"/attempts/"*)
	printf '%s\n' '.github/workflows/release.yml'
	exit 0
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
m="" prev=""
for a in "$@"; do
	if [[ "$prev" == "-m" ]]; then m="$a"; fi
	prev="$a"
done
if [[ -n "$m" && "$*" == *-S* ]]; then
	printf 'minisig\n' >"${m}.minisig"
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
out="" prev=""
for a in "$@"; do
	if [[ "$prev" == "-o" ]]; then out="$a"; fi
	prev="$a"
done
if [[ "$*" == *detach-sign* && -n "$out" ]]; then
	printf 'asc\n' >"$out"
fi
exit 0
SH
chmod +x "$scratch/bin/gh" "$scratch/bin/minisign" "$scratch/bin/gpg"
export PATH="$scratch/bin:$PATH"

# Native: create-draft refuses a directory that already contains signatures.
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

# Documented run-inspection command, using the field list from the checklist.
fields="$(python3 - "$root/RELEASE_CHECKLIST.md" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r"gh run view[^\n]*--json ([A-Za-z,]+)", text)
if not m:
    raise SystemExit("gh run view --json field list missing")
print(m.group(1))
PY
)"
[ "$fields" = "$view_fields" ] || fail "checklist gh run view fields are $fields, want $view_fields"
RELEASE_RUN_ID=11 RELEASE_RUN_ATTEMPT=1
gh run view "$RELEASE_RUN_ID" --repo 3leaps/sfetch --json "$fields" >/dev/null ||
	fail "documented gh run view fields must be accepted by gh 2.94"
path="$(gh api "repos/3leaps/sfetch/actions/runs/${RELEASE_RUN_ID}/attempts/${RELEASE_RUN_ATTEMPT}" --jq .path)"
[ "$path" = ".github/workflows/release.yml" ] || fail "REST attempt resource must return the workflow path"
pass "run inspection uses attempt plus REST path"

fixture="$scratch/repo"
mkdir -p "$fixture/scripts/cmd/generate-checksums" "$fixture/docs/releases" "$fixture/dist/release"
cp "$root/Makefile" "$fixture/Makefile"
printf '1.2.3\n' >"$fixture/VERSION"
printf 'module github.com/3leaps/sfetch\n\ngo 1.26.0\n' >"$fixture/go.mod"
cp "$root/scripts/release-tag-operator.sh" "$root/scripts/release-prepare-tag-message.py" \
	"$root/scripts/release-create-draft.sh" "$root/scripts/sign-release-manifests.sh" \
	"$root/scripts/install-sfetch.sh" "$fixture/scripts/"
cp "$root/scripts/cmd/generate-checksums/generate-checksums.go" \
	"$fixture/scripts/cmd/generate-checksums/"
printf 'notes for v1.2.3\n' >"$fixture/docs/releases/v1.2.3.md"

install_logger() {
	local dest="$1"
	local label="$2"
	cat >"$dest" <<SH
#!/usr/bin/env bash
echo "$label \$*" >>"\${SEQ_LOG:?}"
exit 0
SH
	chmod +x "$dest"
}
install_logger "$fixture/scripts/release-verify-committed-anchors.sh" "release-verify-committed-anchors"
install_logger "$fixture/scripts/release-inspect-tag-ruleset.sh" "release-inspect-tag-ruleset"
install_logger "$fixture/scripts/test-makefile-release-tag.sh" "test-makefile-release-tag"
install_logger "$fixture/scripts/release-tag.sh" "release-tag"
install_logger "$fixture/scripts/release-push-tag.sh" "release-push-tag"
install_logger "$fixture/scripts/release-verify-published-tag.sh" "release-verify-published-tag"
install_logger "$fixture/scripts/verify-signatures.sh" "verify-signatures"
install_logger "$fixture/scripts/verify-public-key.sh" "verify-public-key"
install_logger "$fixture/scripts/release-stage-tagged-pubkeys.sh" "release-stage-tagged-pubkeys"
install_logger "$fixture/scripts/upload-release-assets.sh" "upload-release-assets"
install_logger "$fixture/scripts/release-publish.sh" "release-publish"
cat >"$fixture/scripts/release-tag-common.sh" <<'SH'
tag_version() { echo "tag_version" >>"${SEQ_LOG:?}"; }
tag_identity() { echo "tag_identity" >>"${SEQ_LOG:?}"; }
tag_checkout() { echo "tag_checkout" >>"${SEQ_LOG:?}"; }
tag_key_selector() { echo "tag_key_selector" >>"${SEQ_LOG:?}"; }
tag_expected_message() { echo "tag_expected_message" >>"${SEQ_LOG:?}"; }
SH
cat >"$fixture/scripts/release-fetch-ci-artifacts.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo "release-fetch-ci-artifacts $*" >>"${SEQ_LOG:?}"
dest="${2:?}"
mkdir -p "$dest"
for name in sfetch_linux_amd64.tar.gz sfetch_linux_arm64.tar.gz \
	sfetch_windows_amd64.zip sfetch_windows_arm64.zip \
	sfetch_darwin_arm64.tar.gz; do
	printf 'pkg %s\n' "$name" >"$dest/$name"
done
cp "$(cd "$(dirname "$0")/.." && pwd)/scripts/install-sfetch.sh" "$dest/install-sfetch.sh"
commit="$(git -C "$(cd "$(dirname "$0")/.." && pwd)" rev-parse HEAD)"
printf 'tag=%s\nobject=%s\ncommit=%s\nrun=11\nattempt=1\n' \
	"$1" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "$commit" >"${dest}.anchor"
SH
chmod +x "$fixture/scripts/release-fetch-ci-artifacts.sh" "$fixture/scripts/"*.sh

git -C "$fixture" init -q
git -C "$fixture" config user.email walkthrough@example.invalid
git -C "$fixture" config user.name walkthrough
git -C "$fixture" checkout -q -b main
git -C "$fixture" add VERSION go.mod docs scripts Makefile
git -C "$fixture" commit -q -m "fixture"

msgdir="$scratch/messages/v1.2.3"
mkdir -p "$scratch/messages"
gpg_home="$scratch/gpg-home"
mkdir -m 700 -p "$gpg_home"
printf 'dummy-minisign-key\n' >"$scratch/minisign.key"
export SFETCH_RELEASE_TAG=v1.2.3
export SFETCH_TAG_MESSAGE_DIR="$msgdir"
export SFETCH_TAGGER_NAME=walkthrough
export SFETCH_TAGGER_EMAIL=walkthrough@example.invalid
export SFETCH_MINISIGN_KEY="$scratch/minisign.key"
export SFETCH_MINISIGN_PUB="$scratch/minisign.key"
export SFETCH_PGP_KEY_ID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
export SFETCH_GPG_HOMEDIR="$gpg_home"
export SFETCH_GPG_SIGNING_FINGERPRINT=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
export RELEASE_RUN_ID=11
export RELEASE_RUN_ATTEMPT=1

run_make() {
	local n="$1" target="$2"
	shift 2
	printf '%s\n' "$n" >"$SEQ_PHASE_FILE"
	echo "make $target" >>"$seq_log"
	make -C "$fixture" "$target" \
		"SFETCH_RELEASE_TAG=v1.2.3" \
		"SFETCH_TAG_MESSAGE_DIR=$msgdir" \
		"SFETCH_MINISIGN_KEY=$scratch/minisign.key" \
		"SFETCH_PGP_KEY_ID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!" \
		"SFETCH_GPG_HOMEDIR=$gpg_home" \
		"$@"
}

: >"$seq_log"
run_make 1 release-preflight
run_make 1 release-prepare-tag-message
[ -f "$msgdir/message.txt" ] || fail "make release-prepare-tag-message must write message.txt"
run_make 1 release-tag
run_make 1 release-push-tag
run_make 3 release-download
run_make 4 release-checksums
run_make 5 release-create-draft
run_make 6 release-sign
run_make 7 release-export-keys
run_make 8 release-verify
run_make 9 release-notes
run_make 9 release-upload
run_make 10 release-publish
if make -C "$fixture" update-scoop-manifest \
	"SFETCH_RELEASE_TAG=v1.2.3" \
	"SCOOP_BUCKET_DIR=$scratch/missing-scoop" >/dev/null 2>"$scratch/scoop.err"; then
	fail "make update-scoop-manifest must fail closed without a sibling bucket"
fi
echo "make update-scoop-manifest" >>"$seq_log"
grep -qi 'not found' "$scratch/scoop.err" || fail "scoop fail-closed (log: $(cat "$scratch/scoop.err"))"

grep -q 'make release-prepare-tag-message' "$seq_log" || fail "walkthrough must run make release-prepare-tag-message"
grep -q 'make release-create-draft' "$seq_log" || fail "walkthrough must run make release-create-draft"
grep -q 'release create' "$seq_log" || fail "walkthrough must record draft create via gh"
grep -q 'minisign -S' "$seq_log" || fail "walkthrough must record signing after draft"
python3 - "$seq_log" <<'PY' || fail "signing must follow create-draft in the log"
from pathlib import Path
import sys
lines = Path(sys.argv[1]).read_text().splitlines()
create = next(i for i, l in enumerate(lines) if "make release-create-draft" in l)
sign = next(i for i, l in enumerate(lines) if "make release-sign" in l)
if not (create < sign):
    raise SystemExit(f"create={create} sign={sign}")
gh_create = next(i for i, l in enumerate(lines) if "release create" in l)
minis = next(i for i, l in enumerate(lines) if "minisign -S" in l)
if not (gh_create < minis):
    raise SystemExit(f"gh_create={gh_create} minisign={minis}")
PY
if grep -q 'draft=false' "$seq_log"; then
	fail "walkthrough must not invoke gh release edit --draft=false"
fi
if grep -qE 'true[[:space:]]*#' "$seq_log"; then
	fail "walkthrough log still contains true placeholder phases"
fi
pass "Make sequence: message, draft, then sign, no unverified publish"

echo "[ok] release ceremony walkthrough"
