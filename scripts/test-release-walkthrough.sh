#!/usr/bin/env bash
# Maintainer-ceremony walkthrough: documented order, real Make entrypoints,
# real internal guards. Stub only gh / curl at the network boundary.
# Signing uses disposable real GnuPG and minisign fixture keys, not PATH loggers.
# Temps are registered in this parent shell and removed on EXIT (success or fail).
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
internal_scripts=(
	release-verify-committed-anchors.sh
	release-inspect-tag-ruleset.sh
	test-makefile-release-tag.sh
	release-tag.sh
	release-push-tag.sh
	release-tag-common.sh
	release-tag-operator.sh
	release-verify-published-tag.sh
	release-fetch-ci-artifacts.sh
	verify-signatures.sh
	verify-public-key.sh
	release-stage-tagged-pubkeys.sh
	upload-release-assets.sh
	release-publish.sh
	release-create-draft.sh
	sign-release-manifests.sh
	release-verify-tag.sh
	release-verify-remote-tag.sh
	verify-pinned-tag.sh
	release-origin.sh
	release-decernor.sh
	release-prepare-tag-message.py
)

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
CLEANUP_FILES=("$mut")
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
CLEANUP_FILES=()
trap - EXIT
pass "negative control: invalid gh fields and missing message step fail"

grep -q 'verify-package-manager-handoff' "$root/Makefile" &&
	fail "do not add verify-package-manager-handoff yet"
pass "no verify-package-manager-handoff target"

self="$root/scripts/test-release-walkthrough.sh"
if grep -nE 'true[[:space:]]*#' "$self"; then
	fail "walkthrough still has true placeholder phases"
fi
grep -q 'make release-prepare-tag-message' "$self" ||
	fail "walkthrough must invoke make release-prepare-tag-message"
grep -q 'make release-create-draft' "$self" ||
	fail "walkthrough must invoke make release-create-draft"
if grep -nE '^install_logger[[:space:]]*\(' "$self"; then
	fail "walkthrough must not replace internal scripts with success loggers"
fi
grep -q 'pwd -P' "$self" || fail "walkthrough must canonicalize the fixture root with pwd -P"
grep -q 'printf -v "$dest"' "$self" ||
	fail "walkthrough must assign registered temps in the parent shell"
if grep -nE 'rm[[:space:]]+-rf[[:space:]]+["'"'"']?/tmp/sfetch' "$self"; then
	fail "walkthrough must not broadly remove /tmp/sfetch-*"
fi
if grep -nE 'rm[[:space:]]+-rf[[:space:]]+["'"'"']?/tmp/sft-walk\*' "$self"; then
	fail "walkthrough must not broadly remove /tmp/sft-walk*"
fi
pass "walkthrough source keeps real internals and parent-shell cleanup"

# ---------------------------------------------------------------------------
# Parent-shell registry. Command substitution must not own the +=.
# ---------------------------------------------------------------------------
CLEANUP_DIRS=()
CLEANUP_FILES=()
CLEANUP_PIDS=()

record_cleanup() {
	local kind="${1:?}" path="${2:?}"
	case "$kind" in
	dir) CLEANUP_DIRS+=("$path") ;;
	file) CLEANUP_FILES+=("$path") ;;
	pid) CLEANUP_PIDS+=("$path") ;;
	*) fail "unknown cleanup kind $kind" ;;
	esac
	if [[ -n "${SFETCH_WALKTHROUGH_RECORD:-}" ]]; then
		printf '%s %s\n' "$kind" "$path" >>"$SFETCH_WALKTHROUGH_RECORD"
	fi
}

register_dir() {
	local dest="${1:?register_dir dest var}"
	local template="${2:-${TMPDIR:-/tmp}/sft-walk.XXXXXX}"
	local d
	d="$(mktemp -d "$template")" || fail "mktemp $template"
	d="$(cd "$d" && pwd -P)"
	record_cleanup dir "$d"
	printf -v "$dest" '%s' "$d"
}

cleanup() {
	local p d
	for p in "${CLEANUP_PIDS[@]+"${CLEANUP_PIDS[@]}"}"; do
		[[ -n "$p" ]] || continue
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	for d in "${CLEANUP_DIRS[@]+"${CLEANUP_DIRS[@]}"}"; do
		[[ -n "$d" ]] || continue
		gpgconf --homedir "$d" --kill all >/dev/null 2>&1 || true
		rm -rf "$d"
	done
	for d in "${CLEANUP_FILES[@]+"${CLEANUP_FILES[@]}"}"; do
		[[ -n "$d" ]] || continue
		rm -f "$d"
	done
}
trap cleanup EXIT

assert_no_symlink_ancestors() {
	local component="$1"
	while [[ "$component" != / ]]; do
		[[ ! -L "$component" ]] || fail "path has symlink ancestor: $component ($1)"
		component="${component%/*}"
		[[ -n "$component" ]] || component=/
	done
}

for tool in minisign gpg gpgconf git jq python3 go; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
decernor_bin="${SFETCH_DECERNOR_BIN:-$(command -v decernor || true)}"
[[ -n "$decernor_bin" ]] || fail "SFETCH_DECERNOR_BIN / decernor required"
[[ "$decernor_bin" == /* ]] || decernor_bin="$(command -v "$decernor_bin")"
[[ "$decernor_bin" == /* && -f "$decernor_bin" && -x "$decernor_bin" && ! -L "$decernor_bin" ]] ||
	fail "Decernor binary must be an absolute executable regular file"
export SFETCH_DECERNOR_BIN="$decernor_bin"

# Allocate the fixture root through a symlink (Linux stand-in for macOS /tmp
# -> /private/tmp) and canonicalize immediately. Do not weaken the production
# symlink guard: a message directory reached through a symlink still fails.
register_dir real_tmp "${TMPDIR:-/tmp}/sft-walk-real.XXXXXX"
register_dir link_parent "${TMPDIR:-/tmp}/sft-walk-link.XXXXXX"
ln -s "$real_tmp" "$link_parent/tmp"
raw_scratch="$(mktemp -d "$link_parent/tmp/sft-walk.XXXXXX")" || fail "mktemp via symlink tmp"
scratch="$(cd "$raw_scratch" && pwd -P)"
record_cleanup dir "$scratch"
[[ "$raw_scratch" != "$scratch" ]] || fail "symlink tmp root must differ from pwd -P"
assert_no_symlink_ancestors "$scratch"
component="$raw_scratch"
raw_has_link=0
while [[ "$component" != / ]]; do
	if [[ -L "$component" ]]; then raw_has_link=1; fi
	component="${component%/*}"
	[[ -n "$component" ]] || component=/
done
[[ "$raw_has_link" == 1 ]] || fail "uncanonicalized scratch should have a symlink ancestor"
pass "fixture root canonicalized through a symlink tmp (pwd -P)"

seq_log="$scratch/seq.log"
: >"$seq_log"
export SEQ_LOG="$seq_log" SEQ_PHASE_FILE="$scratch/phase"
printf '0\n' >"$SEQ_PHASE_FILE"
mkdir -p "$scratch/bin" "$scratch/fx" "$scratch/draft"

# Network / API boundary only. Real git remote ops go to a local bare origin
# via insteadOf; real gpg and minisign stay on PATH.
cat >"$scratch/bin/curl" <<'SH'
#!/usr/bin/env bash
echo "curl $*" >>"${SEQ_LOG:?}"
echo "error: walkthrough must not call curl" >&2
exit 1
SH
cat >"$scratch/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo "gh $*" >>"${SEQ_LOG:?}"
phase="$(cat "${SEQ_PHASE_FILE:?}")"
api_path=""
jq_filter=""
json_fields=""
outdir=""
prev=""
args=("$@")
for a in "${args[@]}"; do
	if [[ "$prev" == "--jq" ]]; then jq_filter="$a"; prev=""; continue; fi
	if [[ "$prev" == "--json" ]]; then json_fields="$a"; prev=""; continue; fi
	if [[ "$prev" == "--dir" ]]; then outdir="$a"; prev=""; continue; fi
	case "$a" in
	--jq | --json | --dir) prev="$a"; continue ;;
	esac
	case "$a" in
	repos/* | */repos/*) api_path="${a#*repos/}"; api_path="repos/${api_path}" ;;
	esac
done
write_before=0
case "$*" in
*"release create"* | *"release upload"* | *"release edit"* | *"release publish"* | *"release download"*)
	write_before=1
	;;
esac
if [[ "$write_before" == 1 && "$phase" -lt 5 ]]; then
	echo "error: remote write before create-draft" >&2
	exit 1
fi
if [[ -n "$json_fields" && "$*" == *"run view"* ]]; then
	IFS=',' read -r -a fs <<<"$json_fields"
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
state="$(cat "${FIXTURE_DIR:?}/release-state" 2>/dev/null || echo absent)"
commit=""
tag_object=""
if [[ -n "${FIXTURE_REPO:-}" && -d "${FIXTURE_REPO:-}/.git" ]]; then
	commit="$(git -C "$FIXTURE_REPO" rev-parse HEAD 2>/dev/null || true)"
	if git -C "$FIXTURE_REPO" rev-parse "refs/tags/v1.2.3" >/dev/null 2>&1; then
		tag_object="$(git -C "$FIXTURE_REPO" rev-parse "refs/tags/v1.2.3")"
		commit="$(git -C "$FIXTURE_REPO" rev-parse "refs/tags/v1.2.3^{}")"
	fi
fi
[[ -n "$commit" ]] || commit="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
emit() {
	local body="$1"
	if [[ -n "$jq_filter" ]]; then
		jq -r -c "$jq_filter" <<<"$body"
	else
		printf '%s\n' "$body"
	fi
}
case "$*" in
*"release create"* | *"release upload"*)
	mkdir -p "${FIXTURE_DRAFT:?}"
	skip=0
	for a in "${args[@]}"; do
		if [[ "$skip" == 1 ]]; then skip=0; continue; fi
		case "$a" in
		--notes-file | --title | --repo | --dir | --json | --jq)
			skip=1
			continue
			;;
		-*) continue ;;
		esac
		if [[ -f "$a" ]]; then cp "$a" "$FIXTURE_DRAFT/$(basename "$a")"; fi
	done
	if [[ "$*" == *"release create"* ]]; then
		printf 'draft\n' >"$FIXTURE_DIR/release-state"
	fi
	exit 0
	;;
*"release download"*)
	[[ -n "$outdir" ]] || exit 1
	mkdir -p "$outdir"
	cp "${FIXTURE_DRAFT:?}"/* "$outdir/"
	exit 0
	;;
*"release edit"*draft=false*)
	printf 'published\n' >"$FIXTURE_DIR/release-state"
	exit 0
	;;
*"release edit"*)
	exit 0
	;;
*"release view"*)
	[[ "$state" != absent ]] || exit 1
	if [[ -n "$json_fields" || -n "$jq_filter" ]]; then
		draft=true
		[[ "$state" == published ]] && draft=false
		names="$(cd "${FIXTURE_DRAFT:?}" && ls -1 | jq -R . | jq -s 'map({name: .})')"
		body="$(jq -n --argjson a "$names" --argjson d "$draft" '{isDraft: $d, assets: $a}')"
		emit "$body"
		exit 0
	fi
	exit 0
	;;
esac
case "$api_path" in
*"/attempts/"*)
	path="${FIXTURE_WORKFLOW_PATH:-.github/workflows/release.yml}"
	body="$(jq -n --arg p "$path" --arg c "$commit" --argjson a "${RELEASE_RUN_ATTEMPT:-1}" \
		'{path:$p,event:"push",head_branch:"v1.2.3",head_sha:$c,status:"completed",conclusion:"success",run_attempt:$a}')"
	emit "$body"
	exit 0
	;;
*"/artifacts/"*"/zip")
	cat "${FIXTURE_ZIP:?}"
	exit 0
	;;
*"/artifacts")
	digest="sha256:$(shasum -a 256 "${FIXTURE_ZIP:?}" | awk '{print $1}')"
	body="$(jq -n --arg d "$digest" --arg c "$commit" \
		'{total_count:1,artifacts:[{id:501,name:"release-packages-v1.2.3",expired:false,digest:$d,workflow_run:{id:11,head_sha:$c}}]}')"
	emit "$body"
	exit 0
	;;
*"actions/runs/"*)
	body="$(jq -n --argjson a "${RELEASE_RUN_ATTEMPT:-1}" '{run_attempt:$a}')"
	emit "$body"
	exit 0
	;;
*"rulesets/"*[0-9]*)
	emit "$(cat "$FIXTURE_DIR/ruleset.json")"
	exit 0
	;;
*"rulesets"*)
	emit "$(cat "$FIXTURE_DIR/rulesets.json")"
	exit 0
	;;
*"git/ref/tags/"*)
	[[ -n "$tag_object" ]] || exit 1
	body="$(jq -n --arg s "$tag_object" '{object:{type:"tag",sha:$s}}')"
	emit "$body"
	exit 0
	;;
*"git/tags/"*)
	[[ -n "$tag_object" ]] || exit 1
	body="$(jq -n --arg t v1.2.3 --arg c "$commit" \
		'{tag:$t,object:{type:"commit",sha:$c},verification:{verified:true,reason:"valid"}}')"
	emit "$body"
	exit 0
	;;
esac
exit 0
SH
chmod +x "$scratch/bin/gh" "$scratch/bin/curl"
export PATH="$scratch/bin:$PATH"
export FIXTURE_DIR="$scratch/fx" FIXTURE_DRAFT="$scratch/draft"
printf 'absent\n' >"$FIXTURE_DIR/release-state"
printf '%s\n' '[[{"id":1,"target":"tag","enforcement":"active"}]]' >"$FIXTURE_DIR/rulesets.json"
cat >"$FIXTURE_DIR/ruleset.json" <<'JSON'
{
  "id": 1,
  "target": "tag",
  "enforcement": "active",
  "source_type": "Repository",
  "source": "3leaps/sfetch",
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/v*"],
      "exclude": []
    }
  },
  "rules": [
    {"type": "creation"},
    {"type": "update"},
    {"type": "deletion"},
    {"type": "non_fast_forward"}
  ],
  "bypass_actors": []
}
JSON

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

# Negative control: remote write while still in checksums (phase 4). Signing
# uses real minisign/gpg; the Make order plus missing .minisig before draft
# is the signing control, not a PATH logger.
printf '4\n' >"$SEQ_PHASE_FILE"
if gh release create v1.2.3 --draft >/dev/null 2>&1; then
	fail "gh release create must be refused before create-draft"
fi
if gh release upload v1.2.3 SHA256SUMS >/dev/null 2>&1; then
	fail "gh release upload must be refused before create-draft"
fi
pass "negative control: no remote write before create-draft"

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

# Real ceremony tree: clone this checkout, replace only public pins with
# throwaway keys, keep every internal guard script byte-identical.
fixture="$scratch/repo"
git clone --local "$root" "$fixture" >/dev/null
git -C "$fixture" checkout -q -B main
git -C "$fixture" config user.name '3 Leaps Infosec Team'
git -C "$fixture" config user.email infosec@3leaps.net
git -C "$fixture" config commit.gpgsign false
git -C "$fixture" config gpg.format openpgp
git -C "$fixture" config gpg.program gpg
git -C "$fixture" config tag.gpgsign false
export FIXTURE_REPO="$fixture"
for s in "${internal_scripts[@]}"; do
	cmp -s "$root/scripts/$s" "$fixture/scripts/$s" || fail "internal $s is not the real script"
done
pass "fixture internal guards match the operator checkout"

gpg_home="$scratch/gpg-home"
mkdir -m 700 -p "$gpg_home"
record_cleanup dir "$gpg_home"
gpg --homedir "$gpg_home" --batch --pinentry-mode loopback --passphrase '' \
	--quick-gen-key '3 Leaps Infosec Team <infosec@3leaps.net>' ed25519 cert 1d >/dev/null 2>&1
primary="$(gpg --homedir "$gpg_home" --batch --with-colons --fingerprint --list-keys | awk -F: '$1=="fpr" {print $10;exit}')"
gpg --homedir "$gpg_home" --batch --pinentry-mode loopback --passphrase '' \
	--quick-add-key "$primary" ed25519 sign 1d >/dev/null 2>&1
subkey="$(gpg --homedir "$gpg_home" --batch --with-colons --with-subkey-fingerprint --list-keys |
	awk -F: '$1=="sub" {s=1;next} s && $1=="fpr" {print $10;exit}')"
[[ "$primary" =~ ^[0-9A-F]{40}$ && "$subkey" =~ ^[0-9A-F]{40}$ && "$primary" != "$subkey" ]] ||
	fail "fixture signing subkey required"
gpg --homedir "$gpg_home" --batch --armor --export "$primary" >"$fixture/docs/security/release-signing-keys.asc"
minisign -G -W -p "$scratch/minisign.pub" -s "$scratch/minisign.key" >/dev/null
record_cleanup file "$scratch/minisign.pub"
record_cleanup file "$scratch/minisign.key"
cp "$scratch/minisign.pub" "$fixture/docs/security/sfetch-minisign.pub"
"$decernor_bin" fingerprint "$fixture/docs/security/release-signing-keys.asc" --class public --kind gpg \
	--format ndjson --path-mode none --gpg-role primary >"$scratch/gpg.ndjson"
"$decernor_bin" fingerprint "$fixture/docs/security/sfetch-minisign.pub" --class public --kind minisign \
	--format ndjson --path-mode none >"$scratch/minisign.ndjson"
python3 - "$scratch" "$fixture/keys" <<'PY'
import json
import pathlib
import sys
base = pathlib.Path(sys.argv[1])
keys = pathlib.Path(sys.argv[2])
g = [json.loads(line) for line in (base / "gpg.ndjson").read_text().splitlines() if line]
m = [
    json.loads(line)
    for line in (base / "minisign.ndjson").read_text().splitlines()
    if line and json.loads(line).get("fingerprint_scheme") == "minisign-public-blob-sha256-v1"
]
if len(g) != 1 or len(m) != 1:
    raise SystemExit("error: expected one GPG primary and one minisign blob fingerprint")
(keys / "expected-fingerprints.ndjson").write_text(
    "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in (g[0], m[0]))
)
(keys / "expected-fingerprints.txt").write_text(
    "gpg " + g[0]["fingerprint"] + "\nminisign " + m[0]["fingerprint"] + "\n"
)
PY
"$decernor_bin" fingerprint verify \
	--anchors "$fixture/keys/expected-fingerprints.txt" \
	--anchors-ndjson "$fixture/keys/expected-fingerprints.ndjson" \
	--gpg "$fixture/docs/security/release-signing-keys.asc" \
	--minisign "$fixture/docs/security/sfetch-minisign.pub" >/dev/null
printf '1.2.3\n' >"$fixture/VERSION"
printf 'notes for v1.2.3\n' >"$fixture/docs/releases/v1.2.3.md"
git -C "$fixture" add VERSION docs/releases/v1.2.3.md docs/security keys
git -C "$fixture" commit -q -m "fixture pins and notes"

origin="$scratch/origin.git"
git clone --bare --quiet "$fixture" "$origin"
git -C "$fixture" remote remove origin
git -C "$fixture" remote add origin https://github.com/3leaps/sfetch.git
git -C "$fixture" config "url.file://$origin.insteadOf" https://github.com/3leaps/sfetch.git
git -C "$fixture" fetch --quiet origin '+refs/heads/main:refs/remotes/origin/main'
[[ "$(git -C "$fixture" rev-parse HEAD)" == "$(git -C "$fixture" rev-parse refs/remotes/origin/main)" ]] ||
	fail "fixture HEAD must match origin/main"
pass "local origin rewritten from github URL (insteadOf); identity stays 3leaps/sfetch"

python3 - "$scratch/fx/artifact.zip" <<'PY'
import sys, zipfile
names = [
    "sfetch_linux_amd64.tar.gz",
    "sfetch_linux_arm64.tar.gz",
    "sfetch_windows_amd64.zip",
    "sfetch_windows_arm64.zip",
    "sfetch_darwin_arm64.tar.gz",
]
with zipfile.ZipFile(sys.argv[1], "w") as z:
    for name in names:
        z.writestr(name, f"pkg {name}\n")
PY
export FIXTURE_ZIP="$scratch/fx/artifact.zip"

msgdir="$scratch/messages/v1.2.3"
mkdir -m 700 -p "$scratch/messages"
# Uncanonicalized path (symlink tmp ancestor) must still be refused.
raw_msg="$raw_scratch/messages/v1.2.3"
mkdir -p "$raw_msg"
if SFETCH_RELEASE_TAG=v1.2.3 SFETCH_TAG_MESSAGE_DIR="$raw_msg" \
	"$fixture/scripts/release-prepare-tag-message.py" >/dev/null 2>"$scratch/symlink-msg.err"; then
	fail "preparer must refuse a message directory with symlink ancestors"
fi
grep -qi 'symlink' "$scratch/symlink-msg.err" || {
	cat "$scratch/symlink-msg.err" >&2
	fail "symlink-ancestor refusal must name the symlink"
}
# Explicit symlink at the message directory itself.
ln -s "$scratch/messages" "$scratch/messages-link"
if SFETCH_RELEASE_TAG=v1.2.3 SFETCH_TAG_MESSAGE_DIR="$scratch/messages-link/v1.2.3" \
	"$fixture/scripts/release-prepare-tag-message.py" >/dev/null 2>"$scratch/symlink-dir.err"; then
	fail "preparer must refuse a symlinked message directory"
fi
pass "production symlink guard still rejects a symlinked message directory"

# Negative control: break one real internal guard input (fetch workflow path).
export SFETCH_RELEASE_TAG=v1.2.3
export SFETCH_TAG_MESSAGE_DIR="$msgdir"
export SFETCH_TAGGER_NAME='3 Leaps Infosec Team'
export SFETCH_TAGGER_EMAIL=infosec@3leaps.net
export SFETCH_MINISIGN_KEY="$scratch/minisign.key"
export SFETCH_MINISIGN_PUB="$scratch/minisign.pub"
export SFETCH_PGP_KEY_ID="${subkey}!"
export SFETCH_GPG_HOMEDIR="$gpg_home"
export SFETCH_GPG_SIGNING_FINGERPRINT="$primary"
export RELEASE_RUN_ID=11
export RELEASE_RUN_ATTEMPT=1

wrong="$scratch/neg-pin"
mkdir -p "$wrong"
printf 'gpg %s\nminisign %s\n' "$(printf 'B%.0s' {1..40})" "$(printf 'a%.0s' {1..64})" \
	>"$fixture/keys/expected-fingerprints.txt"
if make -C "$fixture" release-preflight "SFETCH_RELEASE_TAG=v1.2.3" \
	>"$scratch/neg-preflight.out" 2>&1; then
	git -C "$fixture" checkout -q -- keys/expected-fingerprints.txt
	fail "preflight must fail when committed fingerprint anchors do not match"
fi
git -C "$fixture" checkout -q -- keys/expected-fingerprints.txt
[[ -z "$(git -C "$fixture" status --porcelain)" ]] || fail "negative pin must restore a clean tree"
pass "negative control: real committed-anchor guard fails on a pin mismatch"

run_make() {
	local n="$1" target="$2"
	shift 2
	printf '%s\n' "$n" >"$SEQ_PHASE_FILE"
	echo "make $target" >>"$seq_log"
	# Preflight does not take SFETCH_RELEASE_TAG; its nested
	# test-makefile-release-tag must see an unset tag.
	if [[ "$target" == release-preflight ]]; then
		env -u SFETCH_RELEASE_TAG make -C "$fixture" "$target" \
			"SFETCH_DECERNOR_BIN=$decernor_bin" "$@"
	else
		make -C "$fixture" "$target" \
			"SFETCH_RELEASE_TAG=v1.2.3" \
			"SFETCH_TAG_MESSAGE_DIR=$msgdir" \
			"SFETCH_MINISIGN_KEY=$scratch/minisign.key" \
			"SFETCH_MINISIGN_PUB=$scratch/minisign.pub" \
			"SFETCH_PGP_KEY_ID=${subkey}!" \
			"SFETCH_GPG_HOMEDIR=$gpg_home" \
			"SFETCH_GPG_SIGNING_FINGERPRINT=$primary" \
			"SFETCH_DECERNOR_BIN=$decernor_bin" \
			"SFETCH_TAGGER_NAME=3 Leaps Infosec Team" \
			"SFETCH_TAGGER_EMAIL=infosec@3leaps.net" \
			"RELEASE_RUN_ID=11" \
			"RELEASE_RUN_ATTEMPT=1" \
			"$@"
	fi
	if [[ "${SFETCH_WALKTHROUGH_FAIL_AT:-}" == "$target" ]]; then
		fail "forced failure at $target"
	fi
}

: >"$seq_log"
# Preflight is a clean-tree check; it must not inherit the later tag input.
unset SFETCH_RELEASE_TAG || true
run_make 1 release-preflight
export SFETCH_RELEASE_TAG=v1.2.3
run_make 1 release-prepare-tag-message
[ -f "$msgdir/message.txt" ] || fail "make release-prepare-tag-message must write message.txt"
assert_no_symlink_ancestors "$msgdir"
run_make 1 release-tag
run_make 1 release-push-tag

# Fetch path mismatch: real release-fetch-ci-artifacts.sh must refuse.
export FIXTURE_WORKFLOW_PATH=.github/workflows/ci.yml
if make -C "$fixture" release-download "SFETCH_RELEASE_TAG=v1.2.3" \
	>"$scratch/neg-fetch.out" 2>&1; then
	fail "release-download must fail when the run path is not release.yml"
fi
grep -qi 'not a successful release run' "$scratch/neg-fetch.out" || {
	cat "$scratch/neg-fetch.out" >&2
	fail "fetch guard must name the unsuccessful release run"
}
unset FIXTURE_WORKFLOW_PATH
pass "negative control: real fetch guard fails on a workflow-path mismatch"

run_make 3 release-download
run_make 4 release-checksums
# Signing artifacts must not exist before create-draft.
if compgen -G "$fixture/dist/release/*.minisig" >/dev/null ||
	compgen -G "$fixture/dist/release/*.asc" >/dev/null; then
	fail "signatures must not exist before create-draft"
fi
run_make 5 release-create-draft
run_make 6 release-sign
[ -f "$fixture/dist/release/SHA256SUMS.minisig" ] || fail "real minisign must sign SHA256SUMS after draft"
[ -f "$fixture/dist/release/install-sfetch.sh.minisig" ] || fail "real minisign must sign the installer after draft"
[ -f "$fixture/dist/release/SHA256SUMS.asc" ] || fail "real gpg must sign SHA256SUMS after draft"
run_make 7 release-export-keys
run_make 8 release-verify
run_make 9 release-notes
run_make 9 release-upload
# Publish requires release-notes-vX.Y.Z.md as a draft *asset*. upload-release-assets
# sets the body via --notes-file; provenance is the script that uploads the file.
run_make 9 release-upload-provenance
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
python3 - "$seq_log" <<'PY' || fail "signing must follow create-draft in the log"
from pathlib import Path
import sys
lines = Path(sys.argv[1]).read_text().splitlines()
create = next(i for i, l in enumerate(lines) if "make release-create-draft" in l)
sign = next(i for i, l in enumerate(lines) if "make release-sign" in l)
if not (create < sign):
    raise SystemExit(f"create={create} sign={sign}")
gh_create = next(i for i, l in enumerate(lines) if "release create" in l)
if not (create <= gh_create):
    raise SystemExit(f"create={create} gh_create={gh_create}")
publish = next(i for i, l in enumerate(lines) if "make release-publish" in l)
draft_false = [i for i, l in enumerate(lines) if "draft=false" in l]
if any(i < publish for i in draft_false):
    raise SystemExit("gh release edit --draft=false before make release-publish")
PY
if grep -qE 'true[[:space:]]*#' "$seq_log"; then
	fail "walkthrough log still contains true placeholder phases"
fi
pass "Make sequence: real guards, message, draft, then sign, verified publish"

echo "[ok] release ceremony walkthrough"
