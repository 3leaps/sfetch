#!/usr/bin/env bash
# Fail-closed origin validator: canonical SSH/HTTPS, verified alias, alias
# pointing elsewhere, and the wrong repo. ssh -G is stubbed (mocked).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
# shellcheck source=scripts/release-origin.sh
source "$root/scripts/release-origin.sh"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}
pass() { echo "PASS: $*"; }

scratch="$(mktemp -d /tmp/sft-origin.XXXXXX)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin"

cat >"$scratch/bin/ssh" <<'SH'
#!/usr/bin/env bash
host=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	-G) shift; host="$1"; shift ;;
	*) shift ;;
	esac
done
case "$host" in
	gh) echo "hostname github.com" ;;
	evil) echo "hostname gitlab.example.invalid" ;;
	*) echo "hostname ${host}" ;;
esac
SH
chmod +x "$scratch/bin/ssh"
export SFETCH_SSH_BIN="$scratch/bin/ssh"

sfetch_origin_ok "https://github.com/3leaps/sfetch" || fail "HTTPS origin"
sfetch_origin_ok "https://github.com/3leaps/sfetch.git" || fail "HTTPS .git origin"
sfetch_origin_ok "git@github.com:3leaps/sfetch" || fail "canonical SSH origin"
sfetch_origin_ok "git@github.com:3leaps/sfetch.git" || fail "canonical SSH .git origin"
pass "canonical HTTPS and SSH"

sfetch_origin_ok "git@gh:3leaps/sfetch" || fail "verified SSH alias"
sfetch_origin_ok "git@gh:3leaps/sfetch.git" || fail "verified SSH alias .git"
sfetch_origin_ok "ssh://git@gh/3leaps/sfetch.git" || fail "verified ssh:// alias"
pass "verified SSH host alias"

if sfetch_origin_ok "git@evil:3leaps/sfetch"; then
	fail "alias pointing elsewhere must be refused"
fi
if sfetch_origin_ok "ssh://git@evil/3leaps/sfetch.git"; then
	fail "ssh:// alias pointing elsewhere must be refused"
fi
pass "alias pointing elsewhere is refused"

if sfetch_origin_ok "git@github.com:3leaps/other"; then
	fail "wrong repo must be refused"
fi
if sfetch_origin_ok "https://github.com/3leaps/other.git"; then
	fail "wrong HTTPS repo must be refused"
fi
if sfetch_origin_ok "git@gh:3leaps/other"; then
	fail "alias to the wrong repo must be refused"
fi
pass "wrong repository is refused"

# Negative control: without the shared helper, the published-tag script's
# old exact-match case accepts neither a verified alias nor refuses by ssh -G.
if grep -q 'require_sfetch_github_origin' "$root/scripts/release-verify-published-tag.sh"; then
	:
else
	fail "release-verify-published-tag.sh must call require_sfetch_github_origin"
fi
for f in scripts/release-tag-common.sh scripts/release-restore-tag-ref.sh \
	scripts/release-guard-tag-version.sh scripts/release-verify-published-tag.sh \
	scripts/release-verify-remote-tag.sh scripts/release-push-tag.sh; do
	grep -q 'require_sfetch_github_origin' "$root/$f" ||
		fail "$f must use require_sfetch_github_origin"
done
pass "every release origin check uses the shared validator"

echo "[ok] release origin validator"
