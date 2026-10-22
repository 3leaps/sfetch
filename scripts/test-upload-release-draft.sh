#!/usr/bin/env bash
# release-upload must keep the GitHub release a draft. Promotion is
# release-publish after byte verification.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

UPLOAD="${ROOT}/scripts/upload-release-assets.sh"
[ -f "$UPLOAD" ] || fail "upload-release-assets.sh missing"

if grep -nE -- '--draft=false|draft=false' "$UPLOAD"; then
    fail "upload-release-assets.sh must not publish (no --draft=false)"
fi
grep -q 'isDraft' "$UPLOAD" || fail "upload-release-assets.sh must assert the release stays a draft"
grep -q 'draft=true' "$UPLOAD" || fail "upload-release-assets.sh must pass --draft=true on edit"
pass "upload script never publishes"

# Fixture: a fake gh that records argv and reports a published (non-draft) release.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sft-upload-draft.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/dist"
cat >"$WORK/bin/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${GH_TRACE}"
case "$*" in
  *'release view'*'isDraft'*)
    printf '{"isDraft":false}\n'
    ;;
  *'release view'*)
    printf '{"isDraft":false,"tagName":"v0.0.0"}\n'
    ;;
  *)
    exit 0
    ;;
esac
SH
chmod +x "$WORK/bin/gh"
printf 'notes\n' >"$WORK/dist/release-notes-v0.0.0.md"
printf 'bin\n' >"$WORK/dist/sfetch_linux_amd64.tar.gz"
: >"$WORK/dist/SHA256SUMS"
: >"$WORK/dist/SHA512SUMS"
: >"$WORK/dist/install-sfetch.sh"
: >"$WORK/dist/install-sfetch.sh.minisig"
export GH_TRACE="$WORK/trace"
export PATH="$WORK/bin:$PATH"
: >"$GH_TRACE"
if "$UPLOAD" v0.0.0 "$WORK/dist" >/dev/null 2>&1; then
    fail "upload must refuse when the release is not a draft"
fi
grep -q 'release view' "$GH_TRACE" || fail "upload must read isDraft before mutating"
if grep -q 'release upload' "$GH_TRACE"; then
    fail "upload must not mutate assets before the draft check"
fi
if grep -q 'release edit' "$GH_TRACE"; then
    fail "upload must not edit the release before the draft check"
fi
pass "upload refuses a non-draft release without mutating it"

echo "[ok] release-upload stays draft"
