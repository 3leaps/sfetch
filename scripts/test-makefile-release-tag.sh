#!/usr/bin/env bash
# Makefile must take SFETCH_RELEASE_TAG only. A ?= that lets inherited
# RELEASE_TAG win is a derived input (PDR-0008 §2.4).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

# No assignment of bare RELEASE_TAG (including ?= / := / +=).
if grep -nE '^[[:space:]]*RELEASE_TAG[[:space:]]*(\?=|:=|\+=|=)' Makefile; then
    fail "Makefile must not assign RELEASE_TAG"
fi
# Mentions of RELEASE_TAG in the Makefile may exist only as a refusal.
if grep -nE 'RELEASE_TAG' Makefile | grep -vE 'SFETCH_RELEASE_TAG|not accepted|RELEASE_TAG is not|origin RELEASE_TAG'; then
    fail "Makefile mentions RELEASE_TAG outside a refusal"
fi
grep -q 'SFETCH_RELEASE_TAG' Makefile || fail "Makefile must consume SFETCH_RELEASE_TAG"
pass "Makefile does not assign RELEASE_TAG"

# Command-line RELEASE_TAG must not reach a tag-consuming target.
if make -s release-notes RELEASE_TAG=v0.0.0 >/tmp/sft-make-rt.out 2>&1; then
    fail "make release-notes RELEASE_TAG=... must be refused"
fi
grep -qi 'RELEASE_TAG is not accepted' /tmp/sft-make-rt.out ||
    fail "refusal must name RELEASE_TAG (log: $(cat /tmp/sft-make-rt.out))"
pass "command-line RELEASE_TAG is refused"

# Missing SFETCH_RELEASE_TAG must fail before side effects.
if make -s release-notes >/tmp/sft-make-missing.out 2>&1; then
    fail "make release-notes without SFETCH_RELEASE_TAG must be refused"
fi
grep -q 'SFETCH_RELEASE_TAG required' /tmp/sft-make-missing.out ||
    fail "missing-tag refusal (log: $(cat /tmp/sft-make-missing.out))"
pass "missing SFETCH_RELEASE_TAG is refused"

# Tag must equal v$(VERSION) and the check runs before other prerequisites.
file_version="$(tr -d ' \n' <VERSION)"
unset RELEASE_TAG || true
if make -s release-notes SFETCH_RELEASE_TAG=v0.0.0 >/tmp/sft-make-ver.out 2>&1; then
    fail "make release-notes with a tag that is not v$(VERSION) must be refused"
fi
grep -q "must equal v${file_version}" /tmp/sft-make-ver.out ||
    fail "VERSION mismatch refusal (log: $(cat /tmp/sft-make-ver.out))"
pass "SFETCH_RELEASE_TAG must equal v\$(VERSION)"

# Empty RELEASE_TAG= is still a defined input (make origin=command line).
if make -s release-notes RELEASE_TAG= "SFETCH_RELEASE_TAG=v${file_version}" >/tmp/sft-make-empty-rt.out 2>&1; then
    fail "make RELEASE_TAG= must be refused"
fi
grep -qi 'RELEASE_TAG is not accepted' /tmp/sft-make-empty-rt.out ||
    fail "empty RELEASE_TAG= refusal (log: $(cat /tmp/sft-make-empty-rt.out))"
pass "empty RELEASE_TAG= is refused"

# H4: actually run release-download with a stubbed fetch script. make -n
# alone does not prove the recipe runs.
scratch_dl="$(mktemp -d "${TMPDIR:-/tmp}/sft-make-dl.XXXXXX")"
trap 'rm -rf "$scratch_dl" /tmp/sft-make-rt.out /tmp/sft-make-missing.out /tmp/sft-make-ver.out /tmp/sft-make-empty-rt.out' EXIT
mkdir -p "$scratch_dl/scripts"
cp "$ROOT/VERSION" "$scratch_dl/VERSION"
stub_log="$scratch_dl/called.log"
cat >"$scratch_dl/scripts/release-fetch-ci-artifacts.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"${STUB_LOG:?}"
mkdir -p "$2"
touch "$2/.fetched"
SH
chmod +x "$scratch_dl/scripts/release-fetch-ci-artifacts.sh"
if ! STUB_LOG="$stub_log" make -C "$scratch_dl" -f "$ROOT/Makefile" release-download \
    "SFETCH_RELEASE_TAG=v${file_version}" \
    >/tmp/sft-make-dl.out 2>/tmp/sft-make-dl.err; then
    fail "make release-download with stub fetch failed: $(cat /tmp/sft-make-dl.err)"
fi
[ -s "$stub_log" ] || fail "release-download must invoke release-fetch-ci-artifacts.sh (make -n is not enough)"
grep -q "v${file_version}" "$stub_log" ||
    fail "stub fetch must receive the release tag (got: $(cat "$stub_log"))"
grep -q 'dist/release' "$stub_log" ||
    fail "stub fetch must receive dist/release (got: $(cat "$stub_log"))"
if grep -q 'download-release-assets.sh' /tmp/sft-make-dl.out /tmp/sft-make-dl.err "$stub_log"; then
    fail "release-download still calls download-release-assets.sh"
fi
pass "release-download invokes CI-artifact fetch"

if grep -E '^release-sign:.*release-checksums' Makefile; then
    fail "release-sign must not run release-checksums before the tag guard"
fi
grep -E '^release-sign: require-release-tag' Makefile >/dev/null ||
    fail "release-sign must depend on require-release-tag first"
pass "tag guard runs before release-sign prerequisites"

echo "[ok] Makefile SFETCH_RELEASE_TAG-only"
