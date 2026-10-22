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
if grep -nE 'RELEASE_TAG' Makefile | grep -vE 'SFETCH_RELEASE_TAG|not accepted|RELEASE_TAG is not'; then
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
if make -s release-notes SFETCH_RELEASE_TAG=v0.0.0 RELEASE_TAG= >/tmp/sft-make-ver.out 2>&1; then
    fail "make release-notes with a tag that is not v$(VERSION) must be refused"
fi
grep -q "must equal v${file_version}" /tmp/sft-make-ver.out ||
    fail "VERSION mismatch refusal (log: $(cat /tmp/sft-make-ver.out))"
pass "SFETCH_RELEASE_TAG must equal v\$(VERSION)"

if grep -E '^release-sign:.*release-checksums' Makefile; then
    fail "release-sign must not run release-checksums before the tag guard"
fi
grep -E '^release-sign: require-release-tag' Makefile >/dev/null ||
    fail "release-sign must depend on require-release-tag first"
pass "tag guard runs before release-sign prerequisites"

echo "[ok] Makefile SFETCH_RELEASE_TAG-only"
