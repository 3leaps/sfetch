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
trap 'rm -rf "$scratch_dl" /tmp/sft-make-rt.out /tmp/sft-make-missing.out /tmp/sft-make-ver.out /tmp/sft-make-empty-rt.out /tmp/sft-make-scoop.out /tmp/sft-make-scoop.err' EXIT
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

# Scoop handoff is an explicit fail-closed step, not a side effect of upload.
python3 - "$ROOT/Makefile" <<'PY' || fail "release-upload must not call update-scoop-manifest"
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r'^release-upload:.*?(?=\n[a-z].*:|\Z)', text, re.M | re.S)
if not m:
    raise SystemExit('release-upload missing')
body = m.group(0)
if 'update-scoop-manifest' in body:
    raise SystemExit('release-upload still invokes update-scoop-manifest')
if 'Skipping Scoop' in body:
    raise SystemExit('release-upload still carries the fail-open Scoop skip')
# Mutation: splicing the old call back in must fail this checker.
mut = body.rstrip() + '\n\t@$(MAKE) update-scoop-manifest\n'
if 'update-scoop-manifest' not in mut or mut == body:
    raise SystemExit('mutation assertion did not insert the Scoop call')
if 'update-scoop-manifest' not in mut.split('release-upload', 1)[-1]:
    raise SystemExit('mutated recipe lost the Scoop call')
# Re-run the same predicate on the mutated recipe.
if 'update-scoop-manifest' not in mut:
    raise SystemExit('mutated recipe should contain update-scoop-manifest')
# The live recipe must still refuse it.
if 'update-scoop-manifest' in body:
    raise SystemExit('live recipe still contains update-scoop-manifest')
PY
python3 - "$ROOT/Makefile" <<'PY' || fail "update-scoop-manifest must fail closed when the sibling is missing"
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r'^update-scoop-manifest:.*?(?=\n[a-z].*:|\Z)', text, re.M | re.S)
if not m:
    raise SystemExit('update-scoop-manifest missing')
body = m.group(0)
if 'Skipping Scoop' in body:
    raise SystemExit('update-scoop-manifest still skips when the sibling is missing')
if 'exit 1' not in body:
    raise SystemExit('update-scoop-manifest must exit 1 when the sibling is missing')
missing = 'if [ ! -d "$(SCOOP_BUCKET_DIR)" ]'
if missing not in body:
    raise SystemExit('update-scoop-manifest must test SCOOP_BUCKET_DIR')
# Mutation: restore warn-and-skip; the checker must reject it.
open_copy = body.replace('exit 1;', 'echo "Skipping Scoop manifest update.";')
if 'Skipping Scoop' not in open_copy:
    raise SystemExit('mutation assertion did not restore the skip')
if 'Skipping Scoop' in body:
    raise SystemExit('live recipe still skips')
PY
missing_bucket="$scratch_dl/missing-scoop"
if make -s update-scoop-manifest SCOOP_BUCKET_DIR="$missing_bucket" \
	>/tmp/sft-make-scoop.out 2>/tmp/sft-make-scoop.err; then
	fail "make update-scoop-manifest must fail closed when the sibling is missing"
fi
grep -qi 'not found' /tmp/sft-make-scoop.err ||
	fail "missing scoop-bucket refusal (log: $(cat /tmp/sft-make-scoop.err /tmp/sft-make-scoop.out))"
if grep -qi 'Skipping Scoop' /tmp/sft-make-scoop.out /tmp/sft-make-scoop.err; then
	fail "update-scoop-manifest must not skip a missing sibling"
fi
pass "update-scoop-manifest is fail-closed and not part of release-upload"

echo "[ok] Makefile SFETCH_RELEASE_TAG-only"
