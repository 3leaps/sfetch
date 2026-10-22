#!/usr/bin/env bash
# Revert-failing static checks for the High/Medium review-fix round.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

wf="$root/.github/workflows/release.yml"
ci="$root/.github/workflows/ci.yml"
mk="$root/Makefile"

# H1: tag CI verifies committed exports with Decernor; no maintainer-only pin script.
grep -q 'release-validate-pin.sh' "$wf" && fail "H1: tag CI must not call release-validate-pin.sh"
grep -q 'release-verify-committed-anchors.sh' "$wf" || fail "H1: tag CI must run release-verify-committed-anchors.sh"
grep -q 'ci-install-decernor.sh' "$wf" || fail "H1: tag CI must install Decernor via ci-install-decernor.sh"
grep -q 'config/release/decernor-ci-sha256.txt' "$root/scripts/ci-install-decernor.sh" ||
	fail "H1: Decernor install must pin config/release/decernor-ci-sha256.txt"
# Decernor must be installed before verify-pinned-tag.sh (needs SFETCH_DECERNOR_BIN).
python3 - "$wf" <<'PY' || fail "H1: Decernor install must precede verify-pinned-tag.sh"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()

def install_before_verify(s):
    install = s.find("ci-install-decernor.sh")
    verify = s.find("verify-pinned-tag.sh")
    return install >= 0 and verify >= 0 and install < verify

if not install_before_verify(text):
    raise SystemExit("ci-install-decernor.sh must appear before verify-pinned-tag.sh")
rev = text.replace("ci-install-decernor.sh", "VERIFY_PLACEHOLDER", 1)
rev = rev.replace("verify-pinned-tag.sh", "ci-install-decernor.sh", 1)
rev = rev.replace("VERIFY_PLACEHOLDER", "verify-pinned-tag.sh", 1)
if install_before_verify(rev):
    raise SystemExit("order checker does not fail when install/verify are reversed")
PY

# H2: every restore-tag-ref step in release.yml carries GH_TOKEN.
python3 - "$wf" <<'PY' || fail "H2: restore-tag-ref step missing GH_TOKEN"
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
steps = text.split("- name:")
missing = []
for step in steps[1:]:
    if "release-restore-tag-ref.sh" not in step:
        continue
    if "GH_TOKEN:" not in step or "github.token" not in step:
        name = step.splitlines()[0].strip()
        missing.append(name)
if missing:
    raise SystemExit("missing GH_TOKEN on: " + ", ".join(missing))
PY

# H3: PR CI installs the same digest-pinned Decernor and exports SFETCH_DECERNOR_BIN.
grep -q 'ci-install-decernor.sh' "$ci" || fail "H3: ci.yml must install Decernor via ci-install-decernor.sh"
grep -q 'SFETCH_DECERNOR_BIN' "$ci" || fail "H3: ci.yml must export SFETCH_DECERNOR_BIN"
grep -q 'SFETCH_DECERNOR_BIN required' "$root/scripts/release-pin-precursors.test.sh" ||
	fail "H3: pin-precursors must name SFETCH_DECERNOR_BIN as required"
grep -qE 'sha256sum --check --quiet' "$root/scripts/ci-install-decernor.sh" ||
	fail "H3: sha256sum --check must be --quiet (stdout is the binary path only)"
grep -q 'printed extra stdout' "$ci" || fail "H3: ci.yml must refuse multiline Decernor stdout"

# H4: behavioural check lives in test-makefile-release-tag.sh (stubbed fetch, not make -n).

# H6: public-key staging is from the tagged commit, not the operator keyring/env.
for target in release-export-minisign-key release-export-key release-export-keys; do
	python3 - "$mk" "$target" <<'PY' || fail "H6: ${target} must stage from the tagged commit"
import pathlib, re, sys
text, target = pathlib.Path(sys.argv[1]).read_text(), sys.argv[2]
m = re.search(rf'^{re.escape(target)}:.*?(?=\n[a-z].*:|\Z)', text, re.M | re.S)
if not m:
    raise SystemExit(f'{target} missing')
body = m.group(0)
if 'release-stage-tagged-pubkeys.sh' not in body:
    raise SystemExit(f'{target} does not call release-stage-tagged-pubkeys.sh')
if 'SFETCH_MINISIGN_PUB' in body or 'export-release-key.sh' in body:
    raise SystemExit(f'{target} still stages from env/keyring')
PY
done
grep -q 'cat-file blob' "$root/scripts/release-stage-tagged-pubkeys.sh" ||
	fail "H6: staging must read git cat-file blob from the tagged commit"
grep -q 'byte-identical to the tagged commit' "$root/scripts/release-publish.sh" ||
	fail "H6: publish must byte-compare the staged minisign public key"

# M1: preflight, publish, and the tag operator use the designated checker.
grep -A2 '^release-preflight:' "$mk" | grep -q 'release-verify-committed-anchors.sh' ||
	fail "M1: release-preflight must run release-verify-committed-anchors.sh"
grep -q 'validate-release-anchors.sh' <(grep -A6 '^release-preflight:' "$mk") &&
	fail "M1: release-preflight must not use validate-release-anchors.sh"
grep -q 'resolve_release_decernor ceremony' "$root/scripts/release-publish.sh" ||
	fail "M1: release-publish must bind Decernor in ceremony mode"
grep -q 'resolve_release_decernor ceremony' "$root/scripts/release-tag-common.sh" ||
	fail "M1: tag operator must bind Decernor in ceremony mode"
grep -q 'validate-release-anchors.sh' "$root/scripts/release-tag-common.sh" &&
	fail "M1: tag operator must not call validate-release-anchors.sh"

# M2: installer minisig is minisign-verified, not only byte-compared.
grep -n -B2 -A2 'minisign -Vq' "$root/scripts/release-publish.sh" | grep -q 'install-${binary}.sh' ||
	fail "M2: publish must minisign-verify install-sfetch.sh"

# M4: tag == v$(VERSION) is enforced first; release-sign does not run checksums first.
grep -q 'SFETCH_RELEASE_TAG.*) must equal v' "$mk" || fail "M4: Makefile must require tag == v\$(VERSION)"
grep -E '^release-sign: require-release-tag' "$mk" || fail "M4: release-sign must depend on require-release-tag first"
grep -E '^release-sign:.*release-checksums' "$mk" && fail "M4: release-sign must not list release-checksums as a make prerequisite"

# M6: upload checks draft state read-only before any mutation.
python3 - "$root/scripts/release-upload-provenance.sh" <<'PY' || fail "M6-round2: provenance --clobber must follow a draft view"
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
view = text.find("gh release view")
upload = text.find("gh release upload")
if view < 0 or upload < 0 or not (view < upload):
    raise SystemExit(f'order view={view} upload={upload}')
if "--json isDraft" not in text:
    raise SystemExit('draft check is not a read-only isDraft view')
if 'is not a draft' not in text:
    raise SystemExit('must refuse a published release')
PY
python3 - "$root/scripts/upload-release-assets.sh" <<'PY' || fail "M6: draft view must precede upload/edit"
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
view = text.find("gh release view")
upload = text.find("gh release upload")
edit = text.find("gh release edit")
if view < 0 or upload < 0 or edit < 0:
    raise SystemExit('missing view/upload/edit')
if not (view < upload < edit):
    raise SystemExit(f'order view={view} upload={upload} edit={edit}')
if "--json isDraft" not in text:
    raise SystemExit('draft check is not a read-only isDraft view')
PY

# M7: native matrix must be exactly the five platforms. Dropping a row fails.
python3 - "$ci" "$root/.github/actionlint.yaml" <<'PY' || fail "M7: native matrix rows"
import pathlib, re, sys
ci = pathlib.Path(sys.argv[1]).read_text()
lint = pathlib.Path(sys.argv[2]).read_text()
block = re.search(r"^  native:.*?(?=^  [a-z])", ci, re.M | re.S)
if not block:
    raise SystemExit("native job missing")
native = block.group(0)
required = {
    ("ubuntu-24.04", "linux-amd64"),
    ("ubuntu-latest-arm64-s", "linux-arm64"),
    ("macos-15", "darwin-arm64"),
    ("windows-2022", "windows-amd64"),
    ("windows-latest-arm64-s", "windows-arm64"),
}
rows = re.findall(r"runner:\s+(\S+)\n\s+target:\s+(\S+)", native)
got = set(tuple(r) for r in rows)
if got != required:
    raise SystemExit(f"matrix rows {sorted(got)} != {sorted(required)}")
if "GOHOSTOS" not in native or "Assert runner matches matrix target" not in native:
    raise SystemExit("native job must assert GOHOSTOS against the matrix target")
# Exact equality: inverting to != "success" or = "failure" must fail.
agg = re.search(
    r'(?m)^\s+run:\s+test\s+"\$\{\{\s*needs\.native\.result\s*\}\}"\s+=\s+"success"\s*$',
    ci,
)
if not agg:
    raise SystemExit("platforms aggregate must run: test needs.native.result = success")
if re.search(r'needs\.native\.result[^.\n]*!=', ci):
    raise SystemExit("platforms aggregate check is inverted")
inverted = ci[: agg.start()] + '            run: test "${{ needs.native.result }}" != "success"\n' + ci[agg.end() :]
if re.search(
    r'(?m)^\s+run:\s+test\s+"\$\{\{\s*needs\.native\.result\s*\}\}"\s+=\s+"success"\s*$',
    inverted,
):
    raise SystemExit("aggregate checker does not fail when the test is inverted")
for label in ("ubuntu-latest-arm64-s", "windows-latest-arm64-s"):
    if label not in lint:
        raise SystemExit(f"actionlint.yaml must allow {label}")
PY

# M8: checklist promotes via make release-publish and includes Homebrew.
if grep -nE 'gh release edit.*draft=false' "$root/RELEASE_CHECKLIST.md" | grep -v 'Do not run'; then
	fail "M8: checklist must not instruct gh release edit --draft=false"
fi
grep -q 'make release-publish' "$root/RELEASE_CHECKLIST.md" || fail "M8: checklist must name make release-publish"
grep -qi 'Homebrew' "$root/RELEASE_CHECKLIST.md" || fail "M8: checklist must include the Homebrew handoff"

# M9: install-release-anchors refuses existing dest files.
grep -q 'refusing to overwrite' "$root/scripts/install-release-anchors.sh" ||
	fail "M9: install-release-anchors must refuse to overwrite"
grep -q 'mv -f' "$root/scripts/install-release-anchors.sh" &&
	fail "M9: install-release-anchors must not force-overwrite with mv -f"

# SEC-H1: signing uses a fresh mktemp home; cleanup is armed before it is created.
grep -q 'tag_fresh_signing_gnupg_home' "$root/scripts/release-tag-common.sh" ||
	fail "SEC-H1: tag operator must create a fresh signing home"
grep -q 'tag_cleanup_homes' "$root/scripts/release-tag.sh" || fail "SEC-H1: release-tag.sh must clean signing and verify homes"
grep -q 'must not be the default homedir' "$root/scripts/release-tag-common.sh" ||
	fail "SEC-H1: tag operator must refuse the default homedir"
grep -q 'mode 0700' "$root/scripts/release-tag-common.sh" || fail "SEC-H1: tag operator must require mode 0700"
python3 - "$root/scripts/verify-pinned-tag.sh" <<'PY' || fail "M6-round2: tag verify must call Decernor before the listing check"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
dec = text.find("fingerprint verify")
listing = text.find("validate-release-anchors.sh")
if dec < 0 or listing < 0 or not (dec < listing):
    raise SystemExit(f"order decernor={dec} listing={listing}")
if "resolve_release_decernor ceremony" not in text:
    raise SystemExit("verify-pinned-tag must bind Decernor in ceremony mode")
PY

# SEC-M: installer rejects expired/revoked status.
grep -q 'EXPKEYSIG' "$root/scripts/install-sfetch.sh" || fail "SEC-M: installer must reject EXPKEYSIG"
grep -q 'EXPSIG' "$root/scripts/install-sfetch.sh" || fail "SEC-M: installer must reject EXPSIG"
grep -q 'KEYEXPIRED' "$root/scripts/install-sfetch.sh" || fail "SEC-M: installer must reject KEYEXPIRED"

echo "[ok] review-finding static guards"
