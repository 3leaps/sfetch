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

# H4: release-download is the CI-artifact provenance path and writes .anchor.
python3 - "$mk" <<'PY' || fail "H4: release-download must call release-fetch-ci-artifacts.sh"
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r'^release-download:.*?(?=\n[a-z].*:|\Z)', text, re.M | re.S)
if not m:
    raise SystemExit('release-download target missing')
body = m.group(0)
if 'release-fetch-ci-artifacts.sh' not in body:
    raise SystemExit('does not call release-fetch-ci-artifacts.sh')
if 'download-release-assets.sh' in body:
    raise SystemExit('still calls download-release-assets.sh')
PY

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

# M7: actionlint knows both org runner labels; native jobs assert GOHOST*.
grep -q 'ubuntu-latest-arm64-s' "$root/.github/actionlint.yaml" ||
	fail "M7: actionlint.yaml must allow ubuntu-latest-arm64-s"
grep -q 'windows-latest-arm64-s' "$root/.github/actionlint.yaml" ||
	fail "M7: actionlint.yaml must allow windows-latest-arm64-s"
grep -q 'GOHOSTOS' "$ci" || fail "M7: native job must assert GOHOSTOS/GOHOSTARCH"
grep -q 'Assert runner matches matrix target' "$ci" || fail "M7: native job must assert the matrix target"

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

# SEC-H1: fresh home is mktemp, refuses symlinks, chmod 700, gpgconf --kill all.
grep -q 'mktemp -d' "$root/scripts/release-tag-common.sh" || fail "SEC-H1: tag operator must mktemp -d"
grep -q 'must not be a symlink' "$root/scripts/release-tag-common.sh" || fail "SEC-H1: tag operator must refuse symlinks"
grep -q 'mode 0700' "$root/scripts/release-tag-common.sh" || fail "SEC-H1: tag operator must require mode 0700"
grep -q 'gpgconf --homedir' "$root/scripts/release-tag-common.sh" || fail "SEC-H1: tag operator must kill gpg-agent"
grep -q 'gpgconf --homedir' "$root/scripts/release-tag.sh" || fail "SEC-H1: release-tag.sh must gpgconf --kill all in its EXIT trap"

# SEC-M: installer rejects expired/revoked status.
grep -q 'EXPKEYSIG' "$root/scripts/install-sfetch.sh" || fail "SEC-M: installer must reject EXPKEYSIG"
grep -q 'EXPSIG' "$root/scripts/install-sfetch.sh" || fail "SEC-M: installer must reject EXPSIG"
grep -q 'KEYEXPIRED' "$root/scripts/install-sfetch.sh" || fail "SEC-M: installer must reject KEYEXPIRED"

echo "[ok] review-finding static guards"
