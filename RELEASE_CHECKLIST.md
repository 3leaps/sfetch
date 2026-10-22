# Release Checklist

This document walks maintainers through the build/sign/upload flow for each sfetch release.

## Repository Layout Prerequisite

To dogfood direct Scoop deployment at release time, keep `sfetch` and `scoop-bucket` as sibling repositories:

```text
parent/
  ├── sfetch/        # This repository
  └── scoop-bucket/  # Required for `make update-scoop-manifest`
```

Setup:

```bash
cd ..
git clone https://github.com/3leaps/scoop-bucket.git
cd sfetch
```

Why this matters: `make release-upload` now uploads the signed GitHub release assets and then updates the sibling Scoop manifest automatically. If `../scoop-bucket` is missing, the upload still succeeds but Scoop publication is skipped with a warning and requires manual follow-up.

## 1. Prepare & Tag

- [ ] Ensure `main` is clean and `make precommit` passes
- [ ] Update `VERSION` file with new semver (e.g., `0.4.12`)
- [ ] **Advance verified-bootstrap range constants** (required every release — missing bump fails consumers, not sfetch CI, unless you run the assert):
  - [ ] Set `SFETCH_BOOTSTRAP_MAX` in `scripts/bootstrap-sfetch-verified.sh` to `v$(cat VERSION)` (committed constant — **do not** derive at engine runtime from `VERSION` or the consumer tree)
  - [ ] Review `SFETCH_MINISIG_SINCE` (first tag that publishes `install-sfetch.sh.minisig`). Wrong value mis-routes (3-step vs 5-step); both routes still verify, but route selection is part of the contract
  - [ ] Update boundary tests in `scripts/test-bootstrap-sfetch-verified.sh` (e.g. assert `v(MAX+1)` is refused)
  - [ ] Run `make test-bootstrap-range-release` (or full `make precommit`) — asserts `SFETCH_BOOTSTRAP_MAX == v$(cat VERSION)` and `MINISIG_SINCE` ∈ `[MIN, MAX]`
  - [ ] After merge/tag, publish the new **action SHA** (and engine script digest if documenting Makefile consumers) — action SHA and `sfetch-version` pins are coupled in time; consumers advancing the pin must also advance the action ref when the range expands
- [ ] Update `CHANGELOG.md` (move Unreleased to new version section)
- [ ] Update `RELEASE_NOTES.md`
- [ ] Create `docs/releases/vX.Y.Z.md`
- [ ] Commit: `git add -A && git commit -m "release: prepare vX.Y.Z"`
- [ ] Push `main`. The maintainer (not an agent) then signs and pushes the tag:
  ```bash
  export SFETCH_RELEASE_TAG=v$(cat VERSION)
  make release-preflight
  make release-tag          # local signed annotated tag; throwaway tests never use the operator key
  make release-push-tag     # publish the signed tag
  ```
- [ ] Wait for GitHub Actions tag workflow to complete
  - Workflow is read-only (`contents: read`); it never creates a GitHub Release
  - CI validates VERSION file matches tag and verifies the signed tag object
  - Builds unsigned archives and uploads them as workflow artifacts
  - Maintainer then follows the ordered sequence below: download, checksums,
    create draft, sign, stage tagged keys, verify, notes/upload, verified publish
  - Release remains non-consumable until `make release-publish`

## 2. Manual Signing (local machine, maintainer-only)

Agents never sign. Bare `RELEASE_TAG` is refused.
Do not run `gh release edit --draft=false` — that bypasses the verified publish gate.

### Inputs

```bash
export SFETCH_RELEASE_TAG=v$(cat VERSION)
export SFETCH_MINISIGN_KEY=/path/to/sfetch.key
export SFETCH_MINISIGN_PUB=/path/to/sfetch.pub
export SFETCH_PGP_KEY_ID=<signing-subkey-fpr>!   # required for publish (SHA256SUMS.asc and SHA512SUMS.asc)
export SFETCH_GPG_HOMEDIR=/path/to/isolated/gpg/homedir   # not the default homedir
export SFETCH_GPG_SIGNING_FINGERPRINT=0CACA49B3119B6BC12B2CA11B9B485F294B9FE07
export SFETCH_DECERNOR_BIN=/path/to/decernor              # absolute, non-symlink, >= 0.1.8
export SFETCH_TAGGER_NAME="<name>"                        # with SFETCH_TAGGER_EMAIL, must match
export SFETCH_TAGGER_EMAIL="<email>"                      # config/release/tagger-identity.txt
export SFETCH_TAG_MESSAGE_DIR=/absolute/path/${SFETCH_RELEASE_TAG}
export RELEASE_RUN_ID=<release.yml run id>
export RELEASE_RUN_ATTEMPT=<successful attempt of that run>
```

`SFETCH_GPG_SIGNING_FINGERPRINT` is the approved primary in
`keys/expected-fingerprints.txt` (`0CACA49B3119B6BC12B2CA11B9B485F294B9FE07`).
PGP on both checksum manifests is required for publish; PGP does not sign the
installer.

### Select the CI run and attempt

Tag CI may be re-run. Artifacts belong to the **latest** attempt of a run, so
name a completed **success** attempt of `.github/workflows/release.yml` whose
`head_branch` is `$SFETCH_RELEASE_TAG` and `head_sha` is the tagged commit:

```bash
gh run list --repo 3leaps/sfetch --workflow release.yml --branch "$SFETCH_RELEASE_TAG"
gh run view "$RELEASE_RUN_ID" --repo 3leaps/sfetch --json conclusion,headSha,status,runAttempt,event,path
```

If a later attempt exists, set `RELEASE_RUN_ATTEMPT` to that attempt. The fetch
script refuses a non-success, mismatched commit, or a run that has moved on.

### Ordered sequence

1. **Preflight, message, tag** (after VERSION/changelog prep on `main`)
   ```bash
   make release-preflight
   make release-tag          # local signed annotated tag; throwaway tests never use the operator key
   make release-push-tag     # publish the signed tag
   ```

2. **Select CI run + attempt** (inputs above)

3. **Clean and download**
   ```bash
   make release-clean
   make release-download
   ```

4. **Checksums** (then fail-closed verify)
   ```bash
   make release-checksums
   make release-verify-checksums
   ```

5. **Create draft** — after checksums, **before** signing. The directory must
   contain only the expected archives plus `SHA256SUMS` / `SHA512SUMS`.
   `release-create-draft` refuses `SHA256SUMS.minisig` (and any other extra file).
   ```bash
   make release-create-draft
   ```

6. **Sign** checksum manifests + installer (minisign) and both manifests (PGP)
   ```bash
   make release-sign
   ```
   Produces `SHA256SUMS.minisig`, `SHA512SUMS.minisig`,
   **`install-sfetch.sh.minisig` (required)**, `SHA256SUMS.asc`, `SHA512SUMS.asc`.

7. **Stage tagged public keys** (from the tagged commit, not the operator keyring)
   ```bash
   make release-export-keys
   ```

8. **Verify** (checksums + signatures + keys)
   ```bash
   make release-verify
   ```

9. **Notes and upload**
   ```bash
   make release-notes
   make release-upload
   ```
   Upload stays a draft. `install-sfetch.sh.minisig` is required.
   If `../scoop-bucket` is present, upload also updates the Scoop manifest.
   Provenance-only: `make release-upload-provenance`.

10. **Verified publish**
    ```bash
    make release-publish
    ```
    Do not run `gh release edit --draft=false`.

11. **Package-manager handoff** (after publish; no `verify-package-manager-handoff`
    target yet)
    ```bash
    python3 -m json.tool ../scoop-bucket/bucket/sfetch.json >/dev/null
    cd ../scoop-bucket && git diff bucket/sfetch.json
    ```
    Homebrew tap: update the sibling formula with the new version, darwin/arm64
    archive URL, and sha256. Do not open `brew bump-formula-pr` against a draft.

## 3. Post-Release

- [ ] Verify release: `gh release view v$(cat VERSION)` (must not be a draft)
- [ ] Homebrew tap handoff: after `make release-publish`, update the sibling `homebrew-tap` formula (or `3leaps/homebrew-tap`) with the new version, darwin/arm64 archive URL, and sha256. Do not open `brew bump-formula-pr` against a draft.
- [ ] Smoke-test install via the **verified engine** (not pipe-to-bash), against the just-published tag:
  ```bash
  TAG=v$(cat VERSION)
  DEST=$(mktemp -d)
  ./scripts/bootstrap-sfetch-verified.sh --version "$TAG" --dir "$DEST" --yes
  "$DEST/sfetch" --version   # must report $TAG
  ```
  (After first publish of this tag's signatures; draft/unsigned releases are non-consumable.)
- [ ] Verify binary version: `sfetch --version` shows correct version
- [ ] Commit and push `../scoop-bucket` after confirming `bucket/sfetch.json` has the right version and hashes
- [ ] Test on local Windows VM: `scoop bucket add 3leaps <path-or-url>` then `scoop install sfetch`
- [ ] Announce release

## 4. Post-Release Version Bump (optional)

After release, bump VERSION for next development cycle:
```bash
make version-patch   # 0.2.0 -> 0.2.1 (bugfix prep)
# or: make version-minor  # 0.2.0 -> 0.3.0 (feature prep)
# or: make version-major  # 0.2.0 -> 1.0.0 (breaking change prep)
# or: make version-set V=1.2.3  # explicit version

git add VERSION
git commit -m "chore: bump version to $(cat VERSION)-dev"
```

Check current version anytime with `make version-check`.

## Key Rotation Reminder

If rotating signing keys, also update:
- [ ] `scripts/install-sfetch.sh` - embedded `SFETCH_MINISIGN_PUBKEY`
- [ ] `README.md` - verification snippet public key
- [ ] See `docs/security/signing-runbook.md` for full rotation checklist

## Versioning Reference

- **Patch** (0.2.1): Bug fixes, security patches
- **Minor** (0.3.0): New features, backward-compatible
- **Major** (1.0.0): Breaking changes

See [ADR-0001](docs/adr/adr-0001-semver-versioning.md) for versioning policy.
