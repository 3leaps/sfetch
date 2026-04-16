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
- [ ] Update `VERSION` file with new semver (e.g., `0.2.0`)
- [ ] Update `CHANGELOG.md` (move Unreleased to new version section)
- [ ] Update `RELEASE_NOTES.md`
- [ ] Create `docs/releases/vX.Y.Z.md`
- [ ] Commit: `git add -A && git commit -m "release: prepare vX.Y.Z"`
- [ ] Push and tag:
  ```bash
  git push origin main
  git tag v$(cat VERSION)
  git push origin v$(cat VERSION)
  ```
- [ ] Wait for GitHub Actions release workflow to complete
  - CI validates VERSION file matches tag
  - Builds unsigned archives
  - Uploads install-sfetch.sh

## 2. Manual Signing (local machine)

Set environment variables:
```bash
export RELEASE_TAG=v$(cat VERSION)
export SFETCH_MINISIGN_KEY=/path/to/sfetch.key
export SFETCH_MINISIGN_PUB=/path/to/sfetch.pub
export SFETCH_PGP_KEY_ID="security@fulmenhq.dev"        # or your-subkey-id!
export SFETCH_GPG_HOMEDIR=/path/to/custom/gpg/homedir   # optional, defaults to ~/.gnupg
```

### Steps

1. **Clean previous release artifacts**
   ```bash
   make release-clean
   ```

2. **Download artifacts**
   ```bash
   make release-download
   ```

3. **Generate checksum manifests** (`SHA256SUMS`, `SHA512SUMS`)
   ```bash
   make release-checksums
   ```

4. **Verify checksums**
   ```bash
   make release-verify-checksums
   ```

5. **Sign checksum manifests** with minisign + PGP
   ```bash
   make release-sign
   ```
   Produces: `SHA256SUMS`, `SHA512SUMS` plus `.minisig`/`.asc`

6. **Verify signatures**
   ```bash
   make release-verify-signatures
   ```

7. **Export public keys** (auto-validates before copying)
   ```bash
   make release-export-keys
   ```
   Exports both `sfetch-minisign.pub` and `sfetch-release-signing-key.asc`.

8. **Verify exported keys are public-only**
   ```bash
   make release-verify-keys
   ```

9. **Copy release notes** (requires `docs/releases/$RELEASE_TAG.md`)
   ```bash
   make release-notes
   ```

10. **Upload release assets and update Scoop**
    ```bash
    make release-upload
    ```
    > **Note:** This uploads ALL assets with `--clobber`, including binaries CI already uploaded.
    > This is intentional for idempotency - rerun safely to fix any mistakes.
    >
    > If `../scoop-bucket` is present, this target also runs `make update-scoop-manifest` at the end so the bucket is ready for commit/push immediately after release upload.
    >
    > To upload provenance only (manifests, signatures, keys, notes):
    > ```bash
    > make release-upload-provenance
    > ```

11. **Verify the Scoop manifest update**
    ```bash
    python3 -m json.tool ../scoop-bucket/bucket/sfetch.json >/dev/null
    ```
    Review the diff before committing the bucket repo:
    ```bash
    cd ../scoop-bucket && git diff bucket/sfetch.json
    ```

## 3. Post-Release

- [ ] Verify release: `gh release view v$(cat VERSION)`
- [ ] Test install script: `curl -sSfL .../install-sfetch.sh | bash -s -- --dry-run`
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
