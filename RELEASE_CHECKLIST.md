# Release Checklist

This document walks maintainers through the build/sign/upload flow for each sfetch release.

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

3. **Generate & sign checksum manifests** (`SHA256SUMS`, `SHA2-512SUMS`) with minisign + PGP
   ```bash
   make release-checksums
   make release-sign
   ```
   Produces: `SHA256SUMS`, `SHA2-512SUMS` plus `.minisig`/`.asc`

4. **Export public keys** (auto-validates before copying)
   ```bash
   make release-export-minisign-key   # → sfetch-minisign.pub (validates it's not secret key!)
   make release-export-key            # → sfetch-release-signing-key.asc
   ```

5. **Verify exported keys are public-only**
   ```bash
   make verify-release-key                                    # PGP key
   make verify-minisign-pubkey FILE=dist/release/sfetch-minisign.pub  # minisign key (optional, done in step 4)
   ```

6. **Copy release notes** (requires `docs/releases/$RELEASE_TAG.md`)
   ```bash
   make release-notes
   ```

7. **Upload signatures and keys**
   ```bash
   make release-upload
   ```
   > **Note:** This uploads ALL assets with `--clobber`, including binaries CI already uploaded.
   > This is intentional for idempotency - rerun safely to fix any mistakes.

## 3. Post-Release

- [ ] Verify release: `gh release view v$(cat VERSION)`
- [ ] Test install script: `curl -sSfL .../install-sfetch.sh | bash -s -- --dry-run`
- [ ] Verify binary version: `sfetch --version` shows correct version
- [ ] Update downstream package manifests (Homebrew/Scoop) if needed
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
