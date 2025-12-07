# Release Checklist

This document walks maintainers through the build/sign/upload flow for each sfetch release.

## 1. Prepare & Tag

- [ ] Ensure `main` is clean and `make precommit` passes
- [ ] Update `CHANGELOG.md` (move Unreleased to new version section)
- [ ] Update `RELEASE_NOTES.md`
- [ ] Create `docs/releases/vYYYY.MM.DD.md`
- [ ] Commit: `git add -A && git commit -m "docs: add vYYYY.MM.DD release notes"`
- [ ] Push and tag:
  ```bash
  git push origin main
  git tag vYYYY.MM.DD
  git push origin vYYYY.MM.DD
  ```
- [ ] Wait for GitHub Actions release workflow to complete (builds unsigned archives, uploads install-sfetch.sh)

## 2. Manual Signing (local machine)

Set environment variables:
```bash
export MINISIGN_KEY=/path/to/sfetch.key
export PGP_KEY_ID=security@fulmenhq.dev  # or your-subkey-id!
```

### Steps

1. **Download artifacts**
   ```bash
   RELEASE_TAG=vYYYY.MM.DD make release-download
   ```

2. **Sign SHA256SUMS** (generates checksums, signs with minisign + PGP)
   ```bash
   RELEASE_TAG=vYYYY.MM.DD make release-sign
   ```
   Produces: `SHA256SUMS`, `SHA256SUMS.minisig`, `SHA256SUMS.asc`

3. **Export public keys**
   ```bash
   make release-export-minisign-key   # → sfetch-minisign.pub
   make release-export-key            # → sfetch-release-signing-key.asc
   ```

4. **Verify exported PGP key is public-only**
   ```bash
   make verify-release-key
   ```

5. **Copy release notes**
   ```bash
   RELEASE_TAG=vYYYY.MM.DD make release-notes
   ```

6. **Upload signatures and keys**
   ```bash
   RELEASE_TAG=vYYYY.MM.DD make release-upload
   ```

## 3. Post-Release

- [ ] Verify release: `gh release view vYYYY.MM.DD`
- [ ] Test install script: `curl -sSfL .../install-sfetch.sh | bash -s -- --dry-run`
- [ ] Update downstream package manifests (Homebrew/Scoop) if needed
- [ ] Announce release

## Key Rotation Reminder

If rotating signing keys, also update:
- [ ] `scripts/install-sfetch.sh` - embedded `SFETCH_MINISIGN_PUBKEY`
- [ ] `README.md` - verification snippet public key
- [ ] See `docs/security/signing-runbook.md` for full rotation checklist
