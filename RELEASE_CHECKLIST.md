# Release Checklist

This document walks maintainers through the build/sign/upload flow for each sfetch release.

## 1. Prepare & Tag
- Ensure `main` is clean and `make precommit` passes
- Update `RELEASE_NOTES.md` + `docs/releases/vYYYY.MM.DD.md`
- Tag: `git tag vYYYY.MM.DD` then `git push origin main vYYYY.MM.DD`
- Wait for the GitHub Actions release workflow to finish (builds/upload unsigned archives + SHA256SUMS)

## 2. Manual Signing (local machine)
1. **Download artifacts**
   ```bash
   RELEASE_TAG=vYYYY.MM.DD make release-download
   ```
2. **Sign archives + regenerate checksums**
   ```bash
   PGP_KEY_ID=<your-subkey-id!> RELEASE_TAG=vYYYY.MM.DD make release-sign
   ```
   - This target regenerates `SHA256SUMS` before signing every artifact.
   - `PGP_KEY_ID` is the long key ID (append `!` to pin a subkey)
3. **Export the matching public key**
   ```bash
   PGP_KEY_ID=<your-subkey-id> RELEASE_TAG=vYYYY.MM.DD make release-export-key
   ```
   (runs `scripts/export-release-key.sh` → writes `dist/release/sfetch-release-signing-key.asc`)
4. **Verify the exported key is public-only**
   ```bash
   make verify-release-key
   ```
5. **Copy release notes**
   ```bash
   RELEASE_TAG=vYYYY.MM.DD make release-notes
   ```
6. **Upload binaries + checksums + signatures**
   ```bash
   RELEASE_TAG=vYYYY.MM.DD make release-upload
   ```

## 3. Post-Release
- Verify the release via `gh release view vYYYY.MM.DD`
- Update downstream package manifests (Homebrew/Scoop) if needed
- Announce release notes
