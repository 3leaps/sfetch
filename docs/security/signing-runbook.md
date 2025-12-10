---
title: Release Signing Runbook
description: How to sign releases with minisign and PGP for sfetch and derivative projects
author_of_record: Dave Thompson (@3leapsdave)
status: stable
---

# Release Signing Runbook

This guide covers the dual-signature release process used by sfetch. If you're forking this repo or building similar tools, adapt these steps for your own signing keys.

## Why Minisign

sfetch uses minisign as the primary signing format instead of raw ed25519 signatures:

- Created by Frank Denis (libsodium author) - the tool has been audited and is widely trusted
- Trusted comments are signed, providing verifiable metadata (version, timestamp)
- Secret keys are password-protected by default
- Compatible with OpenBSD signify
- Small, focused codebase with minimal attack surface

PGP signatures are provided as a secondary option for users who prefer gpg tooling.

## What Gets Signed

Only `SHA256SUMS` is signed, not individual archive files. This is standard practice:

1. User downloads archive + `SHA256SUMS` + signature (`SHA256SUMS.minisig` or `SHA256SUMS.asc`)
2. Verify signature on `SHA256SUMS`
3. Verify archive checksum against `SHA256SUMS`

This approach means one signature operation per release (one password prompt) while providing the same security guarantees. Signing individual files would be redundant since their checksums are already in the signed `SHA256SUMS`.

## Signature Formats

| Format | File | Verification | Client Dependency |
|--------|------|--------------|-------------------|
| **minisign** | `SHA256SUMS.minisig` | `sfetch --minisign-key <path>` or auto-detect | None (pure-Go) |
| **PGP** | `SHA256SUMS.asc` | `sfetch --pgp-key-file <path>` or auto-detect | `gpg` binary |

**Minisign key flags:**
- `--minisign-key <path>` - Local file or URL
- `--minisign-key-url <url>` - Download from URL
- `--minisign-key-asset <name>` - Fetch from release assets
- `--require-minisign` - Fail if minisign verification unavailable
- Auto-detects `*minisign*.pub` from release assets when no flags provided

## Key Generation

### Minisign (Primary)

```bash
# Generate keypair (will prompt for password)
minisign -G -p sfetch-minisign.pub -s sfetch-minisign.key -t "3 Leaps Release Signing"

# Use -t for trusted comment (signed), not -c (untrusted)
```

Install minisign: `brew install minisign` (macOS) or see https://jedisct1.github.io/minisign/

### PGP (Optional)

Use your existing GPG key or generate one:

```bash
gpg --full-generate-key
gpg --list-keys --keyid-format long  # Find your KEY_ID
```

## Signing Workflow

### Prerequisites

```bash
# Set environment variables
export MINISIGN_KEY=/secure/path/to/sfetch-minisign.key
export PGP_KEY_ID=security@yourorg.dev  # Optional
```

### Manual Release Signing

```bash
# 1. Download CI-built artifacts
RELEASE_TAG=v0.2.0 make release-download

# 2. Generate SHA256SUMS and sign it
RELEASE_TAG=v0.2.0 make release-sign
# Produces: SHA256SUMS, SHA256SUMS.minisig, SHA256SUMS.asc (if PGP_KEY_ID set)

# 3. Export public keys for the release
make release-export-minisign-key
make release-export-key  # PGP, requires PGP_KEY_ID

# 4. Verify the exported PGP key
make verify-release-key

# 5. Copy release notes
RELEASE_TAG=v0.2.0 make release-notes

# 6. Upload to GitHub
RELEASE_TAG=v0.2.0 make release-upload
```

### Verification Test

After signing, verify locally before upload:

```bash
# Test minisign verification (explicit key)
sfetch --minisign-key dist/release/sfetch-minisign.pub \
       --repo yourorg/sfetch --tag v0.2.0 --dest-dir /tmp/test

# Test minisign verification (strict mode - requires minisign, auto-detects key)
sfetch --require-minisign \
       --repo yourorg/sfetch --tag v0.2.0 --dest-dir /tmp/test

# Test PGP verification
sfetch --pgp-key-file dist/release/sfetch-release-signing-key.asc \
       --repo yourorg/sfetch --tag v0.2.0 --dest-dir /tmp/test
```

## Key Security

### Storage

| Environment | Recommendation |
|-------------|----------------|
| Local dev | Password manager (1Password, Bitwarden) |
| CI/CD | GitHub Secrets, Vault, or cloud KMS |
| High security | Hardware token (YubiKey) or HSM |

Minisign keys are password-protected, adding a layer of security even if the key file is exposed.

### Rotation

- **Schedule**: Annually, or immediately on suspected compromise
- **Process**: Generate new keypair, publish new public key, overlap for 2 releases
- **Announcement**: Document in release notes and README

**Key Rotation Checklist:**

1. Generate new minisign keypair:
   ```bash
   minisign -G -p sfetch-minisign-NEW.pub -s sfetch-minisign-NEW.key
   ```

2. Update embedded trust anchor in `scripts/install-sfetch.sh`:
   ```bash
   # Replace SFETCH_MINISIGN_PUBKEY value with new public key
   # (second line of the .pub file, the base64 key without the comment)
   ```

3. Update README verification snippet with new public key

4. For the transition period (2 releases):
   - Sign with BOTH old and new keys
   - Document both public keys in release notes

5. After transition: remove old key references

**On Compromise:**

If a signing key is compromised:
- Immediately rotate to a new key
- Consider re-signing recent releases with the new key
- Old releases signed with the compromised key remain valid for historical purposes unless explicitly revoked
- Document the incident and affected release range in security advisory

### Access Control

- Limit signing key access to release maintainers
- Store secret keys separately from the codebase
- Use separate keys for different projects/organizations

## Adapting for Your Project

If you're using sfetch's signing infrastructure for another project:

1. **Generate your own keys** - don't reuse sfetch keys
2. **Update Makefile variables**:
   ```makefile
   MINISIGN_PUB_NAME ?= yourproject-minisign.pub
   PUBLIC_KEY_NAME ?= yourproject-release-signing-key.asc
   ```
3. **Document your public key** in your README
4. **Publish public keys** with every release

## Troubleshooting

### "minisign not found in PATH"

Install minisign:
```bash
brew install minisign          # macOS
apt install minisign           # Debian/Ubuntu
# Or download from https://jedisct1.github.io/minisign/
```

### "MINISIGN_KEY not set"

Set the environment variable to your secret key path:
```bash
export MINISIGN_KEY=/path/to/your-key.key
```

### "public key not found"

Minisign generates `.key` and `.pub` files together. Ensure the `.pub` file is in the same directory as the `.key` file, with matching basename.

### Password prompt during signing

This is expected - minisign keys are password-protected. Enter the password you set during key generation. For CI, you may need to use `minisign -W` to remove password protection (consider the security tradeoffs).

## References

- [minisign](https://jedisct1.github.io/minisign/) - Official documentation
- [docs/security.md](../security.md) - Security scanning and verification
- [docs/key-handling.md](../key-handling.md) - Key formats and verification flags
