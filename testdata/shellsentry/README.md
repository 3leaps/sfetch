# shellsentry test fixtures

This folder contains test fixtures for verifying sfetch can fetch and verify
shellsentry releases.

## Files

- `shellsentry-minisign.pub` - 3 Leaps org-wide release signing key
  (shared across sfetch, shellsentry, and other 3leaps projects)

## Corpus entries

shellsentry is included in `testdata/corpus.json` with:

1. **Binary fetch** - `shellsentry_darwin_arm64.tar.gz` with Workflow A
   (checksum-level minisign signature via SHA2-512SUMS.minisig)

2. **Installer fetch** - `install-shellsentry.sh` with Workflow A

## Manual verification

```bash
# Dry-run to check verification plan
sfetch --repo 3leaps/shellsentry --latest --dry-run

# Install shellsentry
sfetch --repo 3leaps/shellsentry --latest --dest-dir ~/.local/bin

# Verify installed binary
shellsentry --version
```

## Cross-project integration

shellsentry can analyze sfetch's install script:

```bash
shellsentry scripts/install-sfetch.sh
```
