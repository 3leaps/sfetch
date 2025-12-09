# Release Notes

## v2025.12.09

### Summary
Major feature release: verification assessment, provenance records, and checksum-only workflow support.

This release makes sfetch work with the majority of GitHub releases, even those without signatures. It also adds structured provenance output for audit trails and CI integration.

### Highlights

**Verification Assessment (`--dry-run`)**
```bash
$ sfetch --repo BurntSushi/ripgrep --latest --dry-run

sfetch dry-run assessment
-------------------------
Repository:  BurntSushi/ripgrep
Release:     15.1.0
Asset:       ripgrep-15.1.0-aarch64-apple-darwin.tar.gz (1.7 MB)

Verification available:
  Signature:  none
  Checksum:   ripgrep-15.1.0-aarch64-apple-darwin.tar.gz.sha256 (sha256, per-asset)

Verification plan:
  Workflow:   C (checksum-only)
  Trust:      low

Warnings:
  - No signature available; authenticity cannot be proven
```

**Provenance Records (`--provenance`)**
```bash
# Output JSON provenance to stderr
sfetch --repo 3leaps/sfetch --latest --dest-dir /tmp --provenance

# Write provenance to file
sfetch --repo 3leaps/sfetch --latest --dest-dir /tmp --provenance-file audit.json
```

**Checksum-Only Workflow (Workflow C)**
- Supports repos like `ripgrep`, `fzf`, `lazygit` that have checksums but no signatures.
- Per-asset checksums (`.sha256`) and consolidated (`checksums.txt`, `SHA256SUMS`).
- Warns that authenticity cannot be proven without signature.

**Minisign Key Safety**
```bash
# Validate a file is a PUBLIC key (not accidentally a secret key)
sfetch --verify-minisign-pubkey /path/to/key.pub
```

### New Flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Assess verification without downloading |
| `--provenance` | Output provenance JSON to stderr |
| `--provenance-file <path>` | Write provenance to file |
| `--skip-checksum` | Skip checksum verification |
| `--insecure` | Skip ALL verification (dangerous) |
| `--minisign-key-url <url>` | Download minisign key from URL |
| `--minisign-key-asset <name>` | Use minisign key from release asset |
| `--require-minisign` | Fail if minisign not available |
| `--prefer-per-asset` | Force per-asset signature workflow |
| `--binary-name <name>` | Override inferred binary name |
| `--verify-minisign-pubkey <path>` | Validate minisign public key file |

### Trust Levels

| Level | Criteria | Example |
|-------|----------|---------|
| high | Signature + checksum verified | 3leaps/sfetch |
| medium | Signature verified, no checksum | jedisct1/minisign |
| low | Checksum only, no signature | BurntSushi/ripgrep |
| none | No verification (`--insecure`) | - |

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

### Details
- See `CHANGELOG.md` for the complete list.
- Release notes: `docs/releases/v2025.12.09.md`
- Provenance schema: `schemas/provenance.schema.json`
