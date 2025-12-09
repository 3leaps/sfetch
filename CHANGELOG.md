# Changelog

All notable changes will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [CalVer: YYYY.MM.DD](https://calver.org/).

## [Unreleased]

## [v2025.12.09] - 2025-12-09

### Added
- **Verification Assessment & Provenance**: Structured JSON provenance records for audit trails and CI integration.
  - `--dry-run`: Assess what verification is available without downloading.
  - `--provenance`: Output provenance record JSON to stderr after operation.
  - `--provenance-file <path>`: Write provenance record to file.
  - Schema: `schemas/provenance.schema.json` (JSON Schema 2020-12).
- **Workflow C (checksum-only)**: Support for repos that publish checksums without signatures.
  - Per-asset checksums (`.sha256`, `.sha512`) and consolidated (`checksums.txt`, `SHA256SUMS`).
  - Warning emitted when no signature available.
- **Override flags**:
  - `--skip-checksum`: Skip checksum verification even if available.
  - `--insecure`: Skip ALL verification (dangerous - use only for testing).
- **Minisign enhancements**:
  - `--minisign-key-url`: Download minisign public key from URL.
  - `--minisign-key-asset`: Use minisign public key from release asset.
  - `--require-minisign`: Fail if minisign signature not available.
  - `--prefer-per-asset`: Force Workflow B over Workflow A when both available.
  - Auto-detection of minisign public keys in release assets (`.pub` files).
  - `--verify-minisign-pubkey <path>`: Validate file is a public key (not secret key).
- **Inference improvements**:
  - `--binary-name`: Override inferred binary name.
  - Binary name inferred from repo name (e.g., `jedisct1/minisign` → `minisign`).
  - Archive type inferred from asset extension (`.tar.gz`, `.zip`, `.tgz`).
- **Trust levels**: Computed trust assessment (high/medium/low/none) based on verification performed.
- **Documentation**: Comprehensive `docs/examples.md` with real-world examples and pattern matching transparency.
- **Integration tests**: Full minisign verification tests with testdata fixtures.
- **Unit tests**: `TestValidateMinisignPubkey` covering public key validation (rejects secret keys, signatures).

### Changed
- Verification workflow detection now prefers checksum-level signatures (Workflow A) over per-asset (Workflow B) by default.
- Minisign verification uses pure-Go `github.com/jedisct1/go-minisign` library (no external dependencies).
- `RepoConfig` struct now includes `SignatureFormats` for extension-based signature type detection.

### Fixed
- Minisign per-asset signatures (Workflow B) now correctly skip checksum verification when checksum file unavailable.

## [v2025.12.06.1] - 2025-12-06

### Fixed
- Install script EXIT trap error due to `local` variable scoping.
- SHA256SUMS now contains basenames only (was including `dist/release/` prefix).

### Changed
- CI now tests install script with `--dry-run` to catch runtime issues.
- README verification examples use `shasum -a 256` (macOS compatible) and temp GPG keyring.
- Upload script includes minisign files (`SHA256SUMS.minisig`, `sfetch-minisign.pub`).

## [v2025.12.06] - 2025-12-06 [YANKED]

**Note:** This release had a bug in install-sfetch.sh. Use v2025.12.06.1 instead.

### Added
- `--minisign-key` flag for pure-Go minisign signature verification.
- `install-sfetch.sh` bootstrap installer with embedded minisign trust anchor.
- Dual signing: SHA256SUMS signed with both minisign (.minisig) and PGP (.asc).
- `shell-check` Makefile target (shellcheck + shfmt) added to precommit.
- Key rotation checklist in `docs/security/signing-runbook.md`.
- Pre-pipe verification docs with minisign and GPG options.

### Changed
- Install script included in SHA256SUMS for unified verification.
- CI workflow installs shellcheck and shfmt for shell script validation.
- Release workflow uploads install-sfetch.sh as release asset.

### Removed
- `bootstrap.sh` (replaced by `install-sfetch.sh` with proper verification).

## [v2025.12.05] - 2025-12-05

### Added
- Embedded quickstart text printable via `sfetch -helpextended`.
- `buildconfig.mk` to centralize binary name and install defaults.
- `--pgp-key-url` / `--pgp-key-asset` flags and auto-detection for `.asc` key assets.
- `make install` now targets user-space (`~/.local/bin` or `%USERPROFILE%\bin`).
- Documentation for asset heuristics, key lookup order, and quickstart instructions.

### Changed
- Release workflow packages archives/zips with a consistent `sfetch` or `sfetch.exe` binary name.
- Bootstrap script downloads the correct platform archive and installs to `/usr/local/bin/sfetch`.
- `resolvePGPKey` now downloads keys from URLs/release assets and is covered by tests.

### Fixed
- Supplemental asset detection now ignores `.asc`/`.sig` candidates when scoring binary assets.
- Repo-specific configs inherit defaults rather than overriding entire structs.
