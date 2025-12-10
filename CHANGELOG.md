# Changelog

All notable changes will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note**: Versions prior to 0.2.0 used CalVer (vYYYY.MM.DD). See [ADR-0001](docs/adr/adr-0001-semver-versioning.md) for migration details.

## [Unreleased]

## [0.2.1] - 2025-12-10

### Added
- **Self-verify & trust anchors:** `--self-verify` prints deterministic release URLs, expected asset/hash (with offline fallback), platform-specific checksum commands, minisign/PGP commands, embedded pubkey, and warning that a compromised binary could lie. `--show-trust-anchors` exposes the embedded minisign key (JSON/plain). Docs updated in README and docs/security; installer logs post-install hint.
- **Real-world corpus (opt-in):** Manifest + runner to exercise common release patterns; Make targets `corpus`, `corpus-all`, `corpus-dryrun`; docs section in `docs/examples.md`; guidance in `docs/test-corpus/README.md`. Manifest/schema live in `testdata/` (dry-run by default; opt-in downloads; token optional for rate limits).
- **Checksum discovery expansion:** Added version-aware templates and additional defaults (`sha256sum.txt`, `SHA256SUMS_64`, `{{binary}}_{{versionNoPrefix}}_checksums.txt`, etc.) to improve checksum detection for real-world repos.

### Changed
- Help output grouped to include new flags (`--asset-match`, `--self-verify`, `--show-trust-anchors`).

## [0.2.0] - 2025-12-09

### Added
- **Verification Assessment & Provenance**: Structured JSON provenance records for audit trails and CI integration.
  - `--dry-run`: Assess what verification is available without downloading.
  - `--provenance`: Output provenance record JSON to stderr after operation.
  - `--provenance-file <path>`: Write provenance record to file.
  - Schema: `schemas/provenance.schema.json` (JSON Schema 2020-12).
- **Workflow C (checksum-only)**: Support for repos that publish checksums without signatures.
  - Per-asset checksums (`.sha256`, `.sha512`) and consolidated (`checksums.txt`, `SHA256SUMS`).
  - Warning emitted when no signature available.
- **Asset classification & raw installs**:
  - New `AssetType`/`ArchiveFormat` fields with expanded archive defaults (`.tar.xz`, `.tar.bz2`, `.tar`, aliases).
  - Raw scripts and standalone binaries skip extraction; chmod on macOS/Linux; package installers (`.deb/.rpm/.pkg/.msi`) tagged and warned.
  - Flag: `--asset-type` override; Schema: `schemas/repo-config.schema.json` updated for new fields.
- **Asset selection overrides**:
  - `--asset-match`: Glob/substring asset selection (user-friendly).
  - `--asset-regex`: Advanced regex selection retained.
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
- **Versioning**: Adopted Semantic Versioning; `VERSION` file as single source of truth.

### Changed
- Verification workflow detection now prefers checksum-level signatures (Workflow A) over per-asset (Workflow B) by default.
- Minisign verification uses pure-Go `github.com/jedisct1/go-minisign` library (no external dependencies).
- `RepoConfig` struct now includes `SignatureFormats` for extension-based signature type detection.
- CI workflow validates `VERSION` file matches git tag at release time.

### Fixed
- Minisign per-asset signatures (Workflow B) now correctly skip checksum verification when checksum file unavailable.

## [0.1.1] - 2025-12-06

_Formerly v2025.12.06.1_

### Fixed
- Install script EXIT trap error due to `local` variable scoping.
- SHA256SUMS now contains basenames only (was including `dist/release/` prefix).

### Changed
- CI now tests install script with `--dry-run` to catch runtime issues.
- README verification examples use `shasum -a 256` (macOS compatible) and temp GPG keyring.
- Upload script includes minisign files (`SHA256SUMS.minisig`, `sfetch-minisign.pub`).

## [0.1.0] - 2025-12-05

_Formerly v2025.12.05_

### Added
- Initial public release.
- `--minisign-key` flag for pure-Go minisign signature verification.
- `install-sfetch.sh` bootstrap installer with embedded minisign trust anchor.
- Dual signing: SHA256SUMS signed with both minisign (.minisig) and PGP (.asc).
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
