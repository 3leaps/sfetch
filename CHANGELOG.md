# Changelog

All notable changes will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [CalVer: YYYY.MM.DD](https://calver.org/).

## [Unreleased]

## [v2025.12.06] - 2025-12-06

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
