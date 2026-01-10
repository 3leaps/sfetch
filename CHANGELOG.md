# Changelog

All notable changes will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note**: Versions prior to 0.2.0 used CalVer (vYYYY.MM.DD). See [ADR-0001](docs/adr/adr-0001-semver-versioning.md) for migration details.

## [Unreleased]

## [0.4.0] - 2026-01-10

### Added
- **Arbitrary URL fetch:** New `--url` mode (or positional URL) with HTTPS-first defaults and optional `--allow-http` override.
- **Raw GitHub content:** Added `--github-raw owner/repo@ref:path` for raw files hosted in GitHub repos.
- **URL safety controls:** `--follow-redirects`, `--max-redirects`, `--allowed-content-types`, and `--allow-unknown-content-type` gates.
- **GitHub URL upgrade:** Release asset URLs automatically route through the GitHub release verification flow.
- **Provenance redirects:** URL provenance now records redirect chains.
- **Corpus expansion:** Added URL and format coverage with optional HTTP test cases.

### Documentation
- Added URL, GitHub raw, and safety flag guidance in `README.md` and quickstart.

### Security
- Block URL credentials by default to avoid leaking user info during redirects.

## [0.3.4] - 2026-01-10

### Added
- **Proxy support:** New `--http-proxy`, `--https-proxy`, and `--no-proxy` flags with environment variable overrides (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) for proxied networks.
- **Proxy validation tests:** Added coverage for proxy URL validation and env overrides.

### Documentation
- Documented proxy support in `README.md`.

## [0.3.3] - 2026-01-10

### Documentation
- Added a local agent role catalog and operating model guidance for supervised sessions.

## [0.3.2] - 2026-01-02

### Added
- **shellsentry integration:** Added shellsentry to `testdata/corpus.json` with minisign verification fixtures.
- **Test coverage improvements:** Comprehensive test suite expansion across 5 passes:
  - Pass 1: Pure functions (inferBinaryName, archiveFormat, tokenCI, etc.)
  - Pass 2: internal/verify edge cases (checksum detection, signature formats)
  - Pass 3: CLI flag validation (mutual exclusivity, required flags, help/version)
  - Pass 4: Asset selection logic (heuristics, match/regex, pattern rendering)
  - Pass 5: Trust score calculation (algorithms, penalties, score capping)

### Changed
- **stdout/stderr convention:** All human-readable output now goes to stderr; stdout reserved for JSON only. Affected: `--version`, `--version-extended`, `--self-verify`, `--show-trust-anchors`, `--dry-run`, `--helpextended`, success messages. This enables clean piping of JSON output in CI/CD pipelines.

### Fixed
- **LICENSE:** Added project name notice and updated contact email.

## [0.3.1] - 2025-12-31

### Fixed
- **Raw scripts no longer misclassified as archives:** Fixed regression where raw scripts (e.g., `install-sfetch.sh`) were incorrectly treated as archives when the default config includes `archiveType: "tar.gz"`. The legacy `archiveType` field now only applies to assets that are actually archives or have unknown type.

### Documentation
- Added `make release-verify-checksums` step to `RELEASE_CHECKLIST.md`.

## [0.3.0] - 2025-12-29

### Added
- **Trust rating system (v0.3.0):** Numeric trust score (0–100) with transparent factor breakdown.
- **Policy gating:** New `--trust-minimum <0-100>` blocks downloads below the threshold.
- **Workflow `none`:** Explicitly represents sources that provide no verification artifacts (distinct from bypass via `--insecure`).
- **Dogfood corpus expansion:** Corpus continues to live in `testdata/corpus.json` and is runnable via `make corpus-dryrun`.

### Changed
- **Provenance schema:** Added `trust` object (`score`, `level`, `levelName`, `factors`) while retaining legacy `trustLevel` for one minor cycle.
- **CLI output:** Normal runs now print trust score; dry-run includes a verifiable/validated breakdown.

### Fixed
- Clarified dry-run messaging to avoid implying integrity when signature artifacts exist but no verification key is available.

## [0.2.9] - 2025-12-25

### Fixed
- **Asset selection now works for `minisign` and similar tool names:** Fixed false positive in supplemental file detection where tools containing "sig" in their name (like `minisign`, `cosign`, `design-tool`) were incorrectly excluded from asset selection. The fix removes the overly broad substring check and adds explicit `.minisig` suffix detection.

### Documentation
- Added "Install permissions" section to README documenting permission behavior for archives, raw scripts/binaries, and cross-device installs.

## [0.2.8] - 2025-12-14

### Added
- **Linux `noexec` detection (warn-only):** sfetch now warns when the install destination appears to be mounted with `noexec`.

### Changed
- **Release notes source is now versioned:** `make release-notes` now requires `docs/releases/$RELEASE_TAG.md` and fails if missing.
- **More deterministic install behavior tests:** install logic is factored into a helper to enable unit tests for rename vs EXDEV copy fallback.

### Security
- Expanded test coverage for ZIP extraction edge cases (zip slip, absolute paths, symlinks).

## [0.2.7] - 2025-12-14

### Changed
- **ZIP extraction is now pure-Go:** `.zip` assets are extracted via the Go standard library (`archive/zip`), removing the runtime dependency on `unzip`.

### Security
- **Hardened ZIP extraction:** ZIP slip/path traversal, absolute paths, and symlinks are rejected during extraction.

## [0.2.6] - 2025-12-14

### Fixed
- **Cross-device installs/caching (EXDEV):** When `--dest-dir` or `--cache-dir` is on a different filesystem than the temp directory (common in containerized CI), sfetch now falls back to copy when `rename(2)` fails with "invalid cross-device link".

### Changed
- Refactored internals to improve auditability and testability (moved logic into `internal/*` and introduced an injectable CLI entrypoint); CLI behavior is intended to be unchanged.

### Documentation
- Added CI/CD usage guide: `docs/cicd-usage-guide.md`.

## [0.2.5] - 2025-12-13

### Added
- **Self-update version check:** `--self-update` now skips reinstall when already at the target version; `--self-update-force` reinstalls; `--tag` allows explicit downgrades (major-version guard still applies).
- **Embedded self-update config:** Self-update uses an embedded, schema-backed update target config (`configs/update/sfetch.json`), with `--show-update-config` and `--validate-update-config`.
- **Update library (initial):** New `pkg/update` package exposes self-update decision logic for reuse.
- **Dry-run version info:** `--self-update --dry-run` now shows version comparison (current/target/status).

### Changed
- Build now targets the package (not `./main.go`) so multi-file `main` builds work (`Makefile` `MAIN ?= .`).
- **Signing env vars standardized:** All signing-related environment variables now use an `SFETCH_` prefix for CI/scripting consistency:
  - `MINISIGN_KEY` → `SFETCH_MINISIGN_KEY`
  - `PGP_KEY_ID` → `SFETCH_PGP_KEY_ID`
  - `GPG_HOMEDIR` → `SFETCH_GPG_HOMEDIR`
  - Added `SFETCH_MINISIGN_PUB` for explicit public key path.
- Dev builds no longer require `--self-update-force` to proceed (easier exit path for developers).

---

> **Maintenance note:** This file is pruned to the latest 10 releases. For older entries, see `docs/releases/`.
