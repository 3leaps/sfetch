# Changelog

All notable changes will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note**: Versions prior to 0.2.0 used CalVer (vYYYY.MM.DD). See [ADR-0001](docs/adr/adr-0001-semver-versioning.md) for migration details.

## [Unreleased]

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
- **Cross-device installs/caching (EXDEV):** When `--dest-dir` or `--cache-dir` is on a different filesystem than the temp directory (common in containerized CI), sfetch now falls back to copy when `rename(2)` fails with “invalid cross-device link”.

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

## [0.2.4] - 2025-12-12

### Fixed
- **Self-update checksum mismatch:** Fixed self-update and fetch failing when SHA2-512SUMS is preferred over SHA256SUMS. Added `detectChecksumAlgorithm()` to infer hash algorithm from checksum filename patterns.

## [0.2.3] - 2025-12-12

### Changed
- **Installer parsing:** Prefer `jq` (if present) for GitHub release JSON parsing; dependency-free fallback retained.
- **Make bootstrap:** `make bootstrap` now advisory via `prereqs-advise`; `make prereqs` remains strict.

### Fixed
- **Signing script GPG support:** Added `GPG_HOMEDIR` environment variable support for custom GPG homedirs. Uses `env GNUPGHOME=...` to avoid polluting user's global GPG settings.

### Security
- Added threat-model comments for pre-extraction path traversal scanning and unzip listing portability in installer.

### Documentation
- Updated docs to reflect checksum-only opt-in and signature defaults.
- Added DO/DONOT section to `AGENTS.md` with push approval and release merge policies.
- Updated `RELEASE_CHECKLIST.md` to document all required environment variables including `GPG_HOMEDIR`.

## [0.2.2] - 2025-12-12

### Added
- **Smart asset selection (Phase 1):** Rule-driven tie-breaking eliminates need for `--asset-match` or `--asset-regex` in most cases.
  - Platform exclusions: `.exe` filtered on darwin/linux automatically.
  - Case-insensitive platform/arch token matching: `macOS`, `Darwin`, `MACOS` all match darwin.
  - Raw-over-archive preference: `yt-dlp_macos` preferred over `yt-dlp_macos.zip`.
  - Schema-validated rules: `schemas/inference-rules.schema.json` + embedded `inference-rules.json`.
- **Expanded checksum/signature discovery:** Added `SHA2-256SUMS`, `SHA2-512SUMS`, `SHA512SUMS` patterns and their signature variants (`.minisig`, `.asc`, `.sig`) to support repos like yt-dlp that use non-standard naming.
- **Heuristic `.sig` handling:** Checksum-level `.sig` files (e.g., `SHA2-256SUMS.sig`) are treated as PGP signatures; per-asset `.sig` files remain ed25519.
- **SHA2-512SUMS generation:** Release process now generates both `SHA256SUMS` and `SHA2-512SUMS` for dual-hash verification.
- **Self-update workflow:** Secure self-update capability with `--self-update`, `--self-update-force`, and `--self-update-dir` flags. Uses existing verification pipeline, enforces major-version guard, and provides Windows lock fallback.

### Changed
- Asset selection flow now applies inference rules before falling back to legacy scoring heuristics.
- `findChecksumSignature` now strips `.sig` extension in addition to `.minisig` and `.asc`.
- `signatureFormatFromExtension` uses context-aware heuristic: `*SUMS.sig` → PGP, other `.sig` → ed25519.
- Replaced shell-based checksum generator (`scripts/generate-sha256sums.sh`) with Go command (`scripts/cmd/generate-checksums`).
- Signing/upload scripts updated to handle both SHA256SUMS and SHA2-512SUMS.

### Fixed
- Test `TestInferenceRulesDocumentValidates` now correctly unmarshals JSON before schema validation.
- Makefile `shell-check` target now uses same shfmt flags (`-i 4 -ci`) as `fmt` target.

## [0.2.1] - 2025-12-10

### Added
- **Self-verify & trust anchors:** `--self-verify` prints deterministic release URLs, expected asset/hash (with offline fallback), platform-specific checksum commands, minisign/PGP commands, embedded pubkey, and warning that a compromised binary could lie. `--show-trust-anchors` exposes the embedded minisign key (JSON/plain).
- **Real-world corpus (opt-in):** Manifest + runner to exercise common release patterns via `make corpus-dryrun`.

## [0.2.0] - 2025-12-09

### Added
- **Verification Assessment & Provenance**: `--dry-run`, `--provenance`, `--provenance-file` for structured JSON audit trails.
- **Workflow C (checksum-only)**: Support for repos that publish checksums without signatures.
- **Asset classification & raw installs**: Scripts and standalone binaries skip extraction; chmod on macOS/Linux.
- **Minisign enhancements**: `--minisign-key-url`, `--minisign-key-asset`, `--require-minisign`, `--prefer-per-asset`, auto-detection of `.pub` files.
- **Trust levels**: Computed trust assessment (high/medium/low/none) based on verification performed.
- **Versioning**: Adopted Semantic Versioning; `VERSION` file as single source of truth.

---

For older releases, see `docs/releases/`.
