# Changelog

All notable changes will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note**: Versions prior to 0.2.0 used CalVer (vYYYY.MM.DD). See [ADR-0001](docs/adr/adr-0001-semver-versioning.md) for migration details.

## [Unreleased]

## [0.4.10] - 2026-07-30

### Fixed

- **Release checksum verification is fail-closed.** `make release-verify-checksums` now requires non-empty `SHA256SUMS` and `SHA512SUMS` and runs `shasum -c` without piping away the exit status, so a corrupted asset or missing/empty manifest fails the target.
- **Maintainer Make upload targets require full verification.** `make release-upload` and `make release-upload-provenance` both depend on `make release-verify` (checksums + signatures + keys). Tag CI may still publish unsigned platform archives and the install script before the manual sign/verify/upload phase; this change gates the maintainer Make upload recipes only.

### Added

- Composite `make release-verify` target and a hermetic regression harness (`scripts/test-release-verify-checksums.sh`) covering valid, corrupted, absent, and empty manifests. The harness is wired into `make precommit` (the gate CI runs).

## [0.4.9] - 2026-07-29

### Changed
- **Go toolchain pinned to 1.26.5.** `go.mod` now declares `go 1.25.12` with `toolchain go1.26.5`, and CI/release `setup-go` pins `1.26.5`. Clears reachable stdlib advisories (including GO-2026-5856) while remaining inside Go's supported-major window.
- **Dependencies updated:** `golang.org/x/crypto` v0.53.0 → v0.54.0, `golang.org/x/sys` v0.46.0 → v0.47.0, `golang.org/x/text` v0.38.0 → v0.40.0. Pinned `govulncheck@v1.6.0` on the precommit/CI path reports zero reachable vulnerabilities.
- **goneat pinned to v0.5.15** (was v0.5.13) across the `Makefile` and all CI dogfood install steps; installed via sfetch with minisign verification.
- **Release publish action bumped to Node 24.** `softprops/action-gh-release@v2` (Node 20) → `@v3` (Node 24) on both release steps.

### Fixed
- **Self-bootstrap trust anchor.** `make bootstrap` now passes the installer `--dir` flag (was incorrect `--dest`), pins the binary with `--tag` matching `SFETCH_VERSION` (N-1: v0.4.8), and requires minisign verification. The installer script and installed binary are the same reviewed release.
- **Unpinned schema CLI removed from precommit.** Corpus validation runs in-repo via `jsonschema/v6` v6.0.2 (the product dependency) instead of network-fetched `cmd/jv@latest`.

### Added
- **Pinned `govulncheck@v1.6.0` gate** in `make precommit` (and therefore CI Quality).

## [0.4.8] - 2026-06-22

### Changed
- **Go toolchain pinned to 1.26.4.** `go.mod` now declares `go 1.25.5` with `toolchain go1.26.4`, and CI/release `setup-go` pins `1.26.4` (was the floating `1.26`). Default builds (`GOTOOLCHAIN=auto`) transparently use the patched 1.26.4 standard library while the module still builds on Go 1.25.x, keeping us inside Go's supported-major window and clearing the stdlib advisories that source-based vulnerability scans were flagging.
- **Dependencies updated:** `golang.org/x/crypto` v0.47.0 → v0.53.0, `golang.org/x/text` v0.33.0 → v0.38.0, `golang.org/x/sys` v0.40.0 → v0.46.0, `github.com/dlclark/regexp2` v1.11.5 → v1.12.0, and `github.com/jedisct1/go-minisign` refreshed to its latest commit. `govulncheck ./...` reports no vulnerabilities.
- **goneat pinned to v0.5.13** (was v0.5.10) across the `Makefile` and the CI dogfood install steps.
- **Release workflow migrated off archived Node12 actions.** `actions/create-release@v1` and `actions/upload-release-asset@v1` (both archived, Node12-era) are replaced with `softprops/action-gh-release@v2` (Node 20). Checkout and setup-go had already moved to Node 24-era majors in v0.4.7.

### Added
- **Pinned YAML formatting standard.** Added repo-root `.yamlfmt` and `.yamllint` so goneat's bundled yamlfmt and any standalone yamlfmt agree on inline-comment padding (two spaces) and document-start handling. Ends the intermittent `make precommit`/CI churn on workflow and config files. The config preserves sfetch's `---` + blank-line house style rather than collapsing it.

### Fixed
- Normalized `scripts/install-sfetch.sh` to 4-space indentation, matching the other `scripts/*.sh` and `.goneat/assess.yaml`'s shfmt `-i 4` setting. Whitespace-only; platform detection and argument handling verified unchanged.
- Re-applied go1.26 `gofmt` alignment to `internal/host/github/client.go`.

## [0.4.7] - 2026-04-20

### Removed
- **darwin/amd64 (Intel Mac) release artifacts.** sfetch no longer publishes `sfetch_darwin_amd64.tar.gz` starting with v0.4.7. Apple has retired Intel Mac support (macOS 15 is the last supporting release), and the sibling `homebrew-tap` already treats `darwin-amd64` as optional. Users on Intel Mac should pin `--tag v0.4.6` (the last supporting release) or upgrade to Apple Silicon. See [ADR-0002](docs/adr/adr-0002-drop-darwin-amd64.md) for the full rationale.

### Changed
- **`scripts/install-sfetch.sh`** exits early with an informative message when run on `darwin/amd64` without an explicit `--tag`, rather than proceeding to a 404 on the missing asset. The guard honors `--tag` so the documented recovery path (`--tag v0.4.6`) works with either the latest or pinned installer.
- **`sfetch --self-update`** on darwin/amd64 surfaces the same retirement guidance when the target release lacks the asset, instead of the generic asset-selection error.
- **Release matrix and `make build-all`** no longer produce darwin/amd64 binaries.
- **GitHub Actions pinned to Node 24 runners:** bumped `actions/checkout@v4` → `@v5` and `actions/setup-go@v5` → `@v6` across CI and release workflows, clearing the Node 20 deprecation warnings GitHub is emitting during the runner transition.

## [0.4.6] - 2026-04-20

### Fixed
- **Private GitHub repo asset downloads:** sfetch was always hitting `https://github.com/<o>/<r>/releases/download/...`, which returns 404 for private-repo assets even with a valid `Authorization: Bearer` header. When a token is available, sfetch now uses the GitHub API asset endpoint (`https://api.github.com/repos/<o>/<r>/releases/assets/<id>`) with `Accept: application/octet-stream`, follows the resulting 302 to the signed S3 URL, and writes the asset to disk.

### Added
- **`GH_TOKEN` recognized in token resolution chain.** Default precedence is now `SFETCH_GITHUB_TOKEN` → `GH_TOKEN` → `GITHUB_TOKEN`, so credentials populated by `gh auth login` are picked up automatically.
- **`--token-env <NAME>` flag.** Names a specific env var to read the token from when the default chain has the wrong-scoped credential. Hard-fails if the named var is unset/empty rather than silently falling back. Pairs naturally with `${{ secrets.PRIVATE_REPO_PAT }}` in CI.
- **Auth-failure error UX.** A 401/404 from an asset download now names the env-var source the token came from (never the value) and prescribes `--token-env` for the recovery path.
- **Cross-host token-stripping on redirects.** All sfetch GitHub HTTP requests install a `CheckRedirect` that drops `Authorization` when the next hop is not on a trusted host, even when Go's stdlib same-domain rule would have preserved it. Defense-in-depth for the `github.com` → S3 hop.

### Changed
- **`internal/model.Asset`** carries `URL` and `ID` from the GitHub release payload so the API asset endpoint is reachable. Backwards compatible — existing JSON without these fields still parses.
- **All release-asset download call sites** (main asset, sidecar checksums, sidecar signatures, key auto-detection) route through a single `downloadAsset(*Asset, path)` helper that picks the right endpoint based on auth availability.

## [0.4.5] - 2026-03-10

### Fixed
- **Windows ARM64 bootstrap detection:** `install-sfetch.sh` now prefers GitHub Actions `RUNNER_ARCH`, then native `powershell.exe`, before consulting Windows env vars or `uname -m`, fixing GitHub Actions Windows ARM64 runs where Git Bash and spawned processes still report `amd64`.

### Added
- **Windows ARM64 installer validation:** CI now runs the local `install-sfetch.sh` detection logic under Git Bash on the Windows ARM64 runner and asserts it resolves to `windows_arm64`.
- **Installer regression coverage:** Added a test case that mocks native PowerShell architecture output so the Windows ARM64 detection path is covered even when shell env vars lie.

## [0.4.4] - 2026-03-10

### Fixed
- **Windows ARM64 bootstrap detection:** `scripts/install-sfetch.sh` now prefers `PROCESSOR_ARCHITECTURE` / `PROCESSOR_ARCHITEW6432` on Windows before falling back to `uname -m`, fixing WoW64 cases where Git Bash reports `x86_64` on native ARM64 runners and downloads the wrong archive.

### Added
- **Installer regression coverage:** Added a table-driven Go test that mocks shell `uname` values and Windows architecture environment variables to lock in the Windows ARM64 installer path.

### Changed
- **Cross-platform build parity:** `make build-all` now includes `windows/arm64`, matching the release workflow matrix so local/precommit builds exercise the same artifact set that ships in releases.
- **goneat pin refreshed:** Bootstrap and CI now pin `fulmenhq/goneat` to `v0.5.7`.

## [0.4.3] - 2026-02-09

### Changed
- **CI goneat version:** Bumped goneat from v0.4.0/v0.5.2 to v0.5.3 across all CI jobs and Makefile bootstrap.
- **SHA512 manifest name:** Renamed `SHA2-512SUMS` to `SHA512SUMS` across release tooling (generate, sign, upload, download) to align with goreleaser/fulseed conventions. sfetch still recognizes `SHA2-512SUMS` from other projects for backward compatibility.
- **Signing script renamed:** `sign-release-assets.sh` → `sign-release-manifests.sh` (clarifies scope: signs manifests, not binaries).
- **Makefile target renames:** `verify-release-key` → `release-verify-key`, `verify-minisign-pubkey` → `release-verify-minisign-pubkey` (consistent `release-` prefix).

### Added
- **Unified release targets:** `release-export-keys` (exports both minisign + PGP keys), `release-verify-keys` (verifies both), `release-verify-signatures` (verifies minisign + PGP signatures on manifests).
- **Provenance upload:** `release-upload-provenance` uploads only manifests, signatures, keys, and notes (no binaries). CI handles binary uploads.
- **Signature verification script:** `scripts/verify-signatures.sh` verifies minisign and PGP signatures on checksum manifests.

### Fixed
- **Windows .zip extraction failure:** Legacy `archiveType: "tar.gz"` in default config overrode the correctly-inferred `.zip` archive format, routing Windows `.zip` assets through the `tar` extraction codepath. The legacy compatibility guard now preserves formats already inferred from file extensions.
- **Upload script signature handling:** `upload-release-assets.sh` now filters non-existent files from the signature list instead of passing literal paths that bypass `nullglob`. Fails with a clear "Did you run `make release-sign`?" message when no signatures are found.

## [0.4.2] - 2026-02-09

### Fixed
- **Pattern regex false positive on Windows:** `matchWithPatterns` regex aliases (e.g. "win") matched as substrings inside unrelated tokens ("darwin"), causing Windows/arm64 to select darwin assets. Pattern matches are now validated with boundary-aware OS token checking before acceptance.
- **Boundary-aware token matching:** `containsTokenCI` and `containsAny` now enforce word boundaries so "win" cannot match inside "darwin" during heuristic asset selection.
- **Windows archive install name:** `installName` now inherits the `.exe` extension from the resolved binary inside archives, fixing paths like `bin\goneat` → `bin\goneat.exe`.
- **Windows archive binary resolution:** Added fallback binary resolution for extracted archives on Windows so `binaryName` can resolve to `binaryName.exe` when the archive contains `.exe` artifacts.
- **Cross-device rename fallback:** `installFile` falls back to copy+remove when `os.Rename` fails across filesystem boundaries (common on Windows CI runners with temp dirs on different drives).

### Added
- **Windows dogfood CI coverage:** Added CI jobs that validate `sfetch` can install `goneat` on:
  - `windows-latest` (x64)
  - `windows-latest-arm64-s` (custom arm64 runner)
- **Actionlint custom runner config:** Added `actionlint.yaml` to allow the custom self-hosted runner label.

## [0.4.1] - 2026-02-04

### Changed
- **Go runtime:** Upgraded from Go 1.23.4 to Go 1.24.0 (automatic with dependency updates).
- **Dependencies updated:**
  - `golang.org/x/crypto`: v0.31.0 → v0.47.0 (security-critical, +16 minor versions)
  - `golang.org/x/sys`: v0.28.0 → v0.40.0 (+12 minor versions)
  - `golang.org/x/text`: v0.21.0 → v0.33.0 (+12 minor versions)
  - `github.com/dlclark/regexp2`: v1.11.0 → v1.11.5

### Fixed
- **install-sfetch.sh:** Corrected indentation from spaces to tabs for consistency with shell formatting standards.

### Documentation
- **CI/CD guide:** Clarified `GITHUB_TOKEN` usage for high-volume CI and GitHub-hosted runners to avoid 403 rate limits.
- **Threat model:** Updated to reflect `SFETCH_GITHUB_TOKEN` and `GH_TOKEN` as alternative authentication environment variables.
- **Makefile:** Updated `GONEAT_VERSION` to v0.5.1.

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
- Updated docs and README to improve awareness of v0.4.0 features including Smart URL routing, security defaults, and sfetch + shellsentry workflow.

### Security
- Block URL credentials by default to avoid leaking user info during redirects.

---

> **Maintenance note:** This file is pruned to the latest 10 releases. For older entries, see `docs/releases/`.

[Unreleased]: https://github.com/3leaps/sfetch/compare/v0.4.10...HEAD
[0.4.10]: https://github.com/3leaps/sfetch/compare/v0.4.9...v0.4.10
[0.4.9]: https://github.com/3leaps/sfetch/compare/v0.4.8...v0.4.9
[0.4.8]: https://github.com/3leaps/sfetch/compare/v0.4.7...v0.4.8
[0.4.7]: https://github.com/3leaps/sfetch/compare/v0.4.6...v0.4.7
[0.4.6]: https://github.com/3leaps/sfetch/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/3leaps/sfetch/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/3leaps/sfetch/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/3leaps/sfetch/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/3leaps/sfetch/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/3leaps/sfetch/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/3leaps/sfetch/compare/v0.3.4...v0.4.0
