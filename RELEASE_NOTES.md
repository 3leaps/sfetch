## v0.4.6

### Summary
Private-repo release assets now download successfully when the user has visibility — no more silent 404s. Token resolution learns `GH_TOKEN` and gains `--token-env <NAME>` for the wrong-scope-PAT case.

### Highlights

**Private-repo asset download fix**
- The browser download URL (`https://github.com/<o>/<r>/releases/download/...`) returns 404 for private-repo assets even with a valid Bearer token. sfetch now uses the GitHub API asset endpoint (`/repos/<o>/<r>/releases/assets/<id>`) with `Accept: application/octet-stream`, which 302s to a short-lived signed URL and lets the download succeed.

**Token resolution improvements**
- New precedence: `SFETCH_GITHUB_TOKEN` → `GH_TOKEN` → `GITHUB_TOKEN`. `GH_TOKEN` is what `gh auth login` populates by default — it now works out of the box.
- `--token-env <NAME>` reads a token from a named env var. Useful when your ambient `GITHUB_TOKEN` cannot see a sibling org's private repo and you have a separately-scoped PAT loaded under a different name. Hard-fails if the named var is empty rather than silently falling back.
- sfetch deliberately does NOT accept `--token <value>` — that pattern leaks into `~/.bash_history`, `ps`, and `set -x` CI logs.

**Defense-in-depth on redirects**
- A custom `CheckRedirect` strips the `Authorization` header on every redirect hop whose target is not a trusted GitHub host, even when Go's stdlib same-domain rule would have preserved it.

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

Or self-update:
```bash
sfetch --self-update --yes
```

### Details
- See `CHANGELOG.md` for the complete list.
- See `docs/security.md#github-authentication-v046` for the full token model.

---

## v0.4.5

### Summary
Windows ARM64 bootstrap follow-up release: fix GitHub Actions Git Bash detection by querying native PowerShell, and validate the installer path on the ARM64 runner itself.

### Highlights

**Bootstrap detection fix**
- `install-sfetch.sh` now prefers GitHub Actions `RUNNER_ARCH`, then asks native `powershell.exe` for the host OS architecture on Windows before falling back to environment variables or `uname -m`.
- This addresses GitHub Actions Windows ARM64 jobs where Git Bash and spawned processes still reported `windows_amd64`.

**Actual runner validation**
- CI now executes the local `install-sfetch.sh` detection logic under Git Bash on the Windows ARM64 runner and asserts that it resolves to `windows_arm64`.
- Added regression coverage that mocks PowerShell architecture output in the installer test suite.

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

Or self-update:
```bash
sfetch --self-update --yes
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.4.4

### Summary
Windows ARM64 bootstrap reliability release for the `install-sfetch.sh` path, with matching local build coverage.

### Highlights

**Bootstrap installer fix**
- Fixed `install-sfetch.sh` platform detection on Windows ARM64 hosts running Git Bash or similar WoW64 shells. The installer now checks `PROCESSOR_ARCHITECTURE` and `PROCESSOR_ARCHITEW6432` before `uname -m`, so it downloads `sfetch_windows_arm64.zip` instead of the x64 archive when the host is actually ARM64.
- This addresses flaky downstream CI installs where `uname -m` reported `x86_64` even though the runner was native Windows ARM64.

**Regression coverage**
- Added a focused installer test that mocks `uname` and Windows architecture environment variables, covering both native and WoW64-style ARM64 detection paths.

**Build matrix parity**
- Updated `make build-all` to include `windows/arm64`, bringing local and precommit artifact builds in line with the release workflow matrix.

**Toolchain refresh**
- Updated the active `goneat` pin in bootstrap and CI flows to `v0.5.7`.

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

Or self-update:
```bash
sfetch --self-update --yes
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.4.3

### Summary
Windows .zip extraction fix and release DX alignment with fulseed conventions.

### Highlights

**Bug fix**
- Fixed Windows `.zip` extraction failure where the default `archiveType: "tar.gz"` config overrode the correctly-inferred `.zip` format, causing sfetch to extract Windows `.zip` assets with `tar` instead of Go's `archive/zip`. This was the root cause of kitfly CI failures installing goneat on Windows.

**Release DX improvements**
- Renamed `SHA2-512SUMS` to `SHA512SUMS` across release tooling (aligned with goreleaser/fulseed conventions)
- Added unified targets: `release-export-keys`, `release-verify-keys`, `release-verify-signatures`
- Added `release-upload-provenance` for uploading only manifests, signatures, and keys (no binaries)
- Renamed `verify-release-key` → `release-verify-key`, `verify-minisign-pubkey` → `release-verify-minisign-pubkey`
- Renamed `sign-release-assets.sh` → `sign-release-manifests.sh`
- Fixed `upload-release-assets.sh` to filter non-existent signature files with clear error message
- Added `scripts/verify-signatures.sh` for post-sign verification
- Bumped goneat to v0.5.3 across all CI jobs

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

Or self-update:
```bash
sfetch --self-update --yes
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.4.2

### Summary
Windows reliability release focused on cross-platform asset selection, archive install compatibility, and CI coverage.

### Highlights

**Asset selection fixes**
- Fixed pattern-based regex matching where OS alias "win" matched as a substring inside "darwin", causing Windows/arm64 to incorrectly select darwin assets. Pattern matches are now validated with boundary-aware token checking before acceptance.
- Fixed boundary-aware token matching (`containsTokenCI`) to prevent "win" from matching inside "darwin" and similar false positives in heuristic selection.

**Windows install fix**
- Added fallback archive binary resolution on Windows so archive installs can resolve `binaryName.exe` when `binaryName` is requested.
- Fixed missing `.exe` extension on `installName` when extracting Windows archives — the resolved binary had `.exe` but the install path did not.
- Fixed cross-device rename failures during install by falling back to copy+remove when `os.Rename` fails across filesystem boundaries.

**CI hardening**
- Added Windows dogfood CI jobs to validate `sfetch -> goneat` installs on:
  - `windows-latest` (x64)
  - `windows-latest-arm64-s` (custom arm64 runner)
- Added `actionlint.yaml` to explicitly allow the custom runner label.

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

Or self-update:
```bash
sfetch --self-update --yes
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.4.1

### Summary
Maintenance release: Go dependency updates (security-critical `golang.org/x/crypto`), bug fixes, and documentation improvements.

### Highlights

**Dependency updates**
- Go runtime: 1.23.4 → 1.24.0
- `golang.org/x/crypto`: v0.31.0 → v0.47.0 (security-critical, +16 minor versions)
- `golang.org/x/sys`, `x/text`: Updated to latest stable versions
- All tests pass; no breaking changes

**Bug fixes**
- Fixed shell script indentation in `install-sfetch.sh` for consistency

**Documentation improvements**
- Clarified GitHub token usage for CI/CD rate limit avoidance
- Updated threat model with alternative token environment variables

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

Or self-update:
```bash
sfetch --self-update --yes
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.4.0

### Summary
URL acquisition upgrades: fetch arbitrary URLs safely, support raw GitHub content, and auto-upgrade GitHub release URLs for stronger verification.

### Highlights

**Arbitrary URL fetch**
- `--url` (or positional URL) for generic HTTPS downloads
- `--allow-http` to opt into HTTP
- Redirects blocked by default; enable with `--follow-redirects` and `--max-redirects`
- Content-type allowlist via `--allowed-content-types` or `--allow-unknown-content-type`

**GitHub smart routing**
- `raw.githubusercontent.com` URLs automatically use `--github-raw`
- GitHub release asset URLs upgrade to `--repo` + `--tag` + `--asset-match` with higher trust

**Provenance and safety**
- Redirect chains captured in provenance output
- URL credentials are rejected to prevent leakage

**Corpus updates**
- Expanded URL and format coverage with explicit HTTP allowlist cases

**Documentation**
- Updated docs and README to improve awareness of v0.4.0 features including Smart URL routing, security defaults, and sfetch + shellsentry workflow

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

Or self-update:
```bash
sfetch --self-update --yes
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.3.4

### Summary
Proxy support for HTTP(S) downloads with CLI flags and env overrides.

### Highlights

**Proxy support**
- Environment variables: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (case-insensitive)
- CLI flags override env: `--http-proxy`, `--https-proxy`, `--no-proxy`
- `NO_PROXY` bypass for host/domain matches
- All network fetches (releases, keys, checksums) honor proxy settings

**Validation coverage**
- Added tests for proxy URL validation and env override behavior

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

Or self-update:
```bash
sfetch --self-update --yes
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.3.3

### Summary
Local agent role catalog and operating model guidance for supervised sessions.

### Highlights
- Added `docs/agent-roles.md` for offline role guidance
- Clarified default role and operating model in `AGENTS.md`

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

Or self-update:
```bash
sfetch --self-update --yes
```

### Details
- See `CHANGELOG.md` for the complete list.
