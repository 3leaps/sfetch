## v0.4.2

### Summary
Windows reliability release focused on archive install compatibility and CI coverage.

### Highlights

**Windows install fix**
- Added fallback archive binary resolution on Windows so archive installs can resolve `binaryName.exe` when `binaryName` is requested.
- Fixes Windows bootstrap/dogfood failures seen when installing `fulmenhq/goneat` via `sfetch`.

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
