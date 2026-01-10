# sfetch

Secure, verifiable, zero-trust downloader for the uncertain world

### The one-liner
**sfetch is the `curl | sh` you can actually trust in 2026.**

A tiny (~3 MB), statically-linked Go binary that downloads release artifacts from GitHub and **verifies signatures and checksums automatically** - using minisign, PGP, or raw ed25519.

No runtime dependencies. No package manager required. Works in CI, Docker, and air-gapped environments. See [CI/CD Usage Guide](docs/cicd-usage-guide.md) for container and pipeline examples.

### Why sfetch exists
Every modern engineering org signs their releases now.  
Yet we still ship 15-line bash bootstrap scripts that do manual `curl → sha256sum → maybe cosign verify`.

`sfetch` is the missing 1% that deletes those scripts forever.

### Pair with shellsentry

[shellsentry](https://github.com/3leaps/shellsentry) analyzes shell scripts for risky patterns before you run them. Use sfetch to verify downloads, then shellsentry to inspect what's inside:

```bash
# Install both tools
sfetch --repo 3leaps/sfetch --latest --dest-dir ~/.local/bin
sfetch --repo 3leaps/shellsentry --latest --dest-dir ~/.local/bin

# The new curl | sh - verified download, inspected before execution
curl -sSfL https://example.com/install.sh -o install.sh
shellsentry install.sh && bash install.sh
```

Or as a one-liner that downloads, analyzes, and runs only if safe:

```bash
# Download, analyze, execute only if no high-risk patterns found
curl -sSfL https://example.com/install.sh -o install.sh && shellsentry --exit-on-danger install.sh && bash install.sh
```

### Security & Verification
See [docs/security.md](docs/security.md).

### Asset Discovery
Auto-selects via heuristics ([docs/pattern-matching.md](docs/pattern-matching.md)) and classifies assets (archives vs raw scripts/binaries vs package-like). Raw files skip extraction; scripts/binaries are chmod'd on macOS/Linux. Use `--asset-match` for glob/substring selection or `--asset-regex` for advanced regex.

### Raw GitHub content
Use `--github-raw owner/repo@ref:path` to fetch raw files from GitHub repositories (e.g., install scripts).

```bash
sfetch --github-raw Homebrew/install@HEAD:install.sh --dest-dir /tmp
```

### Arbitrary URLs
Fetch arbitrary URLs with `--url` or a positional URL. HTTPS is enforced by default; redirects are blocked unless explicitly enabled. Raw GitHub URLs are routed through the GitHub raw flow, and GitHub release asset URLs are upgraded to the release verification path.

```bash
sfetch --url https://get.docker.com --output ./get-docker.sh
```

URL safety flags:
- `--allow-http` to allow `http://` URLs (unsafe)
- `--follow-redirects` with `--max-redirects` (default 5)
- `--allowed-content-types` to restrict MIME types
- `--allow-unknown-content-type` to bypass content type checks
- `--dry-run` and provenance output include redirect details

### Install permissions
- **Archives** (`.tar.gz`, `.zip`, etc.): Permissions from the archive are preserved. Executables packaged with `0755` remain executable after extraction.
- **Raw scripts/binaries** (e.g., `install.sh`, `kubectl`): Automatically set to `0755` on macOS/Linux to ensure executability.
- **Cross-device installs**: When `--dest-dir` is on a different filesystem than the temp directory (common in containers), sfetch falls back to copy and preserves the source permissions.

### Proxy support
sfetch honors standard proxy environment variables and provides CLI flags for explicit control.

**Environment variables** (case-insensitive, zero-config):
- `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`

**CLI flags** (override env when present):
- `--http-proxy <url>`, `--https-proxy <url>`, `--no-proxy <csv>`

```bash
# Via environment (common in CI/enterprise)
export HTTPS_PROXY=http://proxy.corp.example:8080
sfetch --repo 3leaps/sfetch --latest --dest-dir ~/.local/bin

# Via flags (explicit override)
sfetch --repo 3leaps/sfetch --latest --https-proxy http://localhost:8888 --dest-dir /tmp
```

### Signature verification

**Minisign** - pure-Go, no external dependencies
- `--minisign-key <pubkey.pub>` - path to public key file
- `--minisign-key-url <url>` - download key from URL
- `--minisign-key-asset <name>` - fetch key from release assets
- `--require-minisign` - fail if minisign verification unavailable
- Auto-detects `*.pub` files from release assets when no key flags provided

**PGP** - requires `gpg` binary
- `--pgp-key-file <key.asc>` - path to ASCII-armored public key
- `--pgp-key-url <url>` - download key from URL
- `--pgp-key-asset <name>` - fetch key from release assets
- Auto-detects `*-signing-key.asc` or `*-release*.asc` from release assets

**Raw ed25519** - pure-Go (uncommon format)
- `--key <64-hex-bytes>` for `.sig` or `.sig.ed25519` files

See [docs/key-handling.md](docs/key-handling.md) for details. Run `sfetch -helpextended` for examples.

### Verification assessment

sfetch computes a **trust score** (0–100) from the verification plan/results, and can optionally gate installs with `--trust-minimum`.

Design guide: `docs/trust-rating-system.md`.

**Dry-run mode** - see what verification is available before downloading:
```bash
sfetch --repo BurntSushi/ripgrep --latest --dry-run
```

**Enforce a minimum trust score** (useful in CI):
```bash
# Require at least medium trust
sfetch --repo 3leaps/sfetch --latest --trust-minimum 60 --dest-dir /tmp
```

**Provenance records** - structured JSON for audit trails and CI:
```bash
sfetch --repo 3leaps/sfetch --latest --dest-dir /tmp --provenance-file audit.json
```

**Verify installed binary** - print instructions to verify your sfetch installation:
```bash
sfetch --self-verify
```

**Self-update** - update sfetch to the latest verified release:
```bash
# Update if newer version is available (skips reinstall if already current)
sfetch --self-update --yes

# Force reinstall even if already at the target version
sfetch --self-update --self-update-force --yes

# Pin to a specific version (allows downgrades)
sfetch --self-update --tag v0.2.3 --yes
```

For machine-readable trust anchors:
```bash
sfetch --show-trust-anchors        # plain: minisign:<key>
sfetch --show-trust-anchors --json # JSON with pubkey and keyId
```

See [docs/examples.md](docs/examples.md) for comprehensive real-world examples.

### Build, versioning & install

sfetch uses [Semantic Versioning](https://semver.org/). See [ADR-0001](docs/adr/adr-0001-semver-versioning.md) for versioning history.

```bash
make build             # produces bin/sfetch_${GOOS}_${GOARCH}
make install           # installs to ~/.local/bin by default
INSTALL_BINDIR=~/bin make install  # override install location
```

- Edit `buildconfig.mk` to change the canonical binary name (`NAME`) or default install destination once.
- On Windows, `make install` targets `%USERPROFILE%\bin`; ensure that directory is present in `PATH`.

### Bootstrap install

```bash
# Using curl
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash

# Using wget
wget -qO- https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

#### Installer options

Pass arguments using `bash -s --`:

```bash
# Install to custom directory
curl -sSfL .../install-sfetch.sh | bash -s -- --dir ~/bin

# Install specific version
curl -sSfL .../install-sfetch.sh | bash -s -- --tag v0.2.0

# Dry run (download and verify, don't install)
curl -sSfL .../install-sfetch.sh | bash -s -- --dry-run

# Skip confirmation prompt
curl -sSfL .../install-sfetch.sh | bash -s -- --yes

# Allow checksum-only (NOT recommended; skips signature verification)
curl -sSfL .../install-sfetch.sh | bash -s -- --allow-checksum-only
```

The installer:
- Detects platform (linux/darwin/windows, amd64/arm64)
- Requires minisign verification by default using the embedded trust anchor
- Optional GPG fallback with pinned fingerprint; checksum-only requires explicit `--allow-checksum-only`

#### Verify before piping to bash

For users who prefer to verify the installer before execution:

```bash
# Detect OS-appropriate SHA256 command (macOS uses shasum, Linux uses sha256sum)
if command -v sha256sum &>/dev/null; then
  SHA_CMD="sha256sum"
else
  SHA_CMD="shasum -a 256"
fi

# Download assets (curl)
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh -o install-sfetch.sh
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/SHA256SUMS -o SHA256SUMS

# Download assets (wget alternative - use -O to overwrite existing files)
# wget -qO install-sfetch.sh https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh
# wget -qO SHA256SUMS https://github.com/3leaps/sfetch/releases/latest/download/SHA256SUMS

# Option A: Verify with minisign (recommended)
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/SHA256SUMS.minisig -o SHA256SUMS.minisig
minisign -Vm SHA256SUMS -P RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC
$SHA_CMD -c SHA256SUMS --ignore-missing

# Option B: Verify with GPG (uses temp keyring)
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/SHA256SUMS.asc -o SHA256SUMS.asc
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/sfetch-release-signing-key.asc -o sfetch-release-signing-key.asc
GPG_TMPDIR=$(mktemp -d)
gpg --homedir "$GPG_TMPDIR" --import sfetch-release-signing-key.asc
gpg --homedir "$GPG_TMPDIR" --verify SHA256SUMS.asc SHA256SUMS
rm -rf "$GPG_TMPDIR"
$SHA_CMD -c SHA256SUMS --ignore-missing

# Run after verification
bash install-sfetch.sh
```

### Manual signing workflow

CI uploads unsigned archives. Maintainers generate `SHA256SUMS` and `SHA2-512SUMS` locally, then sign them with minisign (primary) and optionally PGP:

```bash
export MINISIGN_KEY=/path/to/sfetch.key
export PGP_KEY_ID=security@fulmenhq.dev  # optional

RELEASE_TAG=v0.2.0 make release-download
RELEASE_TAG=v0.2.0 make release-checksums
RELEASE_TAG=v0.2.0 make release-sign
make release-export-minisign-key
make release-export-key                   # if using PGP
RELEASE_TAG=v0.2.0 make release-notes
RELEASE_TAG=v0.2.0 make release-upload
```

Set `RELEASE_TAG` to the tag you're publishing. The scripts in `scripts/` can be used individually if you prefer manual control.

### Quick examples

```bash
# Download with auto-detected verification (minisign or PGP key from release assets)
sfetch --repo 3leaps/sfetch --latest --dest-dir ~/.local/bin

# Download installer script (no extraction, auto-chmod)
sfetch --repo 3leaps/sfetch --latest --asset-match "install-sfetch.sh" --dest-dir /tmp

# Standalone binary with explicit override for ambiguous extensions
sfetch --repo owner/tool --latest --asset-type raw --dest-dir /usr/local/bin

# Match by glob/substring instead of regex
sfetch --repo jedisct1/minisign --latest --asset-match "*macos*.zip" --dest-dir /usr/local/bin

# Advanced: regex match remains available
sfetch --repo jedisct1/minisign --latest --asset-regex "minisign-.*-macos.zip$" --dest-dir /usr/local/bin

# Dry-run to assess what verification is available
sfetch --repo BurntSushi/ripgrep --latest --dry-run

# Explicit minisign key
sfetch --repo jedisct1/minisign --latest --minisign-key /path/to/key.pub --dest-dir /usr/local/bin

# PGP verification
sfetch --repo fulmenhq/goneat --latest --pgp-key-file fulmen-release.asc --dest-dir /usr/local/bin

# Pin to specific version
sfetch --repo fulmenhq/goneat --tag v0.3.14 --dest-dir /usr/local/bin
```
