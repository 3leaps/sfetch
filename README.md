# sfetch

Secure, verifiable, zero-trust downloader for the uncertain world

### The one-liner
**sfetch is the `curl | sh` you can actually trust in 2026.**

A tiny (~3 MB), statically-linked Go binary that downloads release artifacts from GitHub and **verifies signatures and checksums automatically** - using minisign, PGP, or raw ed25519.

No runtime dependencies. No package manager required. Works in CI, Docker, and air-gapped environments.

### Why sfetch exists
Every modern engineering org signs their releases now.  
Yet we still ship 15-line bash bootstrap scripts that do manual `curl → sha256sum → maybe cosign verify`.

`sfetch` is the missing 1% that deletes those scripts forever.

### Security & Verification
See [docs/security.md](docs/security.md).

### Asset Discovery
Auto-selects via heuristics ([docs/pattern-matching.md](docs/pattern-matching.md)).

### Signature verification

**Minisign (recommended)** - pure-Go, no external dependencies
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

**Dry-run mode** - see what verification is available before downloading:
```bash
sfetch --repo BurntSushi/ripgrep --latest --dry-run
```

**Provenance records** - structured JSON for audit trails and CI:
```bash
sfetch --repo 3leaps/sfetch --latest --dest-dir /tmp --provenance-file audit.json
```

See [docs/examples.md](docs/examples.md) for comprehensive real-world examples.

### Build, versioning & install

We use CalVer in `vYYYY.MM.DD` format (e.g., `v2025.12.05`). If multiple releases ship on the same day we append a revision (`v2025.12.05.1`, `v2025.12.05.2`, ...). See `CHANGELOG.md`, `RELEASE_NOTES.md`, and `docs/releases/` for per-release detail.

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
curl -sSfL .../install-sfetch.sh | bash -s -- --tag v2025.12.06

# Dry run (download and verify, don't install)
curl -sSfL .../install-sfetch.sh | bash -s -- --dry-run

# Skip confirmation prompt
curl -sSfL .../install-sfetch.sh | bash -s -- --yes
```

The installer:
- Detects platform (linux/darwin/windows, amd64/arm64)
- Verifies signatures using embedded minisign public key (trust anchor)
- Falls back to GPG if minisign unavailable, warns if neither present

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

CI uploads unsigned archives. Maintainers sign `SHA256SUMS` locally with minisign (primary) and optionally PGP:

```bash
export MINISIGN_KEY=/path/to/sfetch.key
export PGP_KEY_ID=security@fulmenhq.dev  # optional

RELEASE_TAG=v2025.12.06 make release-download
RELEASE_TAG=v2025.12.06 make release-sign
make release-export-minisign-key
make release-export-key                   # if using PGP
RELEASE_TAG=v2025.12.06 make release-notes
RELEASE_TAG=v2025.12.06 make release-upload
```

Set `RELEASE_TAG` to the tag you're publishing. The scripts in `scripts/` can be used individually if you prefer manual control.

### Quick examples

```bash
# Download with auto-detected verification (minisign or PGP key from release assets)
sfetch --repo 3leaps/sfetch --latest --dest-dir ~/.local/bin

# Dry-run to assess what verification is available
sfetch --repo BurntSushi/ripgrep --latest --dry-run

# Explicit minisign key
sfetch --repo jedisct1/minisign --latest --minisign-key /path/to/key.pub --dest-dir /usr/local/bin

# PGP verification
sfetch --repo fulmenhq/goneat --latest --pgp-key-file fulmen-release.asc --dest-dir /usr/local/bin

# Pin to specific version
sfetch --repo fulmenhq/goneat --tag v0.3.14 --dest-dir /usr/local/bin
