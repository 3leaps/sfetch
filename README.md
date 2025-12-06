# sfetch

Secure, verifiable, zero-trust downloader for the uncertain world

### The one-liner
**sfetch is the `curl | sh` you can actually trust in 2026.**

A tiny (~3 MB), statically-linked Go binary that downloads release artifacts from GitHub (or any URL) and **refuses to install them unless both checksum and ed25519 signature verify**.

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

- Use `--minisign-key <pubkey.pub>` for minisign signatures (`.minisig`) - recommended, pure-Go verification.
- Use `--key <64-hex-bytes>` for raw ed25519 signatures (`.sig`).
- Use `--pgp-key-file <key.asc>` for PGP signatures (`.asc`) - requires `gpg`.
- See [docs/key-handling.md](docs/key-handling.md) for supported formats and verification details.
- Run `sfetch -helpextended` for concrete examples.

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
# Download assets (curl)
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh -o install-sfetch.sh
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/SHA256SUMS -o SHA256SUMS

# Download assets (wget)
wget -q https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh
wget -q https://github.com/3leaps/sfetch/releases/latest/download/SHA256SUMS

# Option A: Verify with minisign (recommended)
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/SHA256SUMS.minisig -o SHA256SUMS.minisig
minisign -Vm SHA256SUMS -P RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC
grep install-sfetch.sh SHA256SUMS | sha256sum -c

# Option B: Verify with GPG
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/SHA256SUMS.asc -o SHA256SUMS.asc
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/sfetch-release-signing-key.asc -o sfetch-release-signing-key.asc
gpg --import sfetch-release-signing-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
grep install-sfetch.sh SHA256SUMS | sha256sum -c

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

```bash
# Install the latest goneat (or any signed tool) in one line
sfetch --repo fulmenhq/goneat --latest --output /usr/local/bin/goneat --pgp-key-file fulmen-release.asc

# Or pin exactly
sfetch --repo fulmenhq/goneat --tag v2025.12.3 --output /usr/local/bin/goneat --pgp-key-file fulmen-release.asc
