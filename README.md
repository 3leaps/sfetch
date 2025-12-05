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

- Use `--key <64-hex-bytes>` for raw `.sig`/`.minisig` ed25519 signatures.
- Use `--pgp-key-file fulmen-release.asc`, `--pgp-key-url https://example/key.asc`, or `--pgp-key-asset fulmen-release.asc` (plus optional `--gpg-bin`) for ASCII-armored `.asc` signatures. `--pgp-key-file` takes precedence and also supports http(s) URLs; next comes `--pgp-key-url`, then `--pgp-key-asset`, and finally auto-detect of `.asc` assets containing keywords like "key"/"release".
- See `docs/key-handling.md` for exporting keys, testing them safely, and wiring CI.
- Need concrete flag combos? Run `sfetch -helpextended` to print the embedded quickstart.

### Build, versioning & install

We use CalVer in `vYYYY.MM.DD` format (e.g., `v2025.12.05`). If multiple releases ship on the same day we append a revision (`v2025.12.05.1`, `v2025.12.05.2`, ...). See `CHANGELOG.md`, `RELEASE_NOTES.md`, and `docs/releases/` for per-release detail.

```bash
make build             # produces bin/sfetch_${GOOS}_${GOARCH}
make install           # installs to ~/.local/bin by default
INSTALL_BINDIR=~/bin make install  # override install location
```

- Edit `buildconfig.mk` to change the canonical binary name (`NAME`) or default install destination once.
- On Windows, `make install` targets `%USERPROFILE%\bin`; ensure that directory is present in `PATH`.

### Manual signing workflow

CI uploads unsigned archives built remotely (the local scripts never rebuild/clobber those artifacts). Maintainers sign and re-upload with:

```bash
RELEASE_TAG=v2025.12.05 make release-download        # needs GitHub CLI (gh)
PGP_KEY_ID=security@fulmenhq.dev RELEASE_TAG=v2025.12.05 make release-sign  # regenerates SHA256SUMS first
RELEASE_TAG=v2025.12.05 make release-export-key  # exports the matching public key into dist/release
make verify-release-key
RELEASE_TAG=v2025.12.05 make release-notes           # copies RELEASE_NOTES.md
RELEASE_TAG=v2025.12.05 make release-upload          # gh release upload --clobber
```

Set `RELEASE_TAG` to the tag you're publishing. The scripts in `scripts/` can be used individually if you prefer manual control.

```bash
# Install the latest goneat (or any signed tool) in one line
sfetch --repo fulmenhq/goneat --latest --output /usr/local/bin/goneat --pgp-key-file fulmen-release.asc

# Or pin exactly
sfetch --repo fulmenhq/goneat --tag v2025.12.3 --output /usr/local/bin/goneat --pgp-key-file fulmen-release.asc
