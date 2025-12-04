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
See [docs/security.md](docs/security.md) for scanning, exclusions, processes.

### Signature verification

- Use `--key <64-hex-bytes>` for raw `.sig`/`.minisig` ed25519 signatures.
- Use `--pgp-key-file fulmen-release.asc` (and optional `--gpg-bin`) for ASCII-armored `.asc` signatures.
- See `docs/key-handling.md` for exporting keys, testing them safely, and wiring CI.

```bash
# Install the latest goneat (or any signed tool) in one line
sfetch --repo fulmenhq/goneat --latest --output /usr/local/bin/goneat --pgp-key-file fulmen-release.asc

# Or pin exactly
sfetch --repo fulmenhq/goneat --tag v2025.12.3 --output /usr/local/bin/goneat --pgp-key-file fulmen-release.asc
