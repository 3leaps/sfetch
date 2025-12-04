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

```bash
# Install the latest goneat (or any signed tool) in one line
sfetch --repo fulmenhq/goneat --latest --output /usr/local/bin/goneat

# Or pin exactly
sfetch --repo fulmenhq/goneat --tag v2025.12.3 --output /usr/local/bin/goneat