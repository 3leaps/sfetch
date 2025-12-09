---
title: "sfetch Examples & Pattern Matching"
description: "Real-world examples and transparent documentation of how sfetch selects assets and verifies signatures"
author_of_record: Dave Thompson (@3leapsdave)
status: draft
last_updated: 2025-12-08
---

# sfetch Examples & Pattern Matching

This document provides transparency into how sfetch works. As the tagline says: **the `curl | sh` you can actually trust** - and trust requires understanding.

---

## Quick Reference

| Signature Format | Workflow | Example Repo | Status | Jump To |
|------------------|----------|--------------|--------|---------|
| **Minisign** | A (checksum-level) | `3leaps/sfetch` | Supported | [Example](#minisign-workflow-a-3leapssfetch) |
| **Minisign** | B (per-asset) | `jedisct1/minisign` | Supported | [Example](#minisign-workflow-b-jedisct1minisign) |
| **GPG/PGP** | A (checksum-level) | `kubernetes/kubectl` | Supported | [Example](#gpg-workflow-a-checksum-level) |
| **GPG/PGP** | B (per-asset) | goreleaser default | Supported | [Example](#gpg-workflow-b-per-asset) |
| **Raw ed25519** | B (per-asset) | custom | Supported | [Example](#raw-ed25519) |
| **Cosign/Sigstore** | - | `sigstore/cosign` | Planned | [Roadmap](#cosignsigstore-planned) |

**Workflow Legend:**
- **A (checksum-level):** Signature over `SHA256SUMS` file, assets verified via checksums
- **B (per-asset):** Signature directly over each asset file

---

## Decision Flow

```
                    ┌─────────────────────┐
                    │   Fetch Release     │
                    │   from GitHub API   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Select Asset      │
                    │   (heuristics or    │
                    │   --asset-regex)    │
                    └──────────┬──────────┘
                               │
              ┌────────────────▼────────────────┐
              │  Is there a checksum-level sig? │
              │  (SHA256SUMS.minisig or .asc)   │
              └────────────────┬────────────────┘
                      ┌────────┴────────┐
                      │                 │
                     YES               NO
                      │                 │
           ┌──────────▼──────────┐    ┌─▼─────────────────────┐
           │    WORKFLOW A       │    │      WORKFLOW B       │
           │  Checksum-level sig │    │   Per-asset signature │
           └──────────┬──────────┘    └───────────┬───────────┘
                      │                           │
           ┌──────────▼──────────┐    ┌───────────▼───────────┐
           │ 1. Verify sig over  │    │ 1. Find per-asset sig │
           │    SHA256SUMS       │    │    (.minisig/.sig)    │
           │ 2. Verify asset     │    │ 2. Verify signature   │
           │    hash vs SUMS     │    │ 3. Checksum optional* │
           └──────────┬──────────┘    └───────────┬───────────┘
                      │                           │
                      └───────────┬───────────────┘
                                  │
                       ┌──────────▼──────────┐
                       │   Extract & Install │
                       └─────────────────────┘

* Checksum is optional for minisign (signature provides integrity).
  Required for PGP/ed25519 per-asset signatures.
```

---

## Inference Rules

sfetch uses inference to minimize configuration:

| Property | Inference Rule | Override Flag |
|----------|----------------|---------------|
| **BinaryName** | Second part of `owner/repo` (e.g., `jedisct1/minisign` → `minisign`) | `--binary-name` |
| **ArchiveType** | From asset extension (`.zip` → zip, `.tar.gz` → tar.gz) | *automatic* |
| **Signature Format** | From sig file extension/content | *automatic* |
| **Checksum File** | Pattern matching (`SHA256SUMS`, `{{asset}}.sha256`) | *automatic* |

---

# Minisign

**Recommended format.** Pure-Go verification, no external dependencies. Supports trusted comments (signed metadata).

## Signature Detection

sfetch detects minisign by:
1. File extension: `.minisig`
2. Content prefix: `untrusted comment:`

## Minisign Workflow A: `3leaps/sfetch`

Checksum-level signing - signature over `SHA256SUMS`.

**Release structure:**
```
sfetch_v2025.12.06_darwin_arm64.tar.gz
sfetch_v2025.12.06_darwin_amd64.tar.gz
sfetch_v2025.12.06_linux_amd64.tar.gz
SHA256SUMS                              ← checksums of all assets
SHA256SUMS.minisig                      ← signature over SHA256SUMS
sfetch-minisign.pub                     ← public key (auto-detected)
```

**Example:**
```bash
# Auto-detect everything (key found in release assets)
sfetch --repo 3leaps/sfetch --latest --dest-dir ~/.local/bin

# Explicit key path
sfetch --repo 3leaps/sfetch --latest \
  --minisign-key ~/.config/sfetch/3leaps-minisign.pub \
  --dest-dir ~/.local/bin

# Require minisign (fail if not available)
sfetch --repo 3leaps/sfetch --latest \
  --require-minisign \
  --dest-dir ~/.local/bin
```

**What sfetch does:**
1. Fetches release from GitHub API
2. Selects `sfetch_v2025.12.06_darwin_arm64.tar.gz` (platform heuristics)
3. Finds `SHA256SUMS.minisig` → triggers Workflow A
4. Auto-detects `sfetch-minisign.pub` from release assets
5. Downloads `SHA256SUMS` + `SHA256SUMS.minisig`
6. Verifies minisign signature over `SHA256SUMS`
7. Downloads asset, computes SHA256, compares to verified checksums
8. Extracts `sfetch` binary from archive
9. Installs to `~/.local/bin/sfetch`

**Public key** (3leaps/sfetch):
```
untrusted comment: sfetch release signing key
RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC
```

## Minisign Workflow B: `jedisct1/minisign`

Per-asset signing - signature directly over each asset. No checksum file.

**Release structure:**
```
minisign-0.12-linux.tar.gz
minisign-0.12-linux.tar.gz.minisig      ← signature over asset
minisign-0.12-macos.zip
minisign-0.12-macos.zip.minisig
minisign-0.12-win64.zip
minisign-0.12-win64.zip.minisig
```

**Example:**
```bash
# Download minisign with explicit key
sfetch --repo jedisct1/minisign --latest \
  --minisign-key /path/to/jedisct1.pub \
  --dest-dir /usr/local/bin

# With asset regex for specific platform
sfetch --repo jedisct1/minisign --latest \
  --asset-regex "minisign-.*-macos.zip$" \
  --minisign-key /path/to/jedisct1.pub \
  --dest-dir /usr/local/bin
```

**What sfetch does:**
1. Fetches release, selects `minisign-0.12-macos.zip`
2. BinaryName inferred: `minisign` (from repo name)
3. ArchiveType inferred: `zip` (from extension)
4. No `SHA256SUMS.minisig` found → Workflow B
5. Finds `minisign-0.12-macos.zip.minisig`
6. No checksum file found - OK (minisign provides integrity)
7. Downloads asset + signature
8. Verifies minisign signature directly over asset bytes
9. Extracts and installs

**Public key** (jedisct1/minisign):
```
untrusted comment: minisign public key
RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
```

---

# GPG/PGP

Widely used, but requires `gpg` binary on system. sfetch uses a temporary keyring (deleted after verification).

## Signature Detection

sfetch detects PGP by:
1. File extension: `.asc`, `.sig` (when containing PGP armor)
2. Content: `-----BEGIN PGP SIGNATURE-----`

## GPG Workflow A: Checksum-Level

**Release structure:**
```
tool-v1.0-linux-amd64.tar.gz
tool-v1.0-darwin-arm64.tar.gz
SHA256SUMS
SHA256SUMS.asc                          ← PGP signature over SHA256SUMS
release-signing-key.asc                 ← public key (optional)
```

**Example:**
```bash
# With explicit key file
sfetch --repo owner/tool --latest \
  --pgp-key-file /path/to/release-key.asc \
  --dest-dir /usr/local/bin

# Auto-detect key from release assets
sfetch --repo owner/tool --latest \
  --dest-dir /usr/local/bin

# With key from URL
sfetch --repo owner/tool --latest \
  --pgp-key-url https://example.com/release-key.asc \
  --dest-dir /usr/local/bin
```

**What sfetch does:**
1. Selects asset based on platform
2. Finds `SHA256SUMS.asc` → triggers Workflow A
3. Downloads key (from flag, URL, or release asset)
4. Creates temporary GPG keyring, imports key
5. Runs `gpg --verify SHA256SUMS.asc SHA256SUMS`
6. Deletes temporary keyring
7. Verifies asset hash against `SHA256SUMS`
8. Extracts and installs

## GPG Workflow B: Per-Asset

**Release structure:**
```
tool-v1.0-linux-amd64.tar.gz
tool-v1.0-linux-amd64.tar.gz.asc        ← PGP signature over asset
SHA256SUMS                              ← checksums (required for PGP)
```

**Example:**
```bash
sfetch --repo owner/tool --latest \
  --pgp-key-file /path/to/release-key.asc \
  --dest-dir /usr/local/bin
```

**What sfetch does:**
1. No checksum-level sig found → Workflow B
2. Finds `tool-v1.0-linux-amd64.tar.gz.asc`
3. Finds `SHA256SUMS` (required for PGP per-asset)
4. Downloads asset, checksum file, signature
5. Verifies PGP signature over asset
6. Verifies asset hash against checksums
7. Extracts and installs

**Note:** Unlike minisign, PGP per-asset signatures still require a checksum file because the signature doesn't inherently provide integrity in sfetch's verification model.

---

# Raw ed25519

For custom tooling that signs with raw ed25519 keys (not minisign format).

## Signature Detection

sfetch detects raw ed25519 by:
1. File extension: `.sig`, `.sig.ed25519`
2. Content: 64 raw bytes OR 128 hex characters

## Raw ed25519 Example

**Release structure:**
```
tool-v1.0-linux-amd64.tar.gz
tool-v1.0-linux-amd64.tar.gz.sig        ← raw ed25519 signature
SHA256SUMS                              ← checksums (required)
```

**Example:**
```bash
# Key is 64 hex characters (32 bytes)
sfetch --repo owner/tool --latest \
  --key "a1b2c3d4e5f6...64_hex_chars..." \
  --dest-dir /usr/local/bin
```

**What sfetch does:**
1. Finds `.sig` file, detects raw ed25519 format
2. Requires checksum file (raw ed25519 needs integrity verification)
3. Downloads asset, checksum, signature
4. Verifies ed25519 signature using pure-Go crypto
5. Verifies asset hash
6. Extracts and installs

**Key format:**
- 64 hex characters representing 32-byte public key
- No PEM/PGP headers allowed (rejected as potential private key leak)
- Example: `a1b2c3d4e5f6789...` (64 chars total)

---

# Cosign/Sigstore (Planned)

**Status:** Not yet implemented. Tracked for future release.

Sigstore provides keyless signing using OIDC identity. Assets are signed with ephemeral keys, and signatures are logged to a transparency log (Rekor).

**Expected release structure:**
```
tool-v1.0-linux-amd64.tar.gz
tool-v1.0-linux-amd64.tar.gz.sig        ← cosign signature
tool-v1.0-linux-amd64.tar.gz.cert       ← signing certificate
SHA256SUMS
```

**Planned flags:**
```bash
sfetch --repo owner/tool --latest \
  --cosign-verify \
  --cosign-identity "maintainer@example.com" \
  --cosign-issuer "https://github.com/login/oauth" \
  --dest-dir /usr/local/bin
```

**Why it matters:**
- No long-lived keys to manage or rotate
- Identity-based verification ("signed by this GitHub user")
- Transparency log provides audit trail

---

# Platform Detection

sfetch auto-detects platform and matches against common naming conventions:

| GOOS | Aliases Matched |
|------|-----------------|
| darwin | darwin, macos, macosx, osx, apple |
| linux | linux |
| windows | windows, win |

| GOARCH | Aliases Matched |
|--------|-----------------|
| amd64 | amd64, x86_64, x64 |
| arm64 | arm64, aarch64 |
| 386 | 386, i386, i686 |

**Asset scoring:**
- Exact GOOS/GOARCH match: +5 points each
- Alias match: +3 points each
- Binary name token: +3 points
- Archive extension (.tar.gz, .zip): +2 points
- Highest score wins; ties are errors

---

# Failure Modes & Fixes

## "no checksum file found" (with non-minisign signature)

```
error: no checksum file found for asset.tar.gz (required for non-minisign signatures)
```

**Cause:** PGP and raw ed25519 signatures require a checksum file.

**Fix:** Ensure the release includes `SHA256SUMS`, or switch to minisign which doesn't require checksums.

## "--require-minisign specified but no .minisig signature found"

```
error: --require-minisign specified but no .minisig signature found in release
```

**Cause:** You requested minisign-only but the release uses PGP or no signatures.

**Fix:** Remove `--require-minisign` or use a release with minisign signatures.

## "binary X not found in archive"

```
error: binary foo not found in archive
```

**Cause:** Inferred binary name doesn't match what's in the archive.

**Fix:** Use `--binary-name`:
```bash
sfetch --repo owner/foo-cli --latest --binary-name foo
```

## "Invalid encoded public key" (minisign)

```
error: read minisign pubkey: Invalid encoded public key
```

**Cause:** Key file missing the header line.

**Fix:** Ensure key file has proper minisign format:
```
untrusted comment: description
RW...base64key...
```

---

# Known Limitations

1. **Archives only**: Expects `.tar.gz`, `.tgz`, or `.zip`. Raw file downloads (`.sh` scripts) not yet supported.

2. **Single binary**: Extracts one file. Multi-binary archives need multiple sfetch calls.

3. **GitHub only**: Currently GitHub releases API only. GitLab, generic URLs planned.

4. **Cosign**: Not yet implemented.

---

# Dogfooding Log

Track real-world repos tested during development:

| Repo | Workflow | Result | Notes |
|------|----------|--------|-------|
| `3leaps/sfetch` | Minisign A | ✅ Works | Auto-detects key |
| `jedisct1/minisign` | Minisign B | ✅ Works | No checksum file, pure minisign |
| `fulmenhq/goneat` | GPG A | ✅ Works | Auto-detects key, checksum-level GPG |

### Dogfooding Detail: fulmenhq/goneat v0.3.14

```bash
$ sfetch --repo fulmenhq/goneat --latest --dest-dir /tmp/test
Detected checksum-level signature: SHA256SUMS.asc
Auto-detected PGP key asset fulmenhq-release-signing-key.asc
PGP checksum signature verified OK
Checksum verified OK
Installed goneat to /tmp/test/goneat
```

**Notes:** goneat uses GPG Workflow A (checksum-level signing). sfetch auto-detects the public key from `fulmenhq-release-signing-key.asc` in the release assets.

### New Flag: --prefer-per-asset

When a release has both checksum-level AND per-asset signatures, sfetch defaults to Workflow A. Use `--prefer-per-asset` to force Workflow B:

```bash
# Force per-asset signature verification (bypass checksum-level)
sfetch --repo owner/tool --latest --prefer-per-asset --dest-dir /tmp/test
```

This is useful when:
- Checksum-level signature is broken but per-asset sigs are valid
- You want to verify the specific asset file directly

### New: Verification Assessment & Provenance

#### --dry-run

Assess what verification is available without downloading:

```bash
$ sfetch --repo BurntSushi/ripgrep --latest --dry-run

sfetch dry-run assessment
─────────────────────────
Repository:  BurntSushi/ripgrep
Release:     15.1.0
Asset:       ripgrep-15.1.0-aarch64-apple-darwin.tar.gz (1.7 MB)

Verification available:
  Signature:  none
  Checksum:   ripgrep-15.1.0-aarch64-apple-darwin.tar.gz.sha256 (sha256, per-asset)

Verification plan:
  Workflow:   C (checksum-only)
  Trust:      low

Warnings:
  - No signature available; authenticity cannot be proven
```

#### --provenance

Output a structured JSON provenance record for audit/compliance:

```bash
# Output provenance to stderr after download
sfetch --repo jesseduffield/lazygit --latest --dest-dir /tmp --provenance

# Write provenance to file
sfetch --repo jesseduffield/lazygit --latest --dest-dir /tmp --provenance-file provenance.json

# Dry-run with JSON output (no download, just assessment)
sfetch --repo jesseduffield/lazygit --latest --dry-run --provenance
```

Provenance record includes:
- Source repository and release info
- Asset name, size, URL, and computed checksum
- Verification workflow used (A/B/C/insecure)
- Signature and checksum verification status
- Trust level (high/medium/low/none)
- Any warnings generated

Schema: `schemas/provenance.schema.json`

#### Workflow C: Checksum-Only

Many popular tools publish checksums but no signatures. sfetch now supports this with Workflow C:

| Repo | Checksum Pattern | Status |
|------|------------------|--------|
| BurntSushi/ripgrep | per-asset `.sha256` | ✅ Supported |
| jesseduffield/lazygit | `checksums.txt` | ✅ Supported |
| junegunn/fzf | versioned `fzf_X.Y.Z_checksums.txt` | ⚠️ Needs pattern |

```bash
$ sfetch --repo jesseduffield/lazygit --latest --dest-dir /tmp
warning: No signature available; authenticity cannot be proven
Using checksum-only verification (no signature available)
Checksum verified OK
Installed lazygit to /tmp/lazygit
```

#### Override Flags

| Flag | Description |
|------|-------------|
| `--skip-sig` | Skip signature verification (existing) |
| `--skip-checksum` | Skip checksum verification |
| `--insecure` | Skip ALL verification (dangerous) |

```bash
# Download without any verification (NOT recommended)
sfetch --repo owner/tool --latest --insecure --dest-dir /tmp
```

---

**Found a repo that doesn't work?** Open an issue with:
- Repo URL and release tag
- Command you ran
- Expected vs actual behavior
