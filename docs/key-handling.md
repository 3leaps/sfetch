---
title: "sfetch Key Handling Guide"
description: "Explains how sfetch validates ed25519 keys, imports PGP keys, and keeps signatures safe."
author: "Schema Cartographer"
author_of_record: "Dave Thompson (https://github.com/3leapsdave)"
supervised_by: "@3leapsdave"
date: "2025-12-03"
last_updated: "2025-12-08"
status: "draft"
tags: ["docs", "signing", "security"]
---

# Key handling guide

## Signing workflows

sfetch supports two industry-standard signing patterns:

### Workflow A: Checksum-level signing (recommended, ~70% of signed tools)

```
SHA256SUMS          ← hashes of all release assets
SHA256SUMS.minisig  ← signature over SHA256SUMS
binary.tar.gz       ← unsigned, verified via checksum
```

Verification order:
1. Download checksum file + signature
2. Verify checksum file authenticity (minisign/PGP)
3. Download asset, compute hash, compare to verified checksums

**Examples:** kubectl, Hugo, ripgrep, bat, starship

### Workflow B: Per-asset signing (~30% of signed tools)

```
binary.tar.gz       ← the asset
binary.tar.gz.sig   ← signature over asset bytes
SHA256SUMS          ← optional, may be unsigned
```

Verification order:
1. Download asset + signature
2. Verify asset bytes directly
3. Optionally verify checksum

**Examples:** cosign, gh CLI (goreleaser default)

sfetch auto-detects the workflow: if `SHA256SUMS.minisig` or `SHA256SUMS.asc` exists, it uses Workflow A; otherwise Workflow B.

## Supported signature formats

| Format | Extension | Verification flags | Client deps |
| --- | --- | --- | --- |
| **Minisign** | `.minisig` | `--minisign-key`, `--minisign-key-url`, `--minisign-key-asset` | None (pure-Go) |
| Raw ed25519 | `.sig`, `.sig.ed25519` | `--key <64-hex-bytes>` | None (pure-Go) |
| ASCII-armored PGP | `.asc` | `--pgp-key-file`, `--pgp-key-url`, `--pgp-key-asset` | `gpg` binary |

Minisign is the recommended format for sfetch releases. It provides trusted comments (signed metadata) and password-protected keys.

`sfetch` auto-detects the format by inspecting the signature file contents:

- `untrusted comment:` prefix → minisign format, verified with pure-Go ed25519.
- `-----BEGIN PGP SIGNATURE-----` → invokes `gpg` in a temporary keyring.
- 64 raw bytes → treats as binary ed25519.
- Hex text of length 128 → decoded into raw ed25519 before verification.

## Minisign key resolution

sfetch resolves minisign public keys in priority order:

1. **`--minisign-key <path>`** - Local file path (or URL if starts with `http://`/`https://`)
2. **`--minisign-key-url <url>`** - Download from URL
3. **`--minisign-key-asset <name>`** - Fetch from release assets by exact name
4. **Auto-detect** - Scan release assets for `*minisign*.pub` or `*-signing-key.pub`

### Strict mode

Use `--require-minisign` to enforce minisign verification:
- Fails fast if no `.minisig` signature is found
- Forces minisign path even if `preferChecksumSig` is false in repo config
- Rejects PGP/raw signatures when minisign is required

## Getting started with minisign

### For users verifying releases

Most releases publish their minisign public key as a release asset (e.g., `project-minisign.pub`).
sfetch auto-detects these keys, so often no flags are needed:

```bash
# Auto-detect key from release assets
sfetch --repo owner/project --latest

# Explicit key from local file
sfetch --repo owner/project --latest --minisign-key /path/to/project.pub

# Strict mode: fail if minisign verification unavailable
sfetch --repo owner/project --latest --require-minisign
```

### For maintainers signing releases

Install minisign: `brew install minisign` (macOS), `apt install minisign` (Debian/Ubuntu),
or download from https://jedisct1.github.io/minisign/

```bash
# Generate keypair (will prompt for password)
minisign -G -p myproject-minisign.pub -s myproject-minisign.key

# Sign your SHA256SUMS file
minisign -Sm SHA256SUMS -s myproject-minisign.key -t "myproject v1.0.0"

# Publish the .pub file with your release
```

See [docs/security/signing-runbook.md](security/signing-runbook.md) for complete release signing workflow.

## ed25519 key expectations

- Supply the publisher’s public key with `--key` as a **64-character hexadecimal string** (32 bytes).
- PEM/PGP blobs, whitespace, or mixed encodings are rejected up front to prevent accidental leakage of private material.
- The CLI never echoes the provided key back to STDOUT/STDERR; errors are generic (`"invalid ed25519 key"`).

To export a FulmenHQ key in the expected format:

```bash
gpg --export --armor security@fulmenhq.dev | grep -v "-----" | tr -d '\n'
```

## PGP verification flow

1. Download the maintainer’s ASCII-armored public key (e.g., `fulmenhq-release-signing-key.asc`).
2. Pass the file via `--pgp-key-file`. The file is **only** imported into a temporary `GNUPGHOME` that is deleted after verification.
3. `gpg --batch --no-tty --trust-model always --verify <sig.asc> <asset>` runs under the hood (override path via `--gpg-bin`).
4. Command output is truncated to 2 KB in error cases to avoid leaking key material.

## Safety checks

- `--key` is required whenever the signature is not PGP. If omitted, the CLI errors before attempting verification.
- If the supplied key contains phrases like `BEGIN PRIVATE KEY`, sfetch exits with a warning so private keys are never logged.
- `--skip-sig` exists solely for controlled testing; sfetch emits a loud warning whenever it is used.

## Operational tips

- Store org-wide public keys under `docs/` or publish with releases so CI, bootstrap scripts, and integration tests reference the same source.
- For your own releases, use minisign (`.minisig`) as primary format - it's pure-Go verifiable with signed metadata. Add PGP (`.asc`) as secondary for users who prefer gpg tooling.
- Only sign `SHA256SUMS`, not individual files. Users verify the signature, then verify file checksums against SHA256SUMS.
- Document key rotation steps alongside release playbooks to keep future maintainers aligned (see `docs/security/signing-runbook.md`).
