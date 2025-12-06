---
title: "sfetch Key Handling Guide"
description: "Explains how sfetch validates ed25519 keys, imports PGP keys, and keeps signatures safe."
author: "Schema Cartographer"
author_of_record: "Dave Thompson (https://github.com/3leapsdave)"
supervised_by: "@3leapsdave"
date: "2025-12-03"
last_updated: "2025-12-03"
status: "draft"
tags: ["docs", "signing", "security"]
---

# Key handling guide

## Supported signature formats

| Format | Extension | Verification flag | Client deps |
| --- | --- | --- | --- |
| **Minisign** | `.minisig` | `--minisign-key <pubkey.pub>` | None (pure-Go) |
| Raw ed25519 | `.sig`, `.sig.ed25519` | `--key <64-hex-bytes>` | None (pure-Go) |
| ASCII-armored PGP | `.asc` | `--pgp-key-file path/to/public.asc` | `gpg` binary |

Minisign is the recommended format for sfetch releases. It provides trusted comments (signed metadata) and password-protected keys.

`sfetch` auto-detects the format by inspecting the signature file contents:

- `untrusted comment:` prefix → minisign format, verified with pure-Go ed25519.
- `-----BEGIN PGP SIGNATURE-----` → invokes `gpg` in a temporary keyring.
- 64 raw bytes → treats as binary ed25519.
- Hex text of length 128 → decoded into raw ed25519 before verification.

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
