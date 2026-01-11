# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in sfetch, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email security concerns to: security@3leaps.net
3. Include: description, reproduction steps, affected versions, potential impact

We aim to respond within 48 hours and will coordinate disclosure timing with you.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| 0.3.x   | Security fixes only |
| < 0.3   | No        |

## Security Model

sfetch is a CLI tool for secure file downloads. See [THREAT_MODEL.md](THREAT_MODEL.md) for:
- Trust boundaries
- Attack surface analysis
- Security controls

## Static Analysis

We use gosec for static security analysis. Suppressions are documented in [suppressions/gosec.md](suppressions/gosec.md) with Security Decision Records (SDRs).

## Verification

sfetch releases include:
- SHA-256 and SHA-512 checksums
- Minisign signatures (Ed25519)
- GPG signatures (RSA-4096)

Verify downloads using `sfetch --self-verify` or manually with the published keys.
