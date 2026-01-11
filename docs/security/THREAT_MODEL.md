# Threat Model

## Overview

sfetch is a CLI tool that downloads files from GitHub releases and arbitrary URLs with cryptographic verification. This document describes trust boundaries, attack surface, and security controls.

## Trust Boundaries

### Local User (Trusted)
- Command-line arguments are trusted input
- The user running sfetch has equivalent filesystem access to the sfetch process
- No privilege escalation occurs - sfetch runs with user permissions

### Network (Untrusted)
- All downloaded content is untrusted until verified
- HTTPS provides transport security but not content authenticity
- Checksums verify integrity; signatures verify authenticity

### GitHub API (Semi-trusted)
- Release metadata comes from GitHub API over HTTPS
- Asset URLs are validated against expected GitHub domains
- Rate limiting and authentication handled via GITHUB_TOKEN

## Attack Surface

| Surface | Threats | Mitigations |
|---------|---------|-------------|
| CLI arguments | Path traversal, injection | Paths resolved to absolute; no shell expansion |
| Downloaded files | Malicious content, tampering | Checksum verification, signature verification |
| Archive extraction | Zip slip, path traversal, decompression bombs | Path validation, controlled extraction directory |
| Network | MITM, redirect attacks | HTTPS required by default, redirect limits |
| File permissions | Overly permissive files | Explicit chmod for executables only |

## Security Controls

### Verification Workflows

| Workflow | Trust Level | Description |
|----------|-------------|-------------|
| A | 100/100 | Checksum-level signature (minisign/GPG signs checksums) |
| B | 85/100 | Per-asset signature (minisign/GPG signs each file) |
| C | 45/100 | Checksum only (integrity, no authenticity) |
| none | 25/100 | HTTPS transport only |

### Default-Secure Behavior

- HTTP blocked by default (`--allow-http` required)
- Redirects blocked by default (`--follow-redirects` required)
- Unknown content types blocked by default
- Signature verification attempted automatically when artifacts present

## Out of Scope

The following are explicitly out of scope for sfetch's threat model:

1. **Malicious local user**: If the user running sfetch is malicious, they already have shell access
2. **Compromised signing keys**: sfetch verifies signatures but cannot detect key compromise
3. **Supply chain attacks on upstream**: If a maintainer publishes malicious releases with valid signatures, sfetch will trust them
4. **Kernel/OS vulnerabilities**: sfetch assumes the underlying OS is not compromised

## Related Documents

- [suppressions/gosec.md](suppressions/gosec.md) - Static analysis suppression decisions
