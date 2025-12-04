---
title: Asset Pattern Matching
description: How sfetch discovers and selects release assets automatically
author_of_record: Dave Thompson (@3leapsdave)
status: stable
---

# Asset Pattern Matching

sfetch uses a scoring heuristics system to automatically select the correct binary asset from GitHub releases without configuration for most repos.

## Research Process

1. **Common repos surveyed**:
   - Kubernetes (kubectl, kubeadm)
   - Helm
   - Cosign/Sigstore
   - FulmenHQ (goneat, crucible)
   - Hugo
   - Terraform
   - GitHub CLI (gh)
   - Nerdctl/Containerd

2. **Patterns extracted**:
   | Component | Patterns |
   |-----------|----------|
   | Binary | `{{binary}}`, `{{binary}}_{{version}}`
   | OS | `darwin`/`macos`/`osx`, `linux`, `windows`/`win`
   | Arch | `amd64`/`x86_64`/`x64`, `arm64`/`aarch64`, `386`/`i386`/`i686`
   | Ext | `.tar.gz`/`.tgz`/`.zip`

3. **Scoring** (pick highest; tie error):
   - Exact GOOS/GOARCH: +5 each
   - Alias GOOS/GOARCH: +3 each
   - Binary token: +3
   - Archive ext: +2
   - Skip supplemental (SHA/sig/checksum)
     - Anything ending with `.asc`, `.sig`, `.sig.ed25519`, or containing `sha256`/`checksum` is filtered out before scoring (matches the `looksLikeSupplemental` helper in `main.go`).

## Examples

**goneat v0.3.11 (darwin/arm64 host)**:
- Selects `goneat_v0.3.11_darwin_arm64.tar.gz` (15pts)
- Rejects `darwin_amd64.tar.gz` (10pts), `.asc` (11pts)

**Override**: entries in `repoConfigs` override specific fields while inheriting defaults (see `mergeConfig` in `main.go`). Asset/signature templates from the override run before heuristics.

See `docs/repo-config-guide.md` custom.

## Signature/Key Patterns

Default `SignatureCandidates`:
```
{{asset}}.sig
{{base}}.sig
{{asset}}.sig.ed25519
{{base}}.sig.ed25519
{{asset}}.minisig
{{asset}}.asc
{{base}}.asc
```

- ed25519: `--key 64hex`
- PGP: `--pgp-key-file pub.asc` (gpg temp keyring)

## Extensibility

- repoConfigs `AssetPatterns`/`SignatureCandidates` regex first.
- Heuristics fallback 95% repos.

## Usage Reference

For concrete CLI examples, run `sfetch -helpextended` to print the embedded quickstart, or see the README’s signature section.
