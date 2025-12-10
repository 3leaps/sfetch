# ADR-0001: Adopt Semantic Versioning

**Status**: Accepted  
**Date**: 2025-12-09  
**Author**: Dave Thompson (@3leapsdave)

## Context

sfetch launched with Calendar Versioning (CalVer) using the format `vYYYY.MM.DD[.N]`. This made sense for the initial concept: a lightweight download helper with periodic updates for new registry patterns.

As development progressed, sfetch evolved into a more substantial tool with:
- Multiple signature verification methods (minisign, PGP, ed25519)
- Verification workflows (A, B, C)
- Provenance records for audit trails
- Extensible asset type handling

This trajectory suggests sfetch will continue to grow with distinct categories of changes:
- Bug fixes and security patches
- New features (signature formats, asset types, CLI flags)
- Potential breaking changes (config format, API)

CalVer does not communicate these distinctions. A release tagged `v2025.12.15` tells users nothing about compatibility or scope of changes.

## Decision

**Adopt Semantic Versioning (SemVer)** starting with v0.2.0.

### Version Number Meaning

| Component | When to Increment | Example |
|-----------|-------------------|---------|
| **Major** (X.0.0) | Breaking changes to CLI, config, or verification behavior | 1.0.0 |
| **Minor** (0.X.0) | New features, backward-compatible | 0.3.0 |
| **Patch** (0.0.X) | Bug fixes, security patches | 0.2.1 |

### Single Source of Truth

Version is stored in `VERSION` file at repository root:
- Contains semver string without `v` prefix (e.g., `0.2.0`)
- Build tooling reads this file
- CI validates VERSION matches git tag at release time
- Enables version display without git context

### Historical Tag Mapping

| CalVer Tag | SemVer Tag | Commit | Notes |
|------------|------------|--------|-------|
| `v2025.12.05` | `v0.1.0` | (same) | Initial public release |
| `v2025.12.06.1` | `v0.1.1` | (same) | Install script bugfix |

CalVer tags are **preserved** (not deleted) for:
- Backward compatibility with any existing references
- Historical accuracy
- Transparency about project evolution

SemVer tags are added pointing to the same commits.

## Consequences

### Positive
- Clear communication about change scope
- Aligns with ecosystem expectations (Go modules, package managers)
- Enables dependency version constraints (e.g., `>=0.2.0 <1.0.0`)
- VERSION file provides build-time validation

### Negative
- Two tag naming schemes in history (minor confusion)
- Requires documentation of mapping (this ADR)
- VERSION file must stay in sync (mitigated by CI validation)

### Neutral
- `latest` release pointer continues to work unchanged
- Install script continues to work unchanged
- No impact on existing users (both tag schemes resolve)

## Implementation

1. Create `VERSION` file containing `0.2.0`
2. Update Makefile to read VERSION
3. Update CI to validate VERSION ↔ tag match
4. Create semver tags for historical releases
5. Update CHANGELOG.md format
6. Update README.md versioning section

## References

- [Semantic Versioning 2.0.0](https://semver.org/)
- [Calendar Versioning](https://calver.org/)
- Migration plan: `.plans/active/v0.2.0/calver-to-semver-migration.md`
