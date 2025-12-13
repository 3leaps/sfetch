// Package update provides small, dependency-free helpers for deciding whether a
// self-update should proceed.
//
// It is designed to be useful for any CLI that updates itself from signed
// releases (for example, from GitHub releases), where you want conservative
// guardrails and clear user messaging.
//
// This package intentionally does not perform downloads, signature verification,
// checksum verification, or installation. It focuses on deciding whether an
// update should proceed given a current version and a target release tag.
//
// Version model
//   - Supports semver-like strings in the form "vMAJOR.MINOR[.PATCH]" with optional
//     prerelease/build metadata (e.g., "v0.2.5-rc1", "v1.0.0+build123").
//   - Prerelease precedence follows SemVer: "0.2.5-rc1" < "0.2.5".
//   - "dev", "0.0.0-dev", and empty versions are treated as non-comparable and
//     default to proceeding (developer escape hatch).
package update
