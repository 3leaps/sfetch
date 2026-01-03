# `pkg/update`

Minimal, dependency-free helpers for deciding whether a self-update should proceed.

This package is intended to be used by CLIs that:
- Determine a target release tag (latest or `--tag`)
- Enforce guardrails (major-version guard, explicit downgrade intent)
- Proceed to a separate verification + install pipeline only when appropriate

This is a building block: to implement a full self-update mechanism you still
need code to fetch release metadata, select the right asset, verify integrity
and authenticity (signatures + checksums), and install atomically.

## API

- `DecideSelfUpdate(current, target string, explicitTag, force bool) (Decision, message string, exitCode int)`
- `NormalizeVersion(v string) (normalized string, ok bool)`
- `CompareSemver(a, b string) (cmp int, err error)`
- `FormatVersionDisplay(v string) string`
- `DescribeDecision(d Decision) string`

## Semver rules

- Accepts `vMAJOR.MINOR[.PATCH]` with optional prerelease/build metadata.
  - Examples: `v0.2.5`, `0.2.5`, `v0.2.5-rc1`, `v1.0.0+build123`
- Prerelease precedence follows SemVer:
  - `0.2.5-rc1 < 0.2.5`
  - Numeric prerelease identifiers sort numerically: `rc.10 > rc.2`
- Build metadata (`+...`) is ignored for ordering.

## Decision semantics

`DecideSelfUpdate` returns:
- `DecisionSkip` when `current == target` and `force == false`
- `DecisionReinstall` when `current == target` and `force == true`
- `DecisionProceed` when a normal upgrade is available
- `DecisionDowngrade` only when `explicitTag == true` and `target < current`
- `DecisionRefuse` when the major version changes and `force == false` (upgrade or downgrade)
- `DecisionDevInstall` when `current` is `dev`/`0.0.0-dev`/empty

The `message` is suitable for end-user output. The suggested `exitCode` is `0`
for “success/skip” and `1` for “refuse”.

## What’s intentionally out of scope

- Release discovery (GitHub API, rate limits, auth, etc.)
- Asset selection (GOOS/GOARCH matching, archives vs raw, etc.)
- Verification workflows (minisign/PGP/ed25519; checksum parsing)
- Installation (atomic replace, Windows lock fallback, permissions)
