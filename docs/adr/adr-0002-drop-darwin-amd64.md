# ADR-0002: Drop darwin/amd64 (Intel Mac) Support

- **Status:** Accepted
- **Date:** 2026-04-20
- **Release:** v0.4.7

## Context

Since its first release, sfetch has shipped `sfetch_darwin_amd64.tar.gz`
alongside the Apple Silicon build. Two forces have shifted the cost/benefit
balance:

1. **Apple's Intel Mac runway has closed.** macOS 15 is the last macOS to
   support Intel hardware. Apple Silicon has been the default Mac since
   late 2020, and the last Intel Mac shipped in 2021. Consumer orgs at
   3leaps are already on Apple Silicon or actively EOL'ing their Intel
   fleet.

2. **The build infrastructure itself is signaling EOL.** GitHub-hosted
   runners with Intel macOS are emitting deprecation banners across
   sibling projects. Our own release matrix builds via cross-compilation
   on `ubuntu-latest`, so we aren't directly affected, but the broader
   ecosystem direction is clear.

Carrying the architecture costs one extra matrix job per release, one
extra signed archive, two extra checksum lines, and a larger user-facing
surface to verify. No current consumer is pinned to our darwin/amd64
artifacts (checked via release asset download counts through v0.4.5).

## Decision

From v0.4.7 onwards, sfetch does not publish `darwin_amd64` release
artifacts. The supported target matrix is:

- `darwin_arm64`
- `linux_amd64`, `linux_arm64`
- `windows_amd64`, `windows_arm64`

`scripts/install-sfetch.sh` detects the Intel-Mac case early and exits
with a clear message pointing users at v0.4.6 (the last supporting
release) or at an Apple Silicon upgrade. The guard honors an explicit
`--tag` so the documented recovery path (`--tag v0.4.6`) stays
functional — only the unversioned (`latest`) install is blocked.

`sfetch --self-update` applies the same retirement handling: on
darwin/amd64, if the resolved target release lacks the asset, sfetch
surfaces the explicit retirement guidance (pin `--tag v0.4.6` or build
from source) instead of the generic "no asset matches GOOS/GOARCH
heuristics" error that the asset selector would otherwise return.

The Go source itself remains portable; anyone who needs to build from
source on Intel Mac can still do so via `go build` — we simply stop
publishing the pre-built binary.

## Consequences

### Positive
- Reduced release surface (5 archives instead of 6), faster release
  workflow, fewer signed checksums to generate.
- Aligns with the default pattern in the sibling `homebrew-tap` repo,
  which treats `darwin-amd64` as optional.
- Clear signal to users still on Intel Mac that they're running on a
  deprecated Apple platform.

### Negative
- Intel Mac users on v0.4.6 or older must pin their install command
  (`--tag v0.4.6`). They will not receive future security fixes through
  the standard installer path.

### Mitigations
- Installer script fails fast with an informative message rather than a
  404 on the missing asset.
- README, CHANGELOG, and release notes explicitly document the
  recovery path.
- Source builds on Intel Mac still work; anyone who must run
  post-v0.4.6 sfetch on Intel Mac can `go build` from a tag.

## Notes

If darwin/amd64 demand re-emerges (unexpected consumer pinning, enterprise
Intel-Mac fleet that survives the 2026 EOL timeline), the architecture can
be restored in a single release: revert the matrix entry, the Makefile
line, the installer guard, and a few doc lines. This ADR is not intended
as a permanent foreclosure — just as a deliberate retirement that matches
current ecosystem reality.
