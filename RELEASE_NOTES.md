# Release Notes

## v2025.12.06

### Highlights
- **Minisign verification**: Pure-Go parsing of `.minisig` files via `--minisign-key` flag.
- **Secure bootstrap installer**: `install-sfetch.sh` with embedded minisign trust anchor for `curl | bash` installs.
- **Dual signing**: Releases signed with both minisign and PGP for user choice.
- **Shell script validation**: `shellcheck` and `shfmt` added to precommit checks.

### Install

```bash
# Quick install
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash

# With options
curl -sSfL .../install-sfetch.sh | bash -s -- --dir ~/bin --yes
```

### Details
- See `CHANGELOG.md` for the complete list of additions and fixes.
- Release notes: `docs/releases/v2025.12.06.md`
