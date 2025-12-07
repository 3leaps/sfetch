# Release Notes

## v2025.12.06.1

### Summary
Patch release fixing install script bug from v2025.12.06.

### Fixed
- Install script EXIT trap error (`tmpdir: unbound variable`) due to `local` variable scoping.

### Changed
- CI now tests install script with `--dry-run` against previous release.
- README verification examples use `shasum -a 256` (macOS compatible) and temp GPG keyring.
- Upload script includes minisign signature files.

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

### Details
- See `CHANGELOG.md` for the complete list.
- Release notes: `docs/releases/v2025.12.06.1.md`
