# Release Notes

## v2025.12.05 (Unreleased)

### Highlights
- Embedded quickstart (`sfetch -helpextended`) so users get practical examples without leaving the CLI.
- Automated PGP key discovery (`--pgp-key-url`, `--pgp-key-asset`, and auto-detect) so goneat and similar releases no longer require manual key downloads.
- `make install` now installs into user-space by default and can be customized via `buildconfig.mk`.
- Release artifacts ship with a consistent `sfetch`/`sfetch.exe` name, simplifying bootstrap scripts and downstream installers.

### Details
- See `CHANGELOG.md` (Unreleased) for the complete list of additions and fixes.
- Each release will have a dedicated notes file under `docs/releases/` named `vYYYY.MM.DD.md`.
