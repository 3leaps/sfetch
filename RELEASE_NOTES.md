# Release Notes

## v0.2.5

### Summary
Self-update reliability improvements (version-aware behavior) plus a schema-backed embedded self-update configuration for auditable, reusable update logic.

### Highlights

**Self-update version checking**
- `--self-update` skips reinstall if already at the target version (exit 0).
- `--self-update-force` reinstalls the same version and allows major-version jumps (existing guard preserved unless forced).
- `--tag` supports explicit downgrades (major-version guard still applies unless forced).
- `--dry-run` now includes a “Version check” section showing current/target and status.

**Embedded, schema-backed update config**
- Self-update now loads an embedded update target config instead of relying on inferred defaults.
- New flags:
  - `--show-update-config`
  - `--validate-update-config`

**Reusable library surface (initial)**
- New `pkg/update` package contains the self-update decision matrix and version comparison helpers.

**Signing workflow standardization**
- All signing-related environment variables now use an `SFETCH_` prefix for CI/scripting consistency:
  - `MINISIGN_KEY` → `SFETCH_MINISIGN_KEY`
  - `PGP_KEY_ID` → `SFETCH_PGP_KEY_ID`
  - `GPG_HOMEDIR` → `SFETCH_GPG_HOMEDIR`
  - Added `SFETCH_MINISIGN_PUB` for explicit public key path

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.2.4

### Summary
Bug fix for self-update failing when SHA2-512SUMS is preferred over SHA256SUMS.

### Highlights

**Fixed self-update checksum mismatch**
- Self-update and fetch now correctly detect the hash algorithm from the checksum filename.
- Previously, when SHA2-512SUMS was selected, the code still used sha256 for hashing, causing "checksum not found" errors.

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.2.3

### Summary
Installer hardening and signing script improvements for custom GPG environments.

### Highlights

**Installer Parsing Improvements**
- Prefer `jq` (if present) for GitHub release JSON parsing; dependency-free fallback retained
- Added threat-model comments for pre-extraction path traversal scanning
- `make bootstrap` now advisory; `make prereqs` remains strict

**Signing Script Fixes**
- Added `GPG_HOMEDIR` environment variable support for custom GPG homedirs
- Uses `env GNUPGHOME=...` to avoid polluting user's global GPG settings

**Documentation**
- Updated docs to reflect checksum-only opt-in and signature defaults
- Added DO/DONOT section to `AGENTS.md` with push approval policies

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

### Details
- See `CHANGELOG.md` for the complete list.

---

Older releases: `docs/releases/`
