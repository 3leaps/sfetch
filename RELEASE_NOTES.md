# Release Notes

## v0.2.7

### Summary
Remove the external `unzip` dependency by extracting ZIP archives with the Go standard library, improving portability in minimal containers and CI runners.

### Highlights

**Pure-Go ZIP extraction**
- `.zip` assets are extracted with `archive/zip` (no `unzip` required).
- Extraction rejects ZIP slip/path traversal, absolute paths, and symlinks.

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.2.6

### Summary
Improved reliability in containerized CI by handling cross-device installs/caching automatically, plus internal refactoring to improve auditability (no intended CLI behavior changes).

### Highlights

**Cross-device install/caching fix (EXDEV)**
- When `--dest-dir` or `--cache-dir` is on a different filesystem than the temp directory (common with container mounts), sfetch now falls back to a copy operation when `rename(2)` fails with “invalid cross-device link”.

**CI/CD documentation**
- New guide: `docs/cicd-usage-guide.md` (GitHub Actions, GitLab CI, container runners).

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

### Details
- See `CHANGELOG.md` for the complete list.

---

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

Older releases: `docs/releases/`
