# Release Notes

## v0.2.8

### Summary
Tighten installation ergonomics and verification-related test coverage: warn on Linux `noexec` destinations, improve deterministic install-path testing, and add low-risk unit tests for internal helpers.

### Highlights

**Linux `noexec` destination warning (best effort)**
- When the install destination appears to be mounted with `noexec`, sfetch prints a warning explaining that `chmod +x` won’t fix it.

**Install-path test coverage (rename vs copy fallback)**
- Added unit tests that cover executable permission behavior for raw and archive installs across both rename and EXDEV copy fallback paths.
- Added a Windows-only test covering the self-update locked-target `.new` fallback.

**Internal helper coverage (low risk)**
- Added unit tests for `internal/verify` checksum parsing and key normalization.
- Added unit tests for `internal/selfupdate` target path selection.

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.2.7

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

Older releases: `docs/releases/`
