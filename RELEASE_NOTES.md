
## v0.3.0

### Summary
Introduce a numeric trust rating system (0–100) with transparent factor breakdown and optional policy gating via `--trust-minimum`.

### Highlights

**Trust rating (v0.3.0)**
- Trust is now reported as `N/100 (level)` with factor breakdown (signature/checksum/transport/algo).
- New workflow `none` distinguishes “source provides no verification artifacts” from explicit bypass (`--insecure`).
- Provenance JSON includes a new `trust` object and retains legacy `trustLevel` for one minor cycle.

**Policy gating**
- `--trust-minimum <0-100>` blocks downloads below the specified threshold and prints factor breakdown on failure.

**Dogfood corpus (opt-in)**
- Dogfood set lives in `testdata/corpus.json` and is runnable via `make corpus-dryrun`.

**Exit codes**
- Exit code `0` indicates the requested fetch/install completed (even if the user chose to bypass verification).
- Non-zero indicates the operation was blocked (e.g., `--trust-minimum`) or failed (download/verification errors).

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.2.9

### Summary
Fix asset selection for tools with "sig" in their name (e.g., `minisign`, `cosign`) and document install permission behavior.

### Highlights
- Fixed false positives in supplemental file detection for tool names containing "sig".
- Documented permission behavior for archives, raw scripts/binaries, and cross-device installs.

---

## v0.2.8

### Summary
Tighten installation ergonomics and verification-related test coverage: warn on Linux `noexec` destinations, improve deterministic install-path testing, and add low-risk unit tests for internal helpers.

### Highlights
- Warn on Linux `noexec` destinations (best effort).
- Added deterministic tests for rename vs EXDEV copy fallback.
- Added unit tests for internal verify/selfupdate helpers.

---

Older releases: `docs/releases/`
