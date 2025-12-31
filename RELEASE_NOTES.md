
## v0.3.1

### Summary
Fix raw script handling so `install-sfetch.sh` and similar assets work correctly.

### Highlights
- **Raw scripts no longer misclassified as archives:** Fixed regression where scripts like `install-sfetch.sh` failed with "extract archive: exit status 1" when fetched alongside archive assets.

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

Or self-update:
```bash
sfetch --self-update --yes
```

### Details
- See `CHANGELOG.md` for the complete list.

---

## v0.3.0

### Summary
Introduce a numeric trust rating system (0–100) with transparent factor breakdown and optional policy gating via `--trust-minimum`.

### Highlights

**Trust rating (v0.3.0)**
- Trust is now reported as `N/100 (level)` with factor breakdown (signature/checksum/transport/algo).
- New workflow `none` distinguishes "source provides no verification artifacts" from explicit bypass (`--insecure`).
- Provenance JSON includes a new `trust` object and retains legacy `trustLevel` for one minor cycle.

**Policy gating**
- `--trust-minimum <0-100>` blocks downloads below the specified threshold and prints factor breakdown on failure.

**Exit codes**
- Exit code `0` indicates the requested fetch/install completed (even if the user chose to bypass verification).
- Non-zero indicates the operation was blocked (e.g., `--trust-minimum`) or failed (download/verification errors).

---

## v0.2.9

### Summary
Fix asset selection for tools with "sig" in their name (e.g., `minisign`, `cosign`) and document install permission behavior.

### Highlights
- Fixed false positives in supplemental file detection for tool names containing "sig".
- Documented permission behavior for archives, raw scripts/binaries, and cross-device installs.

---

Older releases: `docs/releases/`
