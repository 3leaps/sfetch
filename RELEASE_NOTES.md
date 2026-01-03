
## v0.3.2

### Summary
stdout/stderr convention fix and comprehensive test coverage improvements.

### Highlights

**stdout/stderr convention**
- All human-readable output now goes to stderr; stdout reserved for JSON only.
- Enables clean piping: `sfetch --dry-run --json 2>/dev/null | jq .trust`
- Affected flags: `--version`, `--version-extended`, `--self-verify`, `--show-trust-anchors`, `--dry-run`, `--helpextended`

**Test coverage expansion**
- Main package coverage: 39% → 54%
- 5 test passes covering: pure functions, internal/verify, CLI validation, asset selection, trust score calculation

**shellsentry integration**
- Added shellsentry to corpus with minisign verification fixtures

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

Older releases: `docs/releases/`
