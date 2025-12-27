# Trust Rating System (v0.3.0)

This document is the **design guide** for sfetch’s trust rating system.

sfetch exists to make `curl | bash`-style acquisition safer by **preferring verifiable release artifacts** (checksums/signatures/keys) when upstream provides them, while still being transparent about situations where upstream provides nothing.

## Core Ideas

### 1) Trust is capped by the source

sfetch cannot exceed the maximum trust supported by what the source publishes:

- If a project publishes **signatures + checksums**, sfetch can reach “high trust”.
- If a project publishes **only checksums**, sfetch can reach “low trust”.
- If a project publishes **nothing** (common for install scripts), sfetch can only credit transport (HTTPS) and must remain “minimal”.

A low score is often a **source limitation**, not “user error”.

### 2) Non-experts need informative messaging

When verification artifacts are missing, sfetch should be factual and actionable, not scary.

### 3) Skipping verifiable checks is a user decision

When verification is *verifiable by sfetch* but the user disables it (e.g. `--insecure`, `--skip-checksum`, `--skip-sig`), sfetch should be loud and explicit.

## Definitions

### “Verifiable”

In v0.3.0, skip penalties apply only when checks are **verifiable**:

- Artifact exists in the release **and**
- sfetch has the needed trust anchor/key (provided by flag or auto-detected)

This avoids penalizing users for missing keys or imperfect auto-detection.

## Score Model (Option A)

The v0.3.0 model uses transparent factors and produces a 0–100 score.

- Signature validated: **+70**
- Checksum validated: **+40**
- Checksum algorithm strength (only when checksum validated):
  - sha256/sha512: **+5**
  - sha1/md5: **-10**
- HTTPS baseline credit: **+25** only when **nothing** was verified
- Skip penalties (only when verifiable):
  - signature skipped: **-20**
  - checksum skipped: **-15**
- Bypass rule:
  - `--insecure` while something was verifiable forces score **0**

## Levels

Score-to-level mapping:

- `0` → `bypassed`
- `1–29` → `minimal`
- `30–59` → `low`
- `60–84` → `medium`
- `85–100` → `high`

## CLI Examples (Hypothetical)

### A) HTTPS-only (no artifacts)

```
Trust: 25/100 (minimal)
  ✓ Transport: HTTPS
  ✗ Checksum: not provided by source
  ✗ Signature: not provided by source

Note: This source provides no verification artifacts.
```

### B) Checksum-only

```
Trust: 45/100 (low)
  ✓ Checksum: sha256 verified
  ✓ Algorithm: sha256
```

### C) Signature-only

```
Trust: 70/100 (medium)
  ✓ Signature: verified
```

### D) Signature + checksum

```
Trust: 100/100 (high)
  ✓ Signature: verified
  ✓ Checksum: sha256 verified
```

### E) Bypassed verifiable checks

```
Trust: 0/100 (bypassed)
  ⚠ Signature: verifiable but skipped
  ⚠ Checksum: verifiable but skipped

Warning: Verification was available but bypassed.
```

## Gating: `--trust-minimum`

`--trust-minimum N` enforces a required score (0–100). sfetch exits non-zero when the computed score is below the threshold.

On failures, sfetch prints a factor breakdown so CI logs explain *why* the run was blocked.

## Provenance JSON

For v0.3.0, provenance includes:

- `trustLevel` (string) — **deprecated**, retained for one minor cycle
- `trust` (object) — numeric score + factors

Schema: `schemas/provenance.schema.json`

## Reproducible References (Tests / Fixtures)

The trust rating system is backed by unit and integration tests so results are reviewable and stable:

- Canonical score scenarios: `main_test.go:1063` (`TestComputeTrustScoreOptionA`)
- Assessment wiring (workflow selection): `main_test.go:1184` (`TestAssessRelease`)
- Provenance schema validation fixtures: `main_test.go:1781` (`TestProvenanceRecordValidation`)
- End-to-end verification fixtures (real signatures/checksums):
  - `testdata/integration/`
  - `integration_test.go`

## Future extensions (out of scope for v0.3.0)

The trust model is intended to generalize to other acquisition domains where the verification story differs:

- Docker/OCI images (digests, signatures, transparency logs)
- Patch/update workflows (signed manifests, delta updates)
- Non-executable artifacts (documents, SBOMs)
