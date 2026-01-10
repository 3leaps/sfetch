# Test Data

This directory contains test fixtures and corpus manifests for sfetch.

## Corpus

The corpus manifest (`corpus.json`) defines real-world fetch targets for integration testing.

### Guidelines

**Adding entries:**
- Assets must be publicly available (no auth required beyond GitHub API)
- Content must be non-objectionable and appropriate for all audiences
- Prefer well-known, stable projects with predictable release patterns
- Include a `note` field explaining why the entry is useful

**Important:**
- Assets are fetched on-demand and are **never persisted in this repo**
- Downloaded content goes to `test-corpus/` (gitignored) or OS temp
- Exercise responsibly: limit corpus runs to **5-6 times per hour** during development
- GitHub API has rate limits; always set `GITHUB_TOKEN` for authenticated access

### Running

```bash
make corpus                      # Fast tier, dry-run
make corpus-all                  # All tiers, dry-run
GITHUB_TOKEN=$(gh auth token) make corpus  # With auth (recommended)
```

**Note:** GitHub API rate limits are strict for unauthenticated requests. Always use a valid `GITHUB_TOKEN` environment variable. A fine-grained PAT with `Contents: Read` on public repos is sufficient.

### Categories

Entries are tagged with a `category` field for filtering:

| Category | Description | Fetch method |
|----------|-------------|--------------|
| `release` | GitHub release assets | `--repo owner/repo` |
| `github-raw` | Raw GitHub repo content | `--github-raw owner/repo@ref:path` |
| `url` | Arbitrary HTTPS/HTTP URLs | `--url` (v0.4.0+) |
| `format-test` | File format variety testing | `--github-raw` |

### Overlap Cases & Trust-Based Path Selection

Some content is accessible via multiple methods with different trust levels:

| Content | Via Release | Via --github-raw | Via --url |
|---------|-------------|------------------|-----------|
| `install-sfetch.sh` | Trust 100 (checksums + minisign) | Trust 25 (HTTPS only) | Trust 25 |
| `install-shellsentry.sh` | Trust 100 (checksums + minisign) | Trust 25 (HTTPS only) | Trust 25 |

**Future direction:** When the same content is accessible via multiple paths, sfetch should prefer the path with the highest trust score. The corpus tracks these overlap cases with notes like "OVERLAP TEST" to validate this behavior.

### HTTP Testing

The corpus includes HTTP-only test sites for verifying sfetch's security defaults:

| Site | Purpose | Tests |
|------|---------|-------|
| `http://neverssl.com` | Captive portal buster | HTTP blocked by default |
| `http://httpforever.com` | Reliably insecure | HTTP allowed with `--allow-http` |
| `http://nossl.sh` | IP echo diagnostic | Both negative and positive cases |

Each HTTP site has two entries:
1. **Negative test** (`expectSuccess: false`) - verifies HTTP is blocked by default
2. **Positive test** (`allowHTTP: true`, `expectSuccess: true`) - verifies `--allow-http` works

### Schema

See `corpus.schema.json` for field definitions:
- Required: `repo`, `tag`, `assetMatch|assetRegex`, `expectedWorkflow`, `expectSuccess`, `tier`
- Optional: `category`, `note`, `pattern`, `allowHTTP`

### Output

Corpus runner output goes to `test-corpus/` (gitignored) or override with `--dest`.
