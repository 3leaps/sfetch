## v0.3.4

### Summary
Proxy support for HTTP(S) downloads with CLI flags and env overrides.

### Highlights

**Proxy support**
- Environment variables: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (case-insensitive)
- CLI flags override env: `--http-proxy`, `--https-proxy`, `--no-proxy`
- `NO_PROXY` bypass for host/domain matches
- All network fetches (releases, keys, checksums) honor proxy settings

**Validation coverage**
- Added tests for proxy URL validation and env override behavior

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

## v0.3.3

### Summary
Local agent role catalog and operating model guidance for supervised sessions.

### Highlights
- Added `docs/agent-roles.md` for offline role guidance
- Clarified default role and operating model in `AGENTS.md`

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

## v0.3.2

### Summary
stdout/stderr convention fix and comprehensive test coverage improvements.

### Highlights

**stdout/stderr convention**
- All human-readable output now goes to stderr; stdout reserved for JSON only.
- Enables clean piping: `sfetch --dry-run --json 2>/dev/null | jq .trust`
- Affected flags: `--version`, `--version-extended`, `--self-verify`, `--show-trust-anchors`, `--dry-run`, `--helpextended`

**Test coverage expansion**
- Main package coverage: 39% -> 54%
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
