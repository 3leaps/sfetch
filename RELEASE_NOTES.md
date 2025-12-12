# Release Notes

## v0.2.2

### Summary
Smart asset selection (Phase 1) eliminates the need for `--asset-match` or `--asset-regex` for most repos, plus expanded checksum discovery for non-standard naming patterns.

### Highlights

**Smart Asset Selection**

No more tie-breaking errors! sfetch now automatically selects the right asset:

```bash
# Before v0.2.2: Failed with "multiple assets tie"
sfetch --repo yt-dlp/yt-dlp --latest --dest-dir ~/bin

# After v0.2.2: Just works
sfetch --repo yt-dlp/yt-dlp --latest --dest-dir ~/bin
# → Selects yt-dlp_macos automatically
```

How it works:
- **Platform exclusions:** `.exe` filtered out on darwin/linux
- **Case-insensitive matching:** `macOS`, `Darwin`, `MACOS` all match
- **Raw-over-archive:** Prefers `yt-dlp_macos` over `yt-dlp_macos.zip`
- **Schema-validated rules:** Extensible via `inference-rules.json`

**Checksum Pattern Expansion**
- Added `SHA2-256SUMS`, `SHA2-512SUMS`, `SHA512SUMS` patterns
- Signature variants: `.minisig`, `.asc`, `.sig` for all checksum files
- Supports yt-dlp and similar repos without `--insecure`

**Heuristic `.sig` Handling**
```
SHA2-256SUMS.sig  → GPG (checksum-level)
binary.tar.gz.sig → ed25519 (per-asset)
```

**Dual-Hash Release Signing**
- Releases now include both `SHA256SUMS` and `SHA2-512SUMS`
- Both signed with minisign and PGP

**Secure Self-Update**
```bash
# Update to latest release
sfetch --self-update --yes

# Update to specific version
sfetch --self-update --tag v0.2.1 --yes

# Force major version jump
sfetch --self-update --self-update-force --yes

# Dry run to see what would happen
sfetch --self-update --dry-run
```

Security-first design:
- Uses existing verification pipeline (no insecure path)
- Major-version guard prevents accidental breaking changes
- Windows lock handling with `.new` fallback
- Custom install directory support

### Proof Points

| Repo | Before | After |
|------|--------|-------|
| yt-dlp/yt-dlp | Tie: `yt-dlp` vs `yt-dlp.exe` | `yt-dlp_macos` |
| cli/cli | Tie: case mismatch | `gh_*_macOS_arm64.zip` |

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

### Details
- See `CHANGELOG.md` for the complete list.
- Inference rules schema: `schemas/inference-rules.schema.json`

---

## v0.2.1

### Summary
Self-verify instructions and trust anchors for installed binaries, plus an opt-in real-world corpus runner and expanded checksum pattern coverage.

### Highlights

**Self-verify & trust anchors**
```bash
sfetch --self-verify
sfetch --show-trust-anchors           # plain
sfetch --show-trust-anchors --json    # JSON
```
- Prints deterministic release URLs, expected asset/hash (with offline fallback), platform-specific checksum commands, minisign/PGP commands, embedded minisign pubkey, and a warning that a compromised binary could lie. Dev builds print “no published checksums.”
- Installer now logs: `To verify this installation later: sfetch --self-verify`.
- Docs updated: README verification section; docs/security “Verifying Your Installation”.

**Real-world corpus (opt-in)**
- Manifest + runner (`scripts/run-corpus.go`, `testdata/corpus.json`, schema at `testdata/corpus.schema.json`).
- Make targets: `make corpus` (fast, dry-run), `make corpus-all` (includes slow), `make corpus-dryrun` (dry-run helper). Default destination: `test-corpus/` (gitignored); override via `CORPUS_DEST`.
- Docs: `docs/examples.md` corpus section; guidance in `docs/test-corpus/README.md`.
- Requires network; set `GITHUB_TOKEN` if rate limited.

**Checksum discovery expansion**
- Added version-aware templates and additional defaults (`sha256sum.txt`, `SHA256SUMS_64`, `{{binary}}_{{versionNoPrefix}}_checksums.txt`, etc.) to improve checksum detection in the corpus.

### Notes
- Corpus runner is opt-in and not part of default CI; intended for release prep and manual validation.

---

## v0.2.0

### Summary
Major feature release: verification assessment, provenance records, checksum-only workflow support, asset classification/raw installs, and adoption of Semantic Versioning.

This release makes sfetch work with the majority of GitHub releases, even those without signatures. It also adds structured provenance output for audit trails and CI integration, and now handles installer scripts/standalone binaries without extraction.

### Highlights

**Verification Assessment (`--dry-run`)**
```bash
$ sfetch --repo BurntSushi/ripgrep --latest --dry-run

sfetch dry-run assessment
-------------------------
Repository:  BurntSushi/ripgrep
Release:     15.1.0
Asset:       ripgrep-15.1.0-aarch64-apple-darwin.tar.gz (1.7 MB)

Verification available:
  Signature:  none
  Checksum:   ripgrep-15.1.0-aarch64-apple-darwin.tar.gz.sha256 (sha256, per-asset)

Verification plan:
  Workflow:   C (checksum-only)
  Trust:      low

Warnings:
  - No signature available; authenticity cannot be proven
```

**Provenance Records (`--provenance`)**
```bash
# Output JSON provenance to stderr
sfetch --repo 3leaps/sfetch --latest --dest-dir /tmp --provenance

# Write provenance to file
sfetch --repo 3leaps/sfetch --latest --dest-dir /tmp --provenance-file audit.json
```

**Checksum-Only Workflow (Workflow C)**
- Supports repos like `ripgrep`, `fzf`, `lazygit` that have checksums but no signatures.
- Per-asset checksums (`.sha256`) and consolidated (`checksums.txt`, `SHA256SUMS`).
- Warns that authenticity cannot be proven without signature.

**Asset Type Classification & Raw Installs**
- New `AssetType`/`ArchiveFormat` (schema + CLI) with expanded archive defaults.
- Raw scripts and standalone binaries skip extraction; chmod on macOS/Linux.
- Package installers (`.deb/.rpm/.pkg/.msi`) are tagged and downloaded with warnings; sfetch does not run package managers.
- User-friendly selection: `--asset-match` (glob/substring) plus `--asset-regex` for advanced regex.

**Minisign Key Safety**
```bash
# Validate a file is a PUBLIC key (not accidentally a secret key)
sfetch --verify-minisign-pubkey /path/to/key.pub
```

### New Flags

| Flag | Description |
|------|-------------|
| `--asset-match` | Glob/substring asset selection |
| `--asset-regex` | Regex asset selection (advanced) |
| `--asset-type` | Force handling as archive/raw/package |
| `--dry-run` | Assess verification without downloading |
| `--provenance` | Output provenance JSON to stderr |
| `--provenance-file <path>` | Write provenance to file |
| `--skip-checksum` | Skip checksum verification |
| `--insecure` | Skip ALL verification (dangerous) |
| `--minisign-key-url <url>` | Download minisign key from URL |
| `--minisign-key-asset <name>` | Use minisign key from release asset |
| `--require-minisign` | Fail if minisign not available |
| `--prefer-per-asset` | Force per-asset signature workflow |
| `--binary-name <name>` | Override inferred binary name |
| `--verify-minisign-pubkey <path>` | Validate minisign public key file |

### Trust Levels

| Level | Criteria | Example |
|-------|----------|---------|
| high | Signature + checksum verified | 3leaps/sfetch |
| medium | Signature verified, no checksum | jedisct1/minisign |
| low | Checksum only, no signature | BurntSushi/ripgrep |
| none | No verification (`--insecure`) | - |

### Install

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
```

### Versioning Change

This release adopts [Semantic Versioning](https://semver.org/). Previous CalVer releases are mapped as:
- `v2025.12.05` → `v0.1.0`
- `v2025.12.06.1` → `v0.1.1`

See [ADR-0001](docs/adr/adr-0001-semver-versioning.md) for details.

### Details
- See `CHANGELOG.md` for the complete list.
- Release notes: `docs/releases/v0.2.0.md`
- Provenance schema: `schemas/provenance.schema.json`
