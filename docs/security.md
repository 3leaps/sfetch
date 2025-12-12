# sfetch Security & Verification Processes

## Scanning & Quality Gates

Run `make prereqs` (or `make bootstrap`) to install Go analysis tools and verify `yamllint` is present before every push. `make precommit` (or `quality`) enforces:

- `prereqs`: installs `staticcheck`/`gosec` and fails fast if `yamllint` is missing (install it via `brew install yamllint`, `sudo apt-get install yamllint`, or `pipx install yamllint`)
- `fmt-check`: `gofmt -l $(git ls-files '*.go')` (fails if formatting is needed; run `make fmt` to auto-fix)
- `lint`: `go vet ./...` + `staticcheck ./...`
- `test`: `go test -v -race ./...`
- `gosec-high`: `gosec -confidence high -exclude G301,G302,G107,G304 ./...` (0 issues HIGH)
- `build-all`: Cross-platform static binaries
- `yamllint-workflows`: `yamllint .github/workflows`

If `make prereqs` fails because `yamllint` is missing, install it manually via `brew install yamllint`, `sudo apt-get install yamllint`, or `pipx install yamllint` so `make precommit` matches CI.

### Gosec Exclusions Rationale

|.gosec.yaml / -exclude| Rule | Why Safe |
|---|---|---|
|G301| mkdir 0755 | tmp/cache/extract controlled (`MkdirTemp`, hash dirs)—no secrets. |
|G302| chmod 0755 | Verified binary +x before user install (`/usr/local/bin` or `--dest-dir`)—executable std. |
|G107| http.Get(url) | GH API `fmt.Sprintf("%s/repos/%s/releases/%s", baseURL, repo, releaseID)` controlled. |
|G304| os.ReadFile/Create | tmp paths (asset/checksum/sig from `MkdirTemp`) controlled. |

Inline `#nosec` comments on 12 sites for line-granular audit.

## Static Analysis Philosophy

- **Prefer stdlib/crypto**: ed25519 native, SHA256/512.
- **No runtime deps**: ~6MB static binary.
- **Preflight**: `--skip-tools-check` optional (tar/unzip req).
- **gpg optional**: `--pgp-key-file` → temp keyring deleted.

## Manual release signing

CI uploads unsigned archives only. Maintainers generate and sign checksum manifests (`SHA256SUMS`, `SHA2-512SUMS`) locally with minisign (primary) and optionally PGP:

```bash
export MINISIGN_KEY=/path/to/key.key
export PGP_KEY_ID=your-key-id  # optional

RELEASE_TAG=v0.2.0 make release-download
RELEASE_TAG=v0.2.0 make release-sign
make release-export-minisign-key
make release-export-key  # if using PGP
RELEASE_TAG=v0.2.0 make release-notes
RELEASE_TAG=v0.2.0 make release-upload
```

Only the checksum manifests are signed (not individual files). Users verify the signature on `SHA256SUMS`/`SHA2-512SUMS`, then verify archive checksums against them. This is standard practice - signing individual files would be redundant.

See [docs/security/signing-runbook.md](security/signing-runbook.md) for detailed workflow.

## Verifying Your Installation

After installing sfetch, you can verify the binary matches the signed release:

```bash
sfetch --self-verify
```

This prints:
- Version and build info compiled into the binary
- Release URLs for SHA256SUMS and signature files
- Expected asset filename and SHA256 hash (fetched from GitHub)
- Platform-specific commands to verify the checksum externally
- Commands to verify the signature with minisign or GPG
- The embedded trust anchor (minisign public key)

**WARNING: A compromised binary could lie. Run these commands yourself.**

The verification commands must be run externally (not by sfetch itself). A binary cannot reliably verify itself.

For machine-readable output:
```bash
sfetch --show-trust-anchors        # plain: minisign:<key>
sfetch --show-trust-anchors --json # JSON with pubkey and keyId
```

## Future

- Fuzz sig/checksum.
- Cosign/Sigstore.

Audit: `make precommit` blocks HIGH; MED reviewed/excluded.
