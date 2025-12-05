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

CI uploads unsigned archives and individual SHA256 digests. Maintainers:

1. `RELEASE_TAG=v2025.12.05 make release-download`
2. `PGP_KEY_ID=security@fulmenhq.dev RELEASE_TAG=v2025.12.05 make release-sign`
3. Export the matching public key into `dist/release/sfetch-release-signing-key.asc`
4. `make verify-release-key`
5. `RELEASE_TAG=v2025.12.05 make release-notes`
6. `RELEASE_TAG=v2025.12.05 make release-upload`

These targets call the helper scripts in `scripts/` (requires `gh` CLI + `gpg`). Adjust `RELEASE_TAG`/`PGP_KEY_ID` to match the release you’re publishing.

## Future

- Pure-Go PGP (no gpg).
- Fuzz sig/checksum.
- Cosign/Sigstore.

Audit: `make precommit` blocks HIGH; MED reviewed/excluded.