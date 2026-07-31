# CI/CD Usage Guide

This guide covers using sfetch in CI/CD environments such as GitHub Actions, GitLab CI, and containerized runners.

For repo-level release and workflow rules, also see [CI Guardrails](ci-guardrails.md).

## Automatic Cross-Filesystem Handling

**TL;DR:** sfetch v0.2.6+ handles cross-device installs and caching automatically. No special flags needed.

### Background

In containerized CI environments, `/tmp` and `$HOME` (or other destination directories) are often on different filesystem mounts. When sfetch extracts an asset to `/tmp` and then tries to install it to a destination on a different mount, the `rename(2)` syscall fails with `EXDEV` (cross-device link error):

```
install to /github/home/.local/bin/tool: rename /tmp/sfetch-123/extract/tool /github/home/.local/bin/tool: invalid cross-device link
```

**sfetch v0.2.6+ automatically detects this and falls back to a copy operation.** You don't need to do anything special.

The same class of issue can also affect caching when the cache directory is on a different filesystem than `/tmp`. Newer versions handle that case as well.

### For older versions (< v0.2.6)

If you're stuck on an older version, the workaround is to ensure the temp directory is on the same filesystem as your destination directory. One approach is to set `TMPDIR`:

```bash
export TMPDIR="$HOME/.tmp"
mkdir -p "$TMPDIR"
```

This is fragile and version-dependent—upgrading is recommended.

## GitHub Actions Examples

### Recommended: composite action (v0.4.11+)

Pin the action by **commit SHA** (not a moving tag). The action embeds the
supported `sfetch-version` range for that SHA and fails closed outside it.

```yaml
- uses: 3leaps/sfetch/.github/actions/setup-sfetch@<commit-sha>
  with:
    sfetch-version: v0.4.11          # exact tag; never latest
    goneat-version: v0.5.15          # optional; exact tag if set
  env:
    GITHUB_TOKEN: ${{ github.token }}
    GH_TOKEN: ${{ github.token }}
    SFETCH_GITHUB_TOKEN: ${{ github.token }}

- name: Use sfetch
  run: |
    sfetch --version
    sfetch --repo owner/repo --tag v1.2.3 --dest-dir "$HOME/.local/bin" --require-minisign
```

**Dual-route behavior (logged as `route=minisig` or `route=sha256sums`):**

| `sfetch-version` | Verification |
|------------------|--------------|
| ≥ v0.4.11 | Detached `install-sfetch.sh.minisig` |
| v0.4.9 – v0.4.10 | Signed `SHA256SUMS` + installer hash |
| outside action range / `latest` | **Fail closed** |

Never fall back from a failed `.minisig` attempt to checksums.

**Adoption mode:** link the action by SHA from this repository. Do not copy
`action.yml` into consumer repos (that re-creates the drift the action exists
to eliminate).

### Makefile / shell: shared engine (D2b)

```bash
# Prefer in-repo script when developing sfetch itself:
./scripts/bootstrap-sfetch-verified.sh --version v0.4.11 --dir "$HOME/.local/bin"

# Other repos: fetch at an immutable SHA, verify digest, then execute.
# Replace <sha> and <digest> with values published for the release you trust.
SCRIPT_URL="https://raw.githubusercontent.com/3leaps/sfetch/<sha>/scripts/bootstrap-sfetch-verified.sh"
SCRIPT_SHA256="<digest>"
curl -fsSL "$SCRIPT_URL" -o /tmp/bootstrap-sfetch-verified.sh
echo "${SCRIPT_SHA256}  /tmp/bootstrap-sfetch-verified.sh" | shasum -a 256 -c
bash /tmp/bootstrap-sfetch-verified.sh --version v0.4.11 --dir "$HOME/.local/bin"
```

`latest` is refused by the engine (and by the action). Interactive humans may
still use `install-sfetch.sh` from a pinned tag or, carefully, from `latest`;
CI and Makefile recipes must use exact tags.

### Legacy pipe-to-bash (still works; not recommended)

```yaml
- name: Install sfetch + tool (legacy)
  env:
    GITHUB_TOKEN: ${{ github.token }}
    GH_TOKEN: ${{ github.token }}
    SFETCH_GITHUB_TOKEN: ${{ github.token }}
  run: |
    set -euo pipefail
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"

    # Prefer a pinned tag. Avoid releases/latest in CI.
    SFETCH_VERSION="v0.4.10"
    curl -sSfL "https://github.com/3leaps/sfetch/releases/download/${SFETCH_VERSION}/install-sfetch.sh" \
      | bash -s -- --yes --dir "$BIN_DIR" --tag "$SFETCH_VERSION" --require-minisign
    export PATH="$BIN_DIR:$PATH"

    sfetch --repo owner/repo --tag v1.2.3 --dest-dir "$BIN_DIR" --require-minisign
```

Exporting all three token variables at job or workflow scope keeps `sfetch`, `gh`, and child processes on authenticated GitHub API requests by default.

### With explicit version pinning (legacy installer)

```yaml
- name: Install tools (pinned versions)
  run: |
    set -euo pipefail
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
    export PATH="$BIN_DIR:$PATH"

    SFETCH_VERSION="v0.4.10"
    curl -sSfL "https://github.com/3leaps/sfetch/releases/download/${SFETCH_VERSION}/install-sfetch.sh" \
      | bash -s -- --yes --dir "$BIN_DIR" --tag "$SFETCH_VERSION" --require-minisign

    sfetch --repo owner/repo --tag v1.2.3 --dest-dir "$BIN_DIR" --require-minisign
```

### Container jobs

When running in a container (e.g., with `container:` in GitHub Actions), the same approach works:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: golang:1.23
    steps:
      - uses: actions/checkout@v4
      - name: Install tools
        run: |
          BIN_DIR="$HOME/.local/bin"
          mkdir -p "$BIN_DIR"
          curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash -s -- --yes --dir "$BIN_DIR"
          export PATH="$BIN_DIR:$PATH"
          sfetch --repo owner/repo --latest --dest-dir "$BIN_DIR"
```

### Non-root container users

Some container images run as a non-root user by default (e.g., UID 1001). When using GitHub Actions with such containers, you may need to specify the user to match workspace ownership:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/your-org/your-tools:v1.0
      # Match the GitHub-hosted runner workspace ownership (UID 1001)
      options: --user 1001
    steps:
      - uses: actions/checkout@v4
      - name: Install tools
        run: |
          BIN_DIR="$HOME/.local/bin"
          mkdir -p "$BIN_DIR"
          curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash -s -- --yes --dir "$BIN_DIR"
          export PATH="$BIN_DIR:$PATH"
          sfetch --repo owner/repo --latest --dest-dir "$BIN_DIR"
```

If you need to install system packages (e.g., `apt-get install`), you may temporarily need root access:

```yaml
container:
  image: ghcr.io/your-org/your-tools:v1.0
  # Run as root to install packages; consider baking dependencies into the image instead
  options: --user 0
```

**Best practice:** Bake required tools (like `minisign`) into your container image rather than installing at runtime. This improves build speed and avoids permission issues.

### Shell compatibility in containers

Some minimal container images (e.g., `ubuntu:24.04`) use `/bin/sh` as the default shell, which may not support bash-specific features like `pipefail`. If you use `set -euo pipefail`, explicitly specify bash:

```yaml
- name: Install tools
  shell: bash
  run: |
    set -euo pipefail
    # ... your commands
```

Or use POSIX-compatible options only:

```yaml
- name: Install tools
  run: |
    set -eu
    # ... your commands
```

## GitLab CI Example

```yaml
install-tools:
  image: golang:1.23
  script:
    - BIN_DIR="$HOME/.local/bin"
    - mkdir -p "$BIN_DIR"
    - curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash -s -- --yes --dir "$BIN_DIR"
    - export PATH="$BIN_DIR:$PATH"
    - sfetch --repo owner/repo --latest --dest-dir "$BIN_DIR" --require-minisign
```

## Cache Directory

sfetch caches downloaded assets to avoid re-downloading on repeated runs. The default location is `~/.cache/sfetch` (or `$XDG_CACHE_HOME/sfetch`).

In CI, you can:

1. **Let it use the default** - assets are cached per-job but not across jobs
2. **Use `--cache-dir`** to specify a persistent cache location
3. **Use GitHub Actions cache** to persist across runs:

```yaml
- name: Cache sfetch downloads
  uses: actions/cache@v4
  with:
    path: ~/.cache/sfetch
    key: sfetch-${{ runner.os }}-${{ hashFiles('.tool-versions') }}

- name: Install tools
  run: |
    # ... sfetch commands will use the cached downloads
```

## Verification in CI

For security-conscious CI pipelines, always use verification flags:

```bash
# Require minisign signature (fail if unavailable)
sfetch --repo owner/repo --latest --require-minisign --dest-dir "$BIN_DIR"

# Verify after install
sfetch --self-verify
```

## Troubleshooting

### "invalid cross-device link" error

Upgrade to sfetch v0.2.6+. This error is automatically handled in newer versions.

### "permission denied" errors

Ensure the destination directory exists and is writable:
```bash
mkdir -p "$BIN_DIR"
```

If the installed binary exists but won’t execute (exit 126), check:

- File mode: `ls -l "$BIN_DIR/tool"` should show it as executable (e.g. `-rwxr-xr-x`). If not, upgrade to sfetch v0.2.6+ (copy-based fallbacks preserve executable permissions).
- Mount options: some container environments mount destinations with `noexec`, which prevents execution even if the file mode is `+x`. In that case, choose a different `--dest-dir` on an executable filesystem.

### Signature verification failures

- Check that the release has the expected signature files
- Use `--dry-run` to inspect what verification is available:
  ```bash
  sfetch --repo owner/repo --latest --dry-run
  ```

### Rate limiting

For high-volume CI (or GitHub-hosted runners that share egress IPs), set `GITHUB_TOKEN` (or `SFETCH_GITHUB_TOKEN`) so the installer and sfetch can authenticate GitHub API requests and avoid 403 rate limits:
```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Private repositories (cross-repo downloads)

The default `${{ github.token }}` GITHUB_TOKEN is scoped to the workflow's
own repository — it cannot read another private repo's release assets. To
fetch from a different private repo, set a scoped PAT and point sfetch at
its env-var name with `--token-env`:

```yaml
- name: Install private-org tool
  env:
    PRIVATE_REPO_PAT: ${{ secrets.PRIVATE_REPO_PAT }}
  run: |
    sfetch --repo myorg/private-tool --latest \
           --asset-match linux-amd64 \
           --dest-dir "$HOME/.local/bin" \
           --token-env PRIVATE_REPO_PAT
```

`--token-env` overrides the default `SFETCH_GITHUB_TOKEN` → `GH_TOKEN` →
`GITHUB_TOKEN` chain. If the named env var is unset or empty, sfetch fails
loudly rather than silently falling back to a wrong-scope token. sfetch
never accepts the token value on the command line — that would land in CI
logs whenever `set -x` is in effect.

See [security.md](security.md#github-authentication-v046) for the full
precedence model.

## See Also

- [Examples & Pattern Matching](examples.md) - Real-world verification examples
- [Security Documentation](security.md) - Verification workflows explained
- [Key Handling](key-handling.md) - PGP and minisign key configuration

## Minisign provenance (verifier pin)

`minisign` is part of the trust-critical path. The verified bootstrap engine
installs or asserts **minisign 0.12** from official jedisct1 release archives
(hash-pinned before extract):

| Platform | Artifact | SHA-256 |
|----------|----------|---------|
| Windows x64 / arm64 | `minisign-0.12-win64.zip` | `37b600344e20c19314b2e82813db2bfdcc408b77b876f7727889dbd46d539479` |
| macOS arm64 | `minisign-0.12-macos.zip` | `89000b19535765f9cffc65a65d64a820f433ef6db8020667f7570e06bf6aac63` |
| Linux x86_64 / aarch64 | `minisign-0.12-linux.tar.gz` | `9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73` |

Windows maps `RUNNER_ARCH` X64 → `x86_64`, ARM64 → `aarch64`. **macOS Intel is
not supported** by the upstream 0.12 macOS archive (arm64-only) and fails
closed unless an ambient minisign 0.12 is already on PATH.

Do **not** use Chocolatey/winget community packages for the verified bootstrap
path. Distro packages (apt/brew) are acceptable only when the binary reports
exactly version 0.12 (the engine re-asserts identity after acquisition).

## Incomplete release window

Between tag CI (draft + unsigned installer upload) and maintainer
`make release-upload` + publish, a release is **non-consumable** for verified
bootstrap. Consumers must not treat draft assets or an unsigned installer as a
trust anchor. Prefer exact tags over `latest` so you never race that window.
