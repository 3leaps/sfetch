# CI/CD Usage Guide

This guide covers using sfetch in CI/CD environments such as GitHub Actions, GitLab CI, and containerized runners.

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

### Basic usage (recommended)

```yaml
- name: Install sfetch + tool
  run: |
    set -euo pipefail
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"

    # Install sfetch
    curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash -s -- --yes --dir "$BIN_DIR"
    export PATH="$BIN_DIR:$PATH"

    # Install your tool (sfetch handles cross-device automatically)
    sfetch --repo owner/repo --latest --dest-dir "$BIN_DIR" --require-minisign

    # Verify
    tool --version
```

### With explicit version pinning

```yaml
- name: Install tools (pinned versions)
  run: |
    set -euo pipefail
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
    export PATH="$BIN_DIR:$PATH"

    # Install sfetch (pinned; choose the minimum version you require)
    SFETCH_VERSION="v0.2.6"
    curl -sSfL "https://github.com/3leaps/sfetch/releases/download/${SFETCH_VERSION}/install-sfetch.sh" | bash -s -- --yes --dir "$BIN_DIR"

    # Install tool (pinned)
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

For private repos or high-volume CI, set `GITHUB_TOKEN`:
```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## See Also

- [Examples & Pattern Matching](examples.md) - Real-world verification examples
- [Security Documentation](security.md) - Verification workflows explained
- [Key Handling](key-handling.md) - PGP and minisign key configuration
