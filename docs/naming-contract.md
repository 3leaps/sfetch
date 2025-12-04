# sfetch Asset Naming Contract

sfetch auto-detects the correct artifact, checksum, and signature files from a GitHub release. Detection is intentionally lightweight, but predictable naming keeps the experience reliable for both internal and external repos.

## Artifact naming

- Primary artifacts **should include the binary name, GOOS, and GOARCH** using either `_` or `-` separators, for example `sfetch_Darwin_arm64.tar.gz` or `sfetch-linux-amd64.zip`.
- GOOS tokens are matched case-insensitively and accept common aliases:
  - `darwin`: also matches `macos`, `macosx`, `osx`
  - `windows`: also matches `win`, `win32`, `win64`, `mingw`
  - `linux`: already canonical
- GOARCH tokens are also matched case-insensitively with common aliases:
  - `amd64`: matches `x86_64`, `x64`
  - `arm64`: matches `aarch64`
  - `386`: matches `x86`, `i386`, `i686`
- Additional repos can supply custom regex patterns via `RepoConfig.AssetPatterns` when their naming differs (for example, JVM or Python artifacts).

## Checksum & signature files

- When possible, publish one checksum and one signature per artifact, using either of the following templates (sfetch tries these first):
  - `{{asset}}.sha256`, `{{asset}}.sha256.txt`, `{{base}}.sha256`
  - `{{asset}}.sig`, `{{asset}}.sig.ed25519`, `{{base}}.sig`, `{{asset}}.asc`
- `{{asset}}` resolves to the exact artifact filename and `{{base}}` strips the archive extension (`.tar.gz`, `.tgz`, `.zip`).
- Aggregate checksum files such as `SHA256SUMS` or `SHA256SUMS.txt` are supported as long as they contain standard `<hash>  <filename>` lines.
- Signature files may contain either raw 64-byte ed25519 data, a hex-encoded signature (newline-terminated text file), or an ASCII-armored PGP signature (`.asc`).

## Customization roadmap

- All defaults live in `main.go` under `repoConfigs`. When we eventually externalize config, the same structure will be serialized so user-defined naming patterns remain stable.
- Repos with non-standard packaging (e.g., `.pkg`, `.msi`, source tarballs) should define explicit asset, checksum, and signature templates so we never guess incorrectly.
