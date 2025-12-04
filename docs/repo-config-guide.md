---
title: "sfetch RepoConfig User Guide"
description: "Explains how sfetch discovers artifacts, checksums, and signatures and how to override the defaults."
author: "Schema Cartographer"
author_of_record: "Dave Thompson (https://github.com/3leapsdave)"
supervised_by: "@3leapsdave"
date: "2025-12-03"
last_updated: "2025-12-03"
status: "draft"
tags: ["docs", "configuration", "sfetch"]
---

# RepoConfig user guide

This guide explains how sfetch chooses release artifacts, checksum files, and signature files, and how to customize those rules with `RepoConfig`. Pair this document with `docs/naming-contract.md` if you are producing release assets.

## Quick start

- Most repositories can rely on the built-in defaults (Go-style archives named like `tool_GOOS_GOARCH.tar.gz` plus `*.sha256` and `*.sig` companions).
- To customize selection for a repo you control, add/modify an entry in the `repoConfigs` map inside `main.go`.
- Keep the struct stable today; later we will support loading external config files that mirror the same schema.

## Config locations

| Layer | Description |
| --- | --- |
| Built-in defaults | Defined in `main.go` as `var defaults RepoConfig`. Applied to every repo unless overridden. |
| repoConfigs map | `map[string]RepoConfig` keyed by `owner/name`. These entries override any default field. |
| Future external file *(planned)* | Will serialize the same struct (YAML/JSON) and merge on top of the compiled map. |

## Field reference

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `BinaryName` | string | Name of the executable inside the archive. | `sfetch` |
| `HashAlgo` | string | Hash algorithm required in checksum files (`sha256` or `sha512`). | `sha256` |
| `ArchiveType` | string | Hint for extraction command (`tar.gz` or `zip`). | `tar.gz` |
| `ArchiveExtensions` | []string | File extensions stripped before generating `{{base}}`. | `.tar.gz`, `.tgz`, `.zip` |
| `AssetPatterns` | []string | Ordered regex templates used before heuristics. | See defaults below |
| `ChecksumCandidates` | []string | Ordered filename templates for checksum assets. | `{{asset}}.sha256`, etc. |
| `SignatureCandidates` | []string | Ordered filename templates for signature assets. | `{{asset}}.sig`, etc. |

## Pattern template tokens

Use the following tokens inside `AssetPatterns`, `ChecksumCandidates`, or `SignatureCandidates`:

- `{{binary}}`: The configured binary name.
- `{{asset}}`: Full asset filename including extension.
- `{{base}}`: Asset filename minus any known archive extension.
- `{{osToken}}` / `{{archToken}}`: Regex alternations that match all known aliases for the active GOOS/GOARCH.
- `{{goos}}`, `{{GOOS}}`, `{{Goos}}`: Case variants of the current GOOS literal.
- `{{goarch}}`, `{{GOARCH}}`, `{{Goarch}}`: Case variants of the current GOARCH literal.

Example pattern: `(?i)^{{binary}}[-_]{{osToken}}[-_]{{archToken}}.*` matches `sfetch_Darwin_arm64.tgz` and `sfetch-linux-amd64.tar.gz` alike.

## Supplemental asset discovery

1. **Template pass** – We render `ChecksumCandidates` and `SignatureCandidates` using the template context above. The first filename that exists in the release wins.
2. **Keyword fallback** – If templates miss, we look for filenames containing keyword bundles (e.g., `<basename> + sha`, `sha256sum`, `checksum`, or `<basename> + sig`). This allows aggregate files like `SHA256SUMS`.
3. **Parsing expectations** –
   - Checksum files may contain raw hex or standard `<hash>  filename` lines. Only entries matching the selected asset are used.
   - Signature files may contain raw 64-byte ed25519 data or hex-encoded signatures. Other encodings are rejected for now.

## Heuristics for non-Go assets

If no pattern matches, sfetch assigns a score to every asset:

- +4 when the filename contains any GOOS alias (e.g., `macos`, `osx` for `darwin`).
- +4 when it contains any GOARCH alias (e.g., `x86_64` for `amd64`).
- +3 when it contains the binary name.
- +2 when it uses a known extension. 

The asset with the highest score wins, unless there is a tie (which results in an error). This allows Python wheels, installers, or other packaging formats, as long as they include platform cues.

## Customizing for your repo

1. **Add an entry** in `repoConfigs` with your `owner/repo` key.
2. **Set `AssetPatterns`** to match your canonical filenames. Keep patterns specific enough to avoid collisions.
3. **Override supplemental templates** if your checksums or signatures follow fixed names (e.g., `CHECKSUMS.txt`).
4. **Document the naming** by updating `docs/naming-contract.md` if you are changing expectations for everyone.

## Change tracking

- Update the frontmatter `last_updated` field when you tweak defaults or add new examples.
- When the config schema changes (new fields, renamed fields), bump the document `status` to `review` and call it out in the repository CHANGELOG so downstream consumers can adjust.

## Looking ahead

- External config files will mirror this struct exactly. Treat today’s fields as the public API.
- Schema validation will likely remain lightweight (e.g., compile regexes, ensure strings are non-empty) to avoid runtime bloat.
- When we introduce user-editable configs, we will provide a `sfetch config lint` helper plus migration guidance.
