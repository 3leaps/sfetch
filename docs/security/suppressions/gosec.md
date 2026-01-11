# Gosec Suppression Decisions

This document records Security Decision Records (SDRs) for gosec static analysis suppressions in sfetch.

## SDR-001: CLI File Path Inputs (G304)

**Rule:** G304 - Potential file inclusion via variable
**Severity:** Medium
**Instances:** 7
**Decision:** Suppress with `#nosec G304 -- SDR-001`

### Context

G304 flags `os.ReadFile(path)` and `os.Open(path)` where `path` is a variable, warning of potential path traversal attacks.

### Threat Model Consideration

This rule protects against attacks where:
1. Untrusted remote input becomes a file path
2. The application has higher privileges than the input source
3. Attackers could read sensitive files they shouldn't access

### Why Suppression is Appropriate

sfetch is a CLI tool where:

1. **No privilege escalation**: sfetch runs with the invoking user's permissions. A user who runs `sfetch --minisign-key /etc/shadow` could also run `cat /etc/shadow`.

2. **Local user = trusted input**: Command-line arguments come from a local user with shell access. The "attacker" would need local access, at which point they have equivalent capabilities without sfetch.

3. **Intended functionality**: Reading user-specified files (keys, manifests) is core functionality. Refusing user-specified paths would break the tool.

4. **No network exposure**: These code paths are only reachable from CLI argument parsing, not from network input.

### Affected Locations

| File | Function | Purpose |
|------|----------|---------|
| main.go | ValidateMinisignPubkey | User-specified minisign key file |
| main.go | writeOutput | User-specified output path |
| scripts/run-corpus.go | loadManifest | Test harness loading corpus manifest |
| scripts/cmd/generate-checksums/ | main | Build tool reading release assets |

---

## SDR-002: Directory Permissions (G301)

**Rule:** G301 - Expect directory permissions to be 0750 or less
**Severity:** Medium
**Instances:** 10
**Decision:** Suppress with `#nosec G301 -- SDR-002`

### Context

G301 flags `os.Mkdir` and `os.MkdirAll` with permissions greater than 0750.

### Why Suppression is Appropriate

sfetch creates directories for:

1. **User bin directories** (`~/.local/bin`): Must be 0755 for PATH directories. Other users don't need write access, but the directory must be traversable.

2. **Cache directories** (`~/.cache/sfetch`): Standard cache permissions. No sensitive data stored.

3. **Extraction directories**: Temporary directories for archive extraction. Cleaned up after use.

4. **User-specified destinations**: User controls where files go; 0755 is standard for created directories.

### Security Consideration

0755 means:
- Owner: read, write, execute
- Group: read, execute
- Other: read, execute

This is appropriate because:
- No sensitive data is written to these directories
- Executables placed here need to be runnable
- This matches standard Unix conventions for bin/cache directories

---

## SDR-003: File Permissions (G302)

**Rule:** G302 - Expect file permissions to be 0600 or less
**Severity:** Medium
**Instances:** 6
**Decision:** Suppress with `#nosec G302 -- SDR-003`

### Context

G302 flags `os.Chmod`, `os.WriteFile`, and `os.OpenFile` with permissions greater than 0600.

### Why Suppression is Appropriate

sfetch sets file permissions for:

1. **Executable binaries** (0755): Downloaded/extracted executables must be executable. This is the tool's primary function.

2. **Installer scripts** (0755): Shell scripts need execute permission to run.

3. **Downloaded files** (0644): Non-executable downloads need to be readable by other processes (editors, tools).

### Security Consideration

- 0755 for executables is standard Unix practice
- 0644 for data files allows reading without write access
- No secrets or credentials are written with these permissions
- User explicitly requested the download; permissions match expectations

---

## SDR-004: Archive Extraction (G110)

**Rule:** G110 - Potential DoS vulnerability via decompression bomb
**Severity:** Medium
**Instances:** 1
**Decision:** Suppress with `#nosec G110 -- SDR-004`

### Context

G110 flags `io.Copy` in archive extraction contexts, warning that a malicious archive could expand to exhaust disk space or memory.

### Why Suppression is Appropriate

1. **User-initiated downloads**: The user explicitly chose to download and extract the archive. They've accepted responsibility for the content.

2. **Trust model handles risk**: sfetch's trust scoring (Workflow A/B/C) indicates verification level. Users can make informed decisions.

3. **Size limits would break legitimate use**: Large archives (SDKs, toolchains) are legitimate use cases. Arbitrary limits would reduce utility.

4. **Same risk as curl/wget + tar**: Users downloading archives face this risk regardless of tool. sfetch doesn't introduce new attack surface.

### Mitigation

- Archives are extracted to user-specified or temp directories
- sfetch reports archive size before extraction in verbose mode
- Trust score warns when verification is unavailable

---

## SDR-005: Provenance File Write (G306)

**Rule:** G306 - Expect WriteFile permissions to be 0600 or less
**Severity:** Medium
**Instances:** 1
**Decision:** Suppress with `#nosec G306 -- SDR-005`

### Context

G306 flags `os.WriteFile` with permissions greater than 0600.

### Why Suppression is Appropriate

The provenance file (JSON metadata about a download) is written with 0644 permissions because:

1. **Non-sensitive content**: Provenance records contain public metadata (URLs, checksums, timestamps) - no secrets or credentials.

2. **User-specified output**: The file path comes from `--provenance-to` flag. User controls both location and expects standard file permissions.

3. **Readable by other tools**: Provenance files may be consumed by CI systems, audit tools, or other processes that need read access.

### Affected Location

| File | Function | Purpose |
|------|----------|---------|
| main.go | writeProvenance | User-specified provenance output file |

---

## Suppression Audit Log

| Date | SDR | Action | Author |
|------|-----|--------|--------|
| 2026-01-10 | SDR-001 | Created | Claude Opus 4.5 |
| 2026-01-10 | SDR-002 | Created | Claude Opus 4.5 |
| 2026-01-10 | SDR-003 | Created | Claude Opus 4.5 |
| 2026-01-10 | SDR-004 | Created | Claude Opus 4.5 |
| 2026-01-10 | SDR-005 | Created | Claude Opus 4.5 |
