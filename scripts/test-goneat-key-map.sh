#!/usr/bin/env bash
# Unit tests for the engine goneat minisign pin map (rotation at v0.6.1).
# Never installs goneat. Uses committed public pins only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

ENGINE="${ROOT}/scripts/bootstrap-sfetch-verified.sh"
CUR="${ROOT}/docs/security/fulmenhq-goneat-minisign.pub"
OLD="${ROOT}/docs/security/fulmenhq-goneat-minisign-retired-1.pub"
[ -f "$ENGINE" ] || fail "engine missing"
[ -f "$CUR" ] || fail "current goneat pin missing"
[ -f "$OLD" ] || fail "retired goneat pin missing"
[ ! -e "${ROOT}/.github/keys/fulmenhq-goneat-minisign.pub" ] ||
    fail ".github/keys must not hold the goneat pin"

grep -q 'readonly GONEAT_PREVKEY_MAX="v0.6.0"' "$ENGINE" ||
    fail "GONEAT_PREVKEY_MAX must be v0.6.0"
grep -q 'goneat_minisign_key_file' "$ENGINE" || fail "goneat_minisign_key_file missing"
grep -q -- '--minisign-key "$GONEAT_KEY"' "$ENGINE" ||
    fail "goneat install must pass --minisign-key (no default-key verify)"
pass "engine declares goneat pin map and requires --minisign-key"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sft-goneat-map.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/repo/scripts" "$WORK/repo/docs/security"
cp "$ENGINE" "$WORK/repo/scripts/bootstrap-sfetch-verified.sh"
cp "$CUR" "$WORK/repo/docs/security/fulmenhq-goneat-minisign.pub"
cp "$OLD" "$WORK/repo/docs/security/fulmenhq-goneat-minisign-retired-1.pub"

# Extract the selector and its comparison helpers into a throwaway driver
# living under the fake repo's scripts/ so BASH_SOURCE resolves docs/security.
python3 - "$WORK/repo/scripts/bootstrap-sfetch-verified.sh" "$WORK/repo/scripts/driver.sh" <<'PY'
from pathlib import Path
import sys
src = Path(sys.argv[1]).read_text()
keep = []
for name in (
    "is_exact_semver_tag",
    "_semver_cmp_component",
    "semver_cmp",
    "semver_ge",
    "semver_le",
    "goneat_minisign_key_file",
):
    start = src.find(f"{name}() {{")
    if start < 0:
        raise SystemExit(f"missing {name}")
    depth = 0
    i = src.find("{", start)
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                keep.append(src[start : j + 1])
                break
const_start = src.find('readonly GONEAT_PREVKEY_MAX=')
const_end = src.find("\n", const_start)
const = src[const_start:const_end]
Path(sys.argv[2]).write_text(
    "#!/usr/bin/env bash\nset -euo pipefail\n"
    "die() { echo error: $* >&2; exit 1; }\n"
    "log() { echo \"$*\" >&2; }\n"
    + const
    + "\n"
    + "\n".join(keep)
    + '\ngoneat_minisign_key_file "$1"\n'
)
PY
chmod +x "$WORK/repo/scripts/driver.sh"

select_for() {
    bash "$WORK/repo/scripts/driver.sh" "$1"
}

cur_path="$(select_for v0.6.1)"
old_path="$(select_for v0.6.0)"
[ "$cur_path" = "$WORK/repo/docs/security/fulmenhq-goneat-minisign.pub" ] ||
    fail "v0.6.1 must select current pin (got $cur_path)"
[ "$old_path" = "$WORK/repo/docs/security/fulmenhq-goneat-minisign-retired-1.pub" ] ||
    fail "v0.6.0 must select retired pin (got $old_path)"
[ "$(select_for v0.5.15)" = "$old_path" ] || fail "v0.5.15 must select retired pin"
[ "$(select_for v0.6.6)" = "$cur_path" ] || fail "v0.6.6 must select current pin"
if select_for latest >/dev/null 2>&1; then fail "non-semver goneat tag must be refused"; fi
pass "goneat pin map selects exactly one committed file per tag"

echo "[ok] goneat key-by-version map"
