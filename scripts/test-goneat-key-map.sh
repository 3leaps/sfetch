#!/usr/bin/env bash
# Unit tests for the engine goneat minisign pin map (rotation at v0.6.1).
# Never installs goneat. Literals must equal committed public pins; a
# standalone copy of the script (no docs/security tree) must still select.
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
grep -q 'readonly GONEAT_MINISIGN_PUBKEY=' "$ENGINE" || fail "GONEAT_MINISIGN_PUBKEY literal missing"
grep -q 'readonly GONEAT_MINISIGN_PUBKEY_LEGACY=' "$ENGINE" || fail "GONEAT_MINISIGN_PUBKEY_LEGACY literal missing"
grep -q 'goneat_minisign_key_file' "$ENGINE" || fail "goneat_minisign_key_file missing"
grep -q -- '--minisign-key "$GONEAT_KEY"' "$ENGINE" ||
    fail "goneat install must pass --minisign-key (no default-key verify)"
if sed -n '/^goneat_minisign_key_file()/,/^}/p' "$ENGINE" | grep -q 'fulmenhq-goneat-minisign'; then
    fail "goneat_minisign_key_file must not open the committed pin files"
fi
pass "engine declares goneat pin map and requires --minisign-key"

cur_blob="$(sed -n '2p' "$CUR" | tr -d '\r\n')"
old_blob="$(sed -n '2p' "$OLD" | tr -d '\r\n')"
eng_cur="$(grep -E '^readonly GONEAT_MINISIGN_PUBKEY="' "$ENGINE" | head -n1 | sed 's/^readonly GONEAT_MINISIGN_PUBKEY="//; s/"$//')"
eng_old="$(grep -E '^readonly GONEAT_MINISIGN_PUBKEY_LEGACY="' "$ENGINE" | head -n1 | sed 's/^readonly GONEAT_MINISIGN_PUBKEY_LEGACY="//; s/"$//')"
[ "$eng_cur" = "$cur_blob" ] || fail "GONEAT_MINISIGN_PUBKEY must equal $CUR line 2"
[ "$eng_old" = "$old_blob" ] || fail "GONEAT_MINISIGN_PUBKEY_LEGACY must equal $OLD line 2"
pass "goneat literals equal committed public pins"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sft-goneat-map.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# Standalone copy: only the script, no docs/security tree beside it.
mkdir -p "$WORK/alone"
cp "$ENGINE" "$WORK/alone/bootstrap-sfetch-verified.sh"

python3 - "$WORK/alone/bootstrap-sfetch-verified.sh" "$WORK/alone/driver.sh" <<'PY'
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
consts = []
for prefix in (
    "readonly GONEAT_PREVKEY_MAX=",
    "readonly GONEAT_MINISIGN_PUBKEY=",
    "readonly GONEAT_MINISIGN_PUBKEY_LEGACY=",
):
    start = src.find(prefix)
    if start < 0:
        raise SystemExit(f"missing {prefix}")
    end = src.find("\n", start)
    consts.append(src[start:end])
Path(sys.argv[2]).write_text(
    "#!/usr/bin/env bash\nset -euo pipefail\n"
    "die() { echo error: $* >&2; exit 1; }\n"
    "log() { echo \"$*\" >&2; }\n"
    + "\n".join(consts)
    + "\n"
    + "\n".join(keep)
    + '\npath="$(goneat_minisign_key_file "$1")"\n'
    + 'sed -n 2p "$path"\n'
)
PY
chmod +x "$WORK/alone/driver.sh"

select_blob() {
    bash "$WORK/alone/driver.sh" "$1"
}

[ "$(select_blob v0.6.1)" = "$cur_blob" ] || fail "v0.6.1 must select current pin"
[ "$(select_blob v0.6.0)" = "$old_blob" ] || fail "v0.6.0 must select retired pin"
[ "$(select_blob v0.5.15)" = "$old_blob" ] || fail "v0.5.15 must select retired pin"
[ "$(select_blob v0.6.6)" = "$cur_blob" ] || fail "v0.6.6 must select current pin"
if select_blob latest >/dev/null 2>&1; then fail "non-semver goneat tag must be refused"; fi
pass "standalone goneat pin map selects exactly one literal per tag"

echo "[ok] goneat key-by-version map"
