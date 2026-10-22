#!/usr/bin/env bash
# Public keys stage from git cat-file of the tagged commit, byte-exact.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
repo="$scratch/repo"
git init -q -b main "$repo"
git -C "$repo" config user.name Fixture
git -C "$repo" config user.email fixture@example.invalid
git -C "$repo" config commit.gpgsign false
mkdir -p "$repo/docs/security" "$repo/scripts" "$scratch/dest"
printf 'untrusted comment: fixture minisign\nRWTfixturekeyblobAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' \
	>"$repo/docs/security/sfetch-minisign.pub"
cat >"$repo/docs/security/release-signing-keys.asc" <<'ASC'
-----BEGIN PGP PUBLIC KEY BLOCK-----

fixture
-----END PGP PUBLIC KEY BLOCK-----
ASC
cp "$root/scripts/release-stage-tagged-pubkeys.sh" "$repo/scripts/"
git -C "$repo" add docs/security scripts
git -C "$repo" commit -qm fixture
git -C "$repo" tag -am 'v1.2.3' v1.2.3
(cd "$repo" && ./scripts/release-stage-tagged-pubkeys.sh v1.2.3 "$scratch/dest")
cmp -s "$repo/docs/security/sfetch-minisign.pub" "$scratch/dest/sfetch-minisign.pub"
cmp -s "$repo/docs/security/release-signing-keys.asc" "$scratch/dest/sfetch-release-signing-key.asc"
# A later working-tree edit must not change what a retag of the same name would
# stage: the command reads the tagged blob, not the dirty tree.
printf 'untrusted comment: dirty working tree\nRWTfixturekeyblobAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' \
	>"$repo/docs/security/sfetch-minisign.pub"
(cd "$repo" && ./scripts/release-stage-tagged-pubkeys.sh v1.2.3 "$scratch/dest")
git -C "$repo" show v1.2.3:docs/security/sfetch-minisign.pub >"$scratch/tagged.pub"
cmp -s "$scratch/tagged.pub" "$scratch/dest/sfetch-minisign.pub" || {
	echo 'error: staging followed the dirty working tree' >&2
	exit 1
}
echo '[ok] public keys stage byte-exact from the tagged commit'
