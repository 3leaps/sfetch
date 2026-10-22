#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
if grep -Eq '^[^#]*git ls-remote' "$root/scripts/release-restore-tag-ref.sh"; then
	echo 'error: restore-tag-ref must not use anonymous git ls-remote' >&2
	exit 1
fi
grep -q 'gh api' "$root/scripts/release-restore-tag-ref.sh" || {
	echo 'error: restore-tag-ref must read the tag object via the job-token API' >&2
	exit 1
}
git init -q --bare "$scratch/remote.git"
git init -q -b main "$scratch/source"
git -C "$scratch/source" config user.name 'Fixture Author'
git -C "$scratch/source" config user.email 'fixture@example.invalid'
git -C "$scratch/source" config commit.gpgsign false
mkdir -p "$scratch/bin"
cat >"$scratch/bin/gh" <<'SH'
#!/usr/bin/env bash
jq_filter=""
path=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	--jq)
		jq_filter="$2"
		shift 2
		;;
	api)
		shift
		;;
	*)
		path="$1"
		shift
		;;
	esac
done
[[ "$path" == repos/3leaps/sfetch/git/ref/tags/* ]] || exit 1
tag="${path##*/git/ref/tags/}"
sha="$(git -C "$FIXTURE_REMOTE" rev-parse "refs/tags/$tag" 2>/dev/null)" || exit 1
typ="$(git -C "$FIXTURE_REMOTE" cat-file -t "$sha")"
body="$(printf '{"object":{"sha":"%s","type":"%s"}}' "$sha" "$typ")"
if [[ -n "$jq_filter" ]]; then
	jq -r "$jq_filter" <<<"$body"
else
	printf '%s\n' "$body"
fi
SH
chmod +x "$scratch/bin/gh"
export PATH="$scratch/bin:$PATH" FIXTURE_REMOTE="$scratch/remote.git"
printf 'fixture\n' >"$scratch/source/file"
printf '1.2.3\n' >"$scratch/source/VERSION"
cp "$root/scripts/release-guard-tag-version.sh" "$scratch/source/guard.sh"
git -C "$scratch/source" add file VERSION guard.sh
git -C "$scratch/source" commit -qm 'fixture commit'
git -C "$scratch/source" tag -am 'Fixture release' v1.2.3
commit="$(git -C "$scratch/source" rev-parse HEAD)"
object="$(git -C "$scratch/source" rev-parse refs/tags/v1.2.3)"
git -C "$scratch/source" remote add origin "$scratch/remote.git"
git -C "$scratch/source" push -q origin main refs/tags/v1.2.3
git clone -q "$scratch/remote.git" "$scratch/checkout"
git -C "$scratch/checkout" checkout -q --detach "$commit"
git -C "$scratch/checkout" fetch -q --no-tags origin "+$commit:refs/tags/v1.2.3"
[[ "$(git -C "$scratch/checkout" cat-file -t refs/tags/v1.2.3)" == commit ]]
(
	cd "$scratch/checkout"
	git remote set-url origin https://github.com/3leaps/sfetch.git
	# Redirect only the fixture's read/fetch transport, not the identity check.
	git config url."$scratch/remote.git".insteadOf https://github.com/3leaps/sfetch.git
	if SFETCH_RELEASE_TAG=v1.2.3 SFETCH_REQUIRE_TAG=1 bash ./guard.sh >/dev/null 2>&1; then
		echo 'error: strict guard accepted checkout peeled-ref rewrite' >&2
		exit 1
	fi
	SFETCH_RELEASE_TAG=v1.2.3 bash "$root/scripts/release-restore-tag-ref.sh" >/dev/null
	[[ "$(git rev-parse refs/tags/v1.2.3)" == "$object" ]]
	[[ "$(git cat-file -t refs/tags/v1.2.3)" == tag ]]
	SFETCH_RELEASE_TAG=v1.2.3 SFETCH_REQUIRE_TAG=1 bash ./guard.sh >/dev/null
	if SFETCH_RELEASE_TAG=v1.2.4 bash "$root/scripts/release-restore-tag-ref.sh" >/dev/null 2>&1; then
		echo 'error: absent tag was accepted' >&2
		exit 1
	fi
)
git -C "$scratch/source" tag -fa -m 'Different signature fixture' v1.2.3
git -C "$scratch/source" push -q --force origin refs/tags/v1.2.3
(
	cd "$scratch/checkout"
	if SFETCH_RELEASE_TAG=v1.2.3 SFETCH_EXPECTED_TAG_OBJECT="$object" \
		bash "$root/scripts/release-restore-tag-ref.sh" >/dev/null 2>&1; then
		echo 'error: different annotated object for same commit was accepted' >&2
		exit 1
	fi
	[[ "$(git rev-parse refs/tags/v1.2.3)" == "$object" ]]
)
git -C "$scratch/remote.git" update-ref refs/tags/v1.2.3 "$commit"
(
	cd "$scratch/checkout"
	if SFETCH_RELEASE_TAG=v1.2.3 bash "$root/scripts/release-restore-tag-ref.sh" >/dev/null 2>&1; then
		echo 'error: non-annotated remote tag was accepted' >&2
		exit 1
	fi
)
printf 'changed\n' >>"$scratch/source/file"
git -C "$scratch/source" add file
git -C "$scratch/source" commit -qm 'another fixture commit'
git -C "$scratch/source" tag -fa -m 'Other fixture release' v1.2.3
git -C "$scratch/source" push -q --force origin refs/tags/v1.2.3
(
	cd "$scratch/checkout"
	if SFETCH_RELEASE_TAG=v1.2.3 bash "$root/scripts/release-restore-tag-ref.sh" >/dev/null 2>&1; then
		echo 'error: remote tag targeting another commit was accepted' >&2
		exit 1
	fi
)
echo '[ok] checkout peeled-ref repair and remote negative controls passed'
