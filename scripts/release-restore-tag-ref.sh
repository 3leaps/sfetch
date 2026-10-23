#!/usr/bin/env bash
# Restore the remote annotated tag ref after actions/checkout peels it locally.
# The remote object is read with a job-token GitHub API call, not anonymous
# `git ls-remote`.
set -euo pipefail

tag="${SFETCH_RELEASE_TAG:-}"
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
	echo 'error: canonical release tag required' >&2
	exit 1
}
# shellcheck source=scripts/release-origin.sh
source "$(cd "$(dirname "$0")" && pwd -P)/release-origin.sh"
require_sfetch_github_origin || {
	echo 'error: unexpected release origin' >&2
	exit 1
}
command -v gh >/dev/null 2>&1 || {
	echo 'error: gh (GitHub CLI) is required to read the tag object' >&2
	exit 1
}
if ! remote_meta="$(gh api "repos/3leaps/sfetch/git/ref/tags/${tag}" --jq '[.object.sha,.object.type]|@tsv')"; then
	echo 'error: remote release tag is absent' >&2
	exit 1
fi
remote_object="${remote_meta%%$'\t'*}"
remote_type="${remote_meta#*$'\t'}"
[[ "$remote_object" =~ ^[0-9a-f]{40}$ ]] || {
	echo 'error: remote tag object is invalid' >&2
	exit 1
}
[[ "$remote_type" == tag ]] || {
	echo 'error: remote tag is not annotated' >&2
	exit 1
}
if [[ -n "${SFETCH_EXPECTED_TAG_OBJECT+x}" ]]; then
	[[ "$SFETCH_EXPECTED_TAG_OBJECT" =~ ^[0-9a-f]{40}$ &&
		"$remote_object" == "$SFETCH_EXPECTED_TAG_OBJECT" ]] || {
		echo 'error: remote tag object differs from validated object' >&2
		exit 1
	}
fi
# This fetch changes only the runner-local ref. The existing strict guard and
# pinned-signature job separately verify the object, target, and signer.
git fetch --quiet --no-tags origin "+refs/tags/$tag:refs/tags/$tag"
[[ "$(git rev-parse "refs/tags/$tag")" == "$remote_object" &&
"$(git cat-file -t "refs/tags/$tag")" == tag &&
"$(git rev-parse "refs/tags/$tag^{}")" == "$(git rev-parse HEAD)" ]] || {
	echo 'error: runner-local tag is not the remote annotated tag at HEAD' >&2
	exit 1
}
echo "[ok] runner-local annotated tag restored for $tag"
