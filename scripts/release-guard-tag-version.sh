#!/usr/bin/env bash
# Validate the sole release tag input and, in strict mode, bind it to origin/main.

set -euo pipefail
# shellcheck source=scripts/release-origin.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/release-origin.sh"

main() {
	local root version expected tag require_tag
	root="$(git rev-parse --show-toplevel)"
	cd "$root"

	if [[ -n "${RELEASE_TAG+x}" || -n "${SFETCH_RELEASE_KEY+x}" ]]; then
		echo "error: generic or legacy release tag aliases are forbidden" >&2
		exit 1
	fi

	version="$(cat VERSION)"
	if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
		echo "error: VERSION must contain one stable semantic version" >&2
		exit 1
	fi
	expected="v${version}"
	if [[ -z "${SFETCH_RELEASE_TAG:-}" ]]; then
		echo "error: SFETCH_RELEASE_TAG required" >&2
		exit 1
	fi
	tag="$SFETCH_RELEASE_TAG"
	require_tag="${SFETCH_REQUIRE_TAG:-0}"

	if [[ ! "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
		echo "error: release tag must be canonical vX.Y.Z" >&2
		exit 1
	fi
	if [[ "$tag" != "$expected" ]]; then
		echo "error: release tag does not match VERSION" >&2
		exit 1
	fi

	if [[ "$require_tag" == "1" ]]; then
		if [[ -z "${SFETCH_RELEASE_TAG:-}" ]]; then
			echo "error: strict release guard requires SFETCH_RELEASE_TAG" >&2
			exit 1
		fi
		if git symbolic-ref -q HEAD >/dev/null; then
			echo "error: strict release work must use a detached checkout" >&2
			exit 1
		fi
		if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
			echo "error: strict release work requires a clean checkout" >&2
			exit 1
		fi
		require_sfetch_github_origin || exit 1
		git fetch --quiet --no-tags origin "+refs/heads/main:refs/remotes/origin/main"
		if [[ "$(git cat-file -t "refs/tags/$tag" 2>/dev/null || true)" != "tag" ]]; then
			echo "error: strict release tag must be annotated" >&2
			exit 1
		fi
		local remote_object local_object
		remote_object="$(git ls-remote origin "refs/tags/${tag}" | awk '{print $1}')"
		local_object="$(git rev-parse "refs/tags/${tag}")"
		if [[ -z "$remote_object" || "$remote_object" != "$local_object" ]]; then
			echo "error: remote and local annotated tag objects must match" >&2
			exit 1
		fi
		local tag_commit head_commit main_commit
		tag_commit="$(git rev-parse "refs/tags/${tag}^{}")"
		head_commit="$(git rev-parse HEAD)"
		main_commit="$(git rev-parse refs/remotes/origin/main)"
		if [[ "$tag_commit" != "$head_commit" ]]; then
			echo "error: release tag and HEAD must be identical" >&2
			exit 1
		fi
		if [[ "$tag_commit" != "$main_commit" ]]; then
			echo "error: release tag and origin/main must be identical" >&2
			exit 1
		fi
	fi

	echo "[ok] release guard passed for $tag"
}

main "$@"
