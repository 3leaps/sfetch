#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/release-tag-common.sh
source "$(dirname "$0")/release-tag-common.sh"
cd "$tag_root"
require_sfetch_github_origin || tag_die 'origin must be 3leaps/sfetch on GitHub'
"$tag_root/scripts/release-verify-tag.sh"
"$tag_root/scripts/release-inspect-tag-ruleset.sh" "$SFETCH_RELEASE_TAG"
[[ -z "$(git ls-remote --tags origin "refs/tags/$SFETCH_RELEASE_TAG")" ]] || tag_die 'remote tag already exists'
git push origin "refs/tags/$SFETCH_RELEASE_TAG"
"$tag_root/scripts/release-verify-remote-tag.sh"
