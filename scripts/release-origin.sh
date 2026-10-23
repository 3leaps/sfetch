#!/usr/bin/env bash
# Fail-closed origin identity for release scripts: 3leaps/sfetch on GitHub.
# Canonical HTTPS and git@github.com are exact matches. An SSH host alias is
# accepted only when `ssh -G` reports hostname github.com. Wrong repos and
# aliases that resolve elsewhere are refused.
#
# Source this file; call require_sfetch_github_origin. Tests may set
# SFETCH_SSH_BIN to a stub.

sfetch_ssh_hostname() {
	local host="$1" bin="${SFETCH_SSH_BIN:-ssh}"
	"$bin" -G "$host" 2>/dev/null | awk '$1 == "hostname" { print $2; exit }'
}

sfetch_origin_ok() {
	local url="$1" host path
	case "$url" in
	https://github.com/3leaps/sfetch | https://github.com/3leaps/sfetch.git | \
		git@github.com:3leaps/sfetch | git@github.com:3leaps/sfetch.git | \
		ssh://git@github.com/3leaps/sfetch | ssh://git@github.com/3leaps/sfetch.git)
		return 0
		;;
	git@*:3leaps/sfetch | git@*:3leaps/sfetch.git)
		host="${url#git@}"
		host="${host%%:*}"
		[[ -n "$host" && "$host" != *'/'* && "$host" != github.com ]] || return 1
		[[ "$(sfetch_ssh_hostname "$host")" == github.com ]] || return 1
		return 0
		;;
	ssh://git@*/3leaps/sfetch | ssh://git@*/3leaps/sfetch.git)
		path="${url#ssh://git@}"
		host="${path%%/*}"
		[[ -n "$host" && "$host" != github.com ]] || return 1
		[[ "$(sfetch_ssh_hostname "$host")" == github.com ]] || return 1
		return 0
		;;
	*)
		return 1
		;;
	esac
}

require_sfetch_github_origin() {
	local url
	url="$(git config --get remote.origin.url || true)"
	if ! sfetch_origin_ok "$url"; then
		echo "error: origin must be 3leaps/sfetch on GitHub" >&2
		return 1
	fi
}
