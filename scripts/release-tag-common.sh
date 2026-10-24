#!/usr/bin/env bash
# Signed-tag ceremony invariants. No signing material is stored in this repo.
set -euo pipefail

tag_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/release-decernor.sh
source "$tag_root/scripts/release-decernor.sh"
# shellcheck source=scripts/release-origin.sh
source "$tag_root/scripts/release-origin.sh"

tag_discard_verify_home() {
	if [[ -n "${TAG_VERIFY_GNUPGHOME:-}" ]]; then
		gpgconf --homedir "$TAG_VERIFY_GNUPGHOME" --kill all >/dev/null 2>&1 || true
		rm -rf "$TAG_VERIFY_GNUPGHOME"
		TAG_VERIFY_GNUPGHOME=""
	fi
}

# Only verification homes are disposable. The operator owns the signing
# keyring and its agent/card state; never remove it or stop its agent.
tag_cleanup_homes() {
	tag_discard_verify_home
}

# Expand ~ and collapse . / .. without following symlinks. Relative paths fail.
tag_canon_path() {
	python3 -c '
import os, sys
raw = sys.argv[1]
p = os.path.expanduser(raw)
if not p.startswith("/"):
    raise SystemExit("relative")
parts = []
for part in p.split("/"):
    if part in ("", "."):
        continue
    if part == "..":
        if parts:
            parts.pop()
        continue
    parts.append(part)
print("/" + "/".join(parts) if parts else "/")
' "$1"
}

tag_die() {
	echo "error: $*" >&2
	return 1
}

tag_identity() {
	[[ "${SFETCH_TAGGER_NAME:-} <${SFETCH_TAGGER_EMAIL:-}>" == "$(cat "$tag_root/config/release/tagger-identity.txt")" ]] || {
		tag_die 'infosec tagger identity required'
		return 1
	}
	[[ "$SFETCH_TAGGER_NAME" != *$'\n'* && "$SFETCH_TAGGER_NAME" != *$'\r'* &&
		"$SFETCH_TAGGER_NAME" != *'<'* && "$SFETCH_TAGGER_NAME" != *'>'* ]] || {
		tag_die 'invalid tagger name'
		return 1
	}
	[[ "$SFETCH_TAGGER_EMAIL" != *$'\n'* && "$SFETCH_TAGGER_EMAIL" != *$'\r'* &&
		"$SFETCH_TAGGER_EMAIL" != *'<'* && "$SFETCH_TAGGER_EMAIL" != *'>'* ]] || {
		tag_die 'invalid tagger email'
		return 1
	}
}

tag_version() {
	[[ -n "${SFETCH_RELEASE_TAG:-}" ]] || {
		tag_die 'SFETCH_RELEASE_TAG required'
		return 1
	}
	"$tag_root/scripts/release-guard-tag-version.sh" >/dev/null
}

tag_message_file() {
	[[ -n "${SFETCH_TAG_MESSAGE_DIR:-}" && -d "$SFETCH_TAG_MESSAGE_DIR" &&
		! -L "$SFETCH_TAG_MESSAGE_DIR" ]] || {
		tag_die 'tag message directory required'
		return 1
	}
	[[ "${SFETCH_TAG_MESSAGE_DIR%/}" == */"$SFETCH_RELEASE_TAG" ]] || {
		tag_die 'message directory must end in tag'
		return 1
	}
	[[ "$SFETCH_TAG_MESSAGE_DIR" == /* && "/$SFETCH_TAG_MESSAGE_DIR/" != *'/../'* ]] || {
		tag_die 'absolute message directory without parent traversal required'
		return 1
	}
	local component="${SFETCH_TAG_MESSAGE_DIR%/}"
	while [[ "$component" != / ]]; do
		[[ ! -L "$component" ]] || {
			tag_die 'message directory may not contain symlink ancestors'
			return 1
		}
		component="${component%/*}"
		[[ -n "$component" ]] || component=/
	done
	local canonical
	canonical="$(cd "$SFETCH_TAG_MESSAGE_DIR" && pwd -P)"
	case "$canonical" in "$tag_root" | "$tag_root"/*)
		tag_die 'message directory must be outside repository'
		return 1
		;;
	esac
	local file="${SFETCH_TAG_MESSAGE_DIR%/}/message.txt"
	[[ -f "$file" && ! -L "$file" && -s "$file" ]] || {
		tag_die 'message.txt required'
		return 1
	}
	"$tag_root/scripts/release-prepare-tag-message.py" --validate-message "$file" || return 1
	printf '%s\n' "$file"
}

tag_origin() {
	require_sfetch_github_origin || {
		tag_die 'origin must be 3leaps/sfetch on GitHub'
		return 1
	}
}

tag_checkout() {
	tag_origin
	git fetch --quiet origin '+refs/heads/main:refs/remotes/origin/main'
	[[ -z "$(git status --porcelain --untracked-files=normal)" ]] || tag_die 'clean checkout required'
	[[ "$(git rev-parse HEAD)" == "$(git rev-parse refs/remotes/origin/main)" ]] || tag_die 'HEAD must match fetched origin/main'
}

tag_selector_shape() {
	[[ "${SFETCH_PGP_KEY_ID:-}" =~ ^[0-9A-F]{40}!$ ]] || {
		tag_die 'exact uppercase signing subkey fingerprint with ! required'
		return 1
	}
	[[ "${SFETCH_GPG_SIGNING_FINGERPRINT:-}" =~ ^[0-9A-F]{40}$ ]] || {
		tag_die 'uppercase primary fingerprint required'
		return 1
	}
}

tag_stat_mode() {
	if stat -c '%a' "$1" >/dev/null 2>&1; then
		stat -c '%a' "$1"
	else
		stat -f '%OLp' "$1"
	fi
}

# Fresh isolated keyring for selector verification. Never reuse an existing
# directory or follow a symlink: mktemp -d, refuse -L, chmod 0700, kill the
# agent on cleanup.
tag_fresh_verify_gnupg_home() {
	local dir mode
	dir="$(mktemp -d /tmp/sfetch-tag-gnupg.XXXXXX)" || {
		tag_die 'cannot create GnuPG home'
		return 1
	}
	if [[ -L "$dir" || ! -d "$dir" ]]; then
		rm -rf "$dir"
		tag_die 'GnuPG home must be a fresh directory, not a symlink'
		return 1
	fi
	chmod 700 "$dir" || {
		rm -rf "$dir"
		tag_die 'cannot chmod GnuPG home'
		return 1
	}
	mode="$(tag_stat_mode "$dir")"
	[[ "$mode" == "700" ]] || {
		rm -rf "$dir"
		tag_die 'GnuPG home must be mode 0700'
		return 1
	}
	TAG_VERIFY_GNUPGHOME="$dir"
}

# Validate the explicitly selected operator keyring. Canonicalize (~, trailing
# slash, ., ..) before comparing to the default homedir; refuse non-0700
# (do not chmod). Signing uses this home and its existing agent/card setup.
tag_bind_operator_gnupg_home() {
	[[ -n "${SFETCH_GPG_HOMEDIR:-}" ]] || {
		tag_die 'external GPG home required'
		return 1
	}
	local canon default_home default_env
	canon="$(tag_canon_path "$SFETCH_GPG_HOMEDIR")" || {
		tag_die 'GPG home must be an absolute path'
		return 1
	}
	[[ "$canon" == /* ]] || {
		tag_die 'GPG home must be an absolute path'
		return 1
	}
	[[ ! -L "$SFETCH_GPG_HOMEDIR" && ! -L "$canon" ]] || {
		tag_die 'GPG home must not be a symlink'
		return 1
	}
	[[ -d "$canon" ]] || {
		tag_die 'external GPG home required'
		return 1
	}
	local component="$canon"
	while [[ "$component" != / ]]; do
		[[ ! -L "$component" ]] || {
			tag_die 'GPG home may not contain symlink ancestors'
			return 1
		}
		component="${component%/*}"
		[[ -n "$component" ]] || component=/
	done
	case "$canon" in "$tag_root" | "$tag_root"/*)
		tag_die 'GPG home must be outside repository'
		return 1
		;;
	esac
	local mode
	mode="$(tag_stat_mode "$canon")"
	[[ "$mode" == "700" ]] || {
		tag_die 'GPG home must be mode 0700'
		return 1
	}
	default_home="$(tag_canon_path "$HOME/.gnupg")" || default_home=""
	default_env="$(tag_canon_path "${GNUPGHOME:-$HOME/.gnupg}")" || default_env=""
	if [[ -n "$default_home" && "$canon" == "$default_home" ]] ||
		[[ -n "$default_env" && "$canon" == "$default_env" ]]; then
		tag_die 'GPG home must not be the default homedir'
		return 1
	fi
	SFETCH_GPG_HOMEDIR="$canon"
}

# Use the operator's keyring directly: hardware-backed signing subkeys cannot
# be exported into a temporary home. Public verification stays isolated.
tag_prepare_signing_home() {
	tag_bind_operator_gnupg_home || return 1
	export GNUPGHOME="$SFETCH_GPG_HOMEDIR"
}

tag_key_selector() {
	tag_selector_shape || return 1
	resolve_release_decernor ceremony || {
		tag_die 'trusted Decernor identity/version check failed'
		return 1
	}
	"$tag_root/scripts/release-verify-committed-anchors.sh" >/dev/null || return 1
	[[ "$(awk '$1=="gpg" {print $2}' "$tag_root/keys/expected-fingerprints.txt")" == "$SFETCH_GPG_SIGNING_FINGERPRINT" ]] || {
		tag_die 'operator fingerprint differs from committed anchor'
		return 1
	}
	tag_bind_operator_gnupg_home || return 1
	tag_fresh_verify_gnupg_home || return 1
	if ! gpg --homedir "$TAG_VERIFY_GNUPGHOME" --batch --quiet --import \
		"$tag_root/docs/security/release-signing-keys.asc" 2>/dev/null; then
		tag_discard_verify_home
		tag_die 'committed public pin failed to import'
		return 1
	fi
	local listing primary subkey
	if ! listing="$(gpg --homedir "$TAG_VERIFY_GNUPGHOME" --batch --with-colons --fingerprint --with-subkey-fingerprint --list-keys "${SFETCH_PGP_KEY_ID%!}" 2>/dev/null)"; then
		tag_discard_verify_home
		tag_die 'signing subkey unavailable'
		return 1
	fi
	primary="$(printf '%s\n' "$listing" | awk -F: '$1=="pub" {p=1;next} p && $1=="fpr" {print $10;exit}')"
	subkey="$(printf '%s\n' "$listing" | awk -F: -v f="${SFETCH_PGP_KEY_ID%!}" '$1=="sub" {s=1;cap=$12;next} s && $1=="fpr" {if ($10==f && cap ~ /[sS]/) print $10; s=0}')"
	if [[ "$primary" != "$SFETCH_GPG_SIGNING_FINGERPRINT" || "$subkey" != "${SFETCH_PGP_KEY_ID%!}" ]]; then
		tag_discard_verify_home
		tag_die 'signing subkey not on pinned primary'
		return 1
	fi
	tag_discard_verify_home
}

tag_expected_message() {
	local file
	file="$(tag_message_file)" || return 1
	cat "$file"
}

tag_verify_object() {
	local object="$1" expected_file="$2" tagger actual_file
	[[ "$(git cat-file -t "$object" 2>/dev/null)" == tag ]] || {
		tag_die 'annotated tag object required'
		return 1
	}
	[[ "$(git cat-file tag "$object" | sed -n 's/^tag //p' | head -1)" == "$SFETCH_RELEASE_TAG" ]] || {
		tag_die 'tag name mismatch'
		return 1
	}
	[[ "$(git rev-parse "${object}^{}")" == "$(git rev-parse HEAD)" ]] || {
		tag_die 'tag target mismatch'
		return 1
	}
	[[ "$(git rev-parse HEAD)" == "$(git rev-parse refs/remotes/origin/main)" ]] || {
		tag_die 'tag not at main'
		return 1
	}
	tagger="$(git cat-file tag "$object" | sed -n 's/^tagger \(.*\) [0-9][0-9]* [+-][0-9][0-9][0-9][0-9]$/\1/p' | head -1)"
	[[ "$tagger" == "$SFETCH_TAGGER_NAME <$SFETCH_TAGGER_EMAIL>" ]] || {
		tag_die 'tagger identity mismatch'
		return 1
	}
	actual_file="$(mktemp)"
	if ! "$tag_root/scripts/release-tag-body.sh" "$object" >"$actual_file"; then
		rm -f "$actual_file"
		return 1
	fi
	if ! cmp -s "$expected_file" "$actual_file"; then
		rm -f "$actual_file"
		tag_die 'signed tag message mismatch'
		return 1
	fi
	rm -f "$actual_file"
}
