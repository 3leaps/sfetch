#!/usr/bin/env bash
set -euo pipefail
KEY_FILE=${1:?"usage: verify-public-key.sh <path-to-public-key>"}
if [ ! -f "$KEY_FILE" ]; then
	echo "key file $KEY_FILE not found" >&2
	exit 1
fi
if grep -qi "BEGIN PGP PRIVATE" "$KEY_FILE"; then
	echo "❌ private key material detected in $KEY_FILE" >&2
	exit 1
fi
if grep -qi "PRIVATE KEY" "$KEY_FILE"; then
	echo "❌ appears to contain a private key: $KEY_FILE" >&2
	exit 1
fi
echo "✅ $KEY_FILE appears to be a public key"
