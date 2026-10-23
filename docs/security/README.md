# sfetch release verification

Official releases use a GPG-signed annotated Git tag and minisign-signed SHA256SUMS and SHA512SUMS manifests. These are separate signatures.

Establish the expected GPG primary and exact signing subkey, and the minisign public-blob fingerprint, through an independently trusted maintainer channel before accepting downloaded public keys. A key distributed beside a signature is not independent authentication.

The public pins are `release-signing-keys.asc` and `sfetch-minisign.pub`. Release staging extracts both from the verified tagged commit as inert blobs, not from the current checkout or an external public-key locator. The published `sfetch-minisign.pub` asset must match the committed file byte-for-byte; fingerprint verification remains required.

The text and NDJSON anchors in each tagged commit are derived by Decernor 0.1.8 or newer. The minisign fingerprint covers the decoded public blob, not its comment or whole file. Verify exported public material against both anchors with that tool, then use the approved minisign public key to verify both manifests and check every listed digest. Require the complete expected asset set.

Tag verification reads committed public data in an isolated keyring and requires the exact signing subkey. The forge's own "verified" flag is an additional check. Historical tags are not retroactively signed.

The tag workflow has read-only permissions. A passing tag workflow is a consistency signal; it is not release authorization.

## Anchors

| File | Role |
| --- | --- |
| `release-signing-keys.asc` | Approved OpenPGP primary plus the exact signing subkey |
| `sfetch-minisign.pub` | Current minisign pin (used for tags after `v0.4.11`) |
| `sfetch-minisign-retired-1.pub` | Previous minisign pin; last signed tag `v0.4.11` (range `v0.4.0`–`v0.4.11`) |
| `fulmenhq-goneat-minisign.pub` | Third-party pin for fulmenhq/goneat tags after `v0.6.0` |
| `fulmenhq-goneat-minisign-retired-1.pub` | Previous goneat pin; last signed tag `v0.6.0` |
| `../../keys/expected-fingerprints.txt` | Own GPG primary and minisign blob fingerprints |
| `../../config/release/tagger-identity.txt` | Exact git tagger string for annotated tags |
| `../../config/release/decernor-ci-sha256.txt` | Digest of the Decernor archive the tag workflow downloads |

The standalone installer (`scripts/install-sfetch.sh`) carries current and retired pin literals because it is fetched by URL with no repository beside it. `scripts/test-install-anchor-select.sh` asserts each literal equals the committed file here.
