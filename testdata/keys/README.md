# Test Keys

This directory contains **test-only** cryptographic keys for unit tests.

## Files

- `test-minisign.pub` - Minisign public key (committed, used by tests)
- `test-pgp-pub.asc` - PGP public key (committed, used by tests)
- `*.key` - Private keys (gitignored, not needed to run tests)

## Running Tests

Tests only VERIFY signatures using the committed public keys and fixtures.
No private keys are needed to run `go test ./...`.

## Regenerating Fixtures

**Important:** You cannot regenerate a private key from a public key. If you need
to modify test fixtures, you must generate a NEW keypair and re-sign ALL fixtures,
then commit the new public key alongside the new fixtures.

Private keys (`.key`) are gitignored. These are throwaway test credentials
with no security value.

```bash
# 1. Generate NEW minisign keypair with -W (no password, suitable for test fixtures)
minisign -G -W -p testdata/keys/test-minisign.pub \
              -s testdata/keys/test-minisign.key -f

# 2. Update the checksum file content as needed
echo "abc123...  test-asset.tar.gz" > testdata/minisign/SHA256SUMS

# 3. Sign with the NEW private key
minisign -Sm testdata/minisign/SHA256SUMS \
         -s testdata/keys/test-minisign.key \
         -t "sfetch test fixture"

# 4. Commit BOTH the new public key AND new fixtures together
git add testdata/keys/test-minisign.pub testdata/minisign/
git commit -m "test: regenerate minisign fixtures with new keypair"

# 5. Private key can be deleted (gitignored anyway)
rm testdata/keys/test-minisign.key
```

The private key is ephemeral - only needed during fixture creation, then discarded.
The `-W` flag generates a key without password protection, which is appropriate
for test fixtures since the key has no security value.
