# GPG mutant specimens

Throwaway OpenPGP material for installer mutation tests. Public key and
detached signature only; no secret key.

`SHA256SUMS.asc` is a subkey signature over `SHA256SUMS`. VALIDSIG field 3 is
the signing subkey; field 12 is the primary.

## VALIDSIG status lines

`validsig-2.2.status` is a fixture in the GnuPG DETAILS layout (field 12 is
the primary). It is not a captured log from a named GnuPG release.

`validsig-2.5.status` is **synthetic**. It is not real GnuPG 2.5 output.
GnuPG 2.5.22 prints the primary fingerprint as the last VALIDSIG field.
This file appends `00 extra` after field 12 so the forward-compat parser
test keeps using field 12 when `$NF` is not the primary. Keep the test;
do not treat this line as a capture.

Provenance: generated for `scripts/test-install-gpg-mutants.sh` (throwaway
key in `fingerprints.txt`). No live GnuPG capture is checked in.
