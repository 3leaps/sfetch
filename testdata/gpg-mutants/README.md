# GPG mutant specimens

Throwaway OpenPGP material for installer mutation tests. Public key and
detached signature only; no secret key.

`SHA256SUMS.asc` is a subkey signature over `SHA256SUMS`. VALIDSIG field 3 is
the signing subkey; field 12 is the primary. `validsig-2.5.status` appends the
extra trailing fields GnuPG 2.5.x emits so `$NF` is not the primary.
