package main

var defaults = RepoConfig{
	BinaryName:        "sfetch",
	HashAlgo:          "sha256",
	ArchiveType:       "tar.gz",
	ArchiveExtensions: []string{".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tar", ".zip"},
	AssetPatterns: []string{
		"(?i)^{{binary}}[_-]{{osToken}}[_-]{{archToken}}.*",
		"(?i)^{{binary}}.*{{osToken}}.*{{archToken}}.*",
	},
	ChecksumCandidates: []string{
		"{{asset}}.sha256",
		"{{asset}}.sha256.txt",
		"{{base}}.sha256",
		"{{base}}.sha256.txt",
		"SHA2-256SUMS",
		"SHA2-512SUMS",
		"SHA2-256SUMS.txt",
		"SHA2-512SUMS.txt",
		"SHA512SUMS",
		"SHA512SUMS.txt",
		"{{binary}}_{{versionNoPrefix}}_checksums.txt",
		"{{binary}}_{{version}}_checksums.txt",
		"{{binary}}_checksums.txt",
		"SHA256SUMS",
		"SHA256SUMS.txt",
		"SHA256SUMS_64",
		"sha256sum.txt",
		"checksums.txt",
		"CHECKSUMS",
		"CHECKSUMS.txt",
	},
	ChecksumSigCandidates: []string{
		"SHA2-256SUMS.minisig",
		"SHA2-512SUMS.minisig",
		"SHA256SUMS.minisig",
		"SHA512SUMS.minisig",
		"SHA256SUMS.txt.minisig",
		"checksums.txt.minisig",
		"CHECKSUMS.minisig",
		"SHA2-256SUMS.asc",
		"SHA2-512SUMS.asc",
		"SHA256SUMS.asc",
		"SHA512SUMS.asc",
		"SHA256SUMS.txt.asc",
		"checksums.txt.asc",
		"CHECKSUMS.asc",
		"SHA2-256SUMS.sig",
		"SHA2-512SUMS.sig",
		"SHA256SUMS.sig",
		"SHA512SUMS.sig",
		"checksums.txt.sig",
		"CHECKSUMS.sig",
	},
	SignatureCandidates: []string{
		"{{asset}}.minisig",
		"{{asset}}.sig",
		"{{asset}}.sig.ed25519",
		"{{base}}.sig",
		"{{base}}.sig.ed25519",
		"{{asset}}.asc",
		"{{base}}.asc",
	},
	SignatureFormats: SignatureFormats{
		Minisign: []string{".minisig"},
		PGP:      []string{".asc", ".gpg", ".sig.asc"},
		Ed25519:  []string{".sig.ed25519"},
	},
	PreferChecksumSig: boolPtr(true),
}

func boolPtr(v bool) *bool { return &v }

func preferChecksumSig(c *RepoConfig) bool {
	if c.PreferChecksumSig == nil {
		return true
	}
	return *c.PreferChecksumSig
}

// repoConfigs holds overrides for repos that don't follow standard patterns.
// Most repos work without entries here - BinaryName and asset type are inferred from repo/asset names.
// Only add entries for edge cases.
var repoConfigs = map[string]RepoConfig{
	// Example: repos where binary name differs from repo name
	// "owner/repo": {BinaryName: "actual-binary-name"},
}
