package verify

import (
	"strings"

	"github.com/3leaps/sfetch/internal/model"
)

// SignatureFormatFromExtension determines the signature verification method from file extension.
// Returns one of FormatMinisign, FormatPGP, FormatBinary, or empty string if unknown.
func SignatureFormatFromExtension(filename string, formats model.SignatureFormats) string {
	lower := strings.ToLower(filename)

	if strings.HasSuffix(lower, ".sig") {
		if looksLikeChecksumSig(lower) {
			return FormatPGP
		}
		return FormatBinary
	}

	for _, ext := range formats.Minisign {
		if strings.HasSuffix(lower, ext) {
			return FormatMinisign
		}
	}
	for _, ext := range formats.PGP {
		if strings.HasSuffix(lower, ext) {
			return FormatPGP
		}
	}
	for _, ext := range formats.Ed25519 {
		if strings.HasSuffix(lower, ext) {
			return FormatBinary
		}
	}
	return ""
}

func looksLikeChecksumSig(name string) bool {
	return strings.Contains(name, "sums.sig") || strings.Contains(name, "checksums.sig")
}
