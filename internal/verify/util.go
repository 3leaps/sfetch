package verify

import (
	"fmt"
	"strings"
)

// DetectChecksumType determines if a checksum file is consolidated or per-asset.
func DetectChecksumType(filename string) string {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".sha256") || strings.HasSuffix(lower, ".sha512") ||
		strings.HasSuffix(lower, ".sha256.txt") || strings.HasSuffix(lower, ".sha512.txt") {
		return "per-asset"
	}
	return "consolidated"
}

func DetectChecksumAlgorithm(filename, defaultAlgo string) string {
	lower := strings.ToLower(filename)
	switch {
	case strings.Contains(lower, "sha2-512sums"),
		strings.Contains(lower, "sha512sums"),
		strings.HasSuffix(lower, ".sha512"),
		strings.HasSuffix(lower, ".sha512.txt"):
		return "sha512"
	case strings.Contains(lower, "sha2-256sums"),
		strings.Contains(lower, "sha256sums"),
		strings.HasSuffix(lower, ".sha256"),
		strings.HasSuffix(lower, ".sha256.txt"):
		return "sha256"
	default:
		return defaultAlgo
	}
}

// FormatSize formats bytes as human-readable size.
func FormatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
