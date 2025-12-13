package verify

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"strings"
)

func ExtractChecksum(data []byte, algo, assetName string) (string, error) {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "", fmt.Errorf("checksum file is empty")
	}
	digestLen := expectedDigestLength(algo)
	if isHexDigest(text, digestLen) {
		return strings.ToLower(text), nil
	}

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		digest := fields[0]
		if !isHexDigest(digest, digestLen) {
			continue
		}
		candidate := filepath.Base(fields[len(fields)-1])
		if candidate == assetName {
			return strings.ToLower(digest), nil
		}
	}

	return "", fmt.Errorf("checksum for %s not found", assetName)
}

func NormalizeHexKey(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", fmt.Errorf("error: --key is required to verify ed25519 signatures")
	}
	upper := strings.ToUpper(trimmed)
	if strings.Contains(upper, "BEGIN") || strings.Contains(upper, "PRIVATE") {
		return "", fmt.Errorf("ed25519 keys must be provided as 64-character hex strings, not PEM/PGP blobs")
	}
	expectedLen := ed25519.PublicKeySize * 2
	if len(trimmed) != expectedLen {
		return "", fmt.Errorf("ed25519 key must be %d hex characters", expectedLen)
	}
	if !isHexDigest(trimmed, expectedLen) {
		return "", fmt.Errorf("ed25519 key must contain only hexadecimal characters")
	}
	return strings.ToLower(trimmed), nil
}

func isHexDigest(value string, expectedLen int) bool {
	if expectedLen > 0 && len(value) != expectedLen {
		return false
	}
	if len(value)%2 != 0 {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}

func expectedDigestLength(algo string) int {
	switch strings.ToLower(algo) {
	case "sha256":
		return 64
	case "sha512":
		return 128
	default:
		return 0
	}
}
