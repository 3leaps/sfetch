package verify

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"

	"github.com/3leaps/sfetch/internal/model"
)

func TestExtractChecksum(t *testing.T) {
	t.Parallel()

	sha256Digest := strings.Repeat("a", 64)
	sha512Digest := strings.Repeat("b", 128)

	tests := []struct {
		name      string
		data      string
		algo      string
		assetName string
		want      string
		wantErr   string
	}{
		{
			name:    "empty file",
			data:    "\n\n",
			algo:    "sha256",
			wantErr: "empty",
		},
		{
			name: "bare digest",
			data: strings.ToUpper(sha256Digest),
			algo: "sha256",
			want: sha256Digest,
		},
		{
			name:      "consolidated matches by basename",
			data:      sha256Digest + "  ./dist/tool\n" + sha256Digest + "  other\n",
			algo:      "sha256",
			assetName: "tool",
			want:      sha256Digest,
		},
		{
			name:      "ignores comments and blank lines",
			data:      "# comment\n\n" + sha256Digest + " tool\n",
			algo:      "sha256",
			assetName: "tool",
			want:      sha256Digest,
		},
		{
			name:      "asset not found",
			data:      sha256Digest + " tool\n",
			algo:      "sha256",
			assetName: "nope",
			wantErr:   "not found",
		},
		{
			name:      "sha512 digest",
			data:      sha512Digest + " tool\n",
			algo:      "sha512",
			assetName: "tool",
			want:      sha512Digest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ExtractChecksum([]byte(tc.data), tc.algo, tc.assetName)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error: got %q want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractChecksum: %v", err)
			}
			if got != tc.want {
				t.Fatalf("checksum: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizeHexKey(t *testing.T) {
	t.Parallel()

	validKey := strings.Repeat("a", ed25519.PublicKeySize*2)

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{name: "empty", input: " ", wantErr: "required"},
		{name: "pem blob", input: "-----BEGIN KEY-----", wantErr: "hex"},
		{name: "wrong length", input: "abcd", wantErr: "hex characters"},
		{name: "non hex", input: strings.Repeat("g", ed25519.PublicKeySize*2), wantErr: "hexadecimal"},
		{name: "valid upper", input: strings.ToUpper(validKey), want: validKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeHexKey(tc.input)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error: got %q want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeHexKey: %v", err)
			}
			if got != tc.want {
				t.Fatalf("key: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestSignatureFormatFromExtension(t *testing.T) {
	t.Parallel()

	formats := model.SignatureFormats{
		Minisign: []string{".minisig"},
		PGP:      []string{".asc"},
		Ed25519:  []string{".sig.ed25519"},
	}

	tests := []struct {
		name     string
		filename string
		want     string
	}{
		{name: "checksum sig via .sig", filename: "SHA256SUMS.sig", want: FormatPGP},
		{name: "binary sig via .sig", filename: "tool.tar.gz.sig", want: FormatBinary},
		{name: "minisign", filename: "tool.tar.gz.minisig", want: FormatMinisign},
		{name: "pgp", filename: "tool.tar.gz.asc", want: FormatPGP},
		{name: "ed25519", filename: "tool.sig.ed25519", want: FormatBinary},
		{name: "unknown", filename: "tool.txt", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := SignatureFormatFromExtension(tc.filename, formats); got != tc.want {
				t.Fatalf("format: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestChecksumHelpers(t *testing.T) {
	t.Parallel()

	if got := DetectChecksumType("tool.sha256"); got != "per-asset" {
		t.Fatalf("DetectChecksumType: got %q", got)
	}
	if got := DetectChecksumAlgorithm("SHA2-512SUMS", "sha256"); got != "sha512" {
		t.Fatalf("DetectChecksumAlgorithm: got %q", got)
	}
	if got := FormatSize(1536); !strings.Contains(got, "KB") {
		t.Fatalf("FormatSize: got %q", got)
	}

	// Ensure filepath.Base behavior used by ExtractChecksum stays stable.
	if filepath.Base("./dist/tool") != "tool" {
		t.Fatalf("unexpected filepath.Base behavior")
	}
}

// =============================================================================
// Pass 2: internal/verify edge cases
// =============================================================================

func TestDetectChecksumType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		filename string
		want     string
	}{
		// Per-asset formats
		{"tool.sha256", "per-asset"},
		{"tool.sha512", "per-asset"},
		{"tool.sha256.txt", "per-asset"},
		{"tool.sha512.txt", "per-asset"},
		{"TOOL.SHA256", "per-asset"},
		// Consolidated formats
		{"SHA256SUMS", "consolidated"},
		{"SHA2-512SUMS", "consolidated"},
		{"checksums.txt", "consolidated"},
		{"sha256sums.txt", "consolidated"},
		// Unknown defaults to consolidated
		{"random.txt", "consolidated"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := DetectChecksumType(tt.filename)
			if got != tt.want {
				t.Errorf("DetectChecksumType(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestDetectChecksumAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		filename    string
		defaultAlgo string
		want        string
	}{
		// SHA-512 patterns
		{"SHA2-512SUMS", "sha256", "sha512"},
		{"sha512sums", "sha256", "sha512"},
		{"SHA512SUMS", "sha256", "sha512"},
		{"tool.sha512", "sha256", "sha512"},
		{"tool.sha512.txt", "sha256", "sha512"},
		// SHA-256 patterns
		{"SHA2-256SUMS", "sha512", "sha256"},
		{"sha256sums", "sha512", "sha256"},
		{"SHA256SUMS", "sha512", "sha256"},
		{"tool.sha256", "sha512", "sha256"},
		{"tool.sha256.txt", "sha512", "sha256"},
		// Falls back to default
		{"checksums.txt", "sha256", "sha256"},
		{"checksums.txt", "sha512", "sha512"},
		{"random.txt", "sha256", "sha256"},
	}

	for _, tt := range tests {
		name := tt.filename + "_default_" + tt.defaultAlgo
		t.Run(name, func(t *testing.T) {
			got := DetectChecksumAlgorithm(tt.filename, tt.defaultAlgo)
			if got != tt.want {
				t.Errorf("DetectChecksumAlgorithm(%q, %q) = %q, want %q", tt.filename, tt.defaultAlgo, got, tt.want)
			}
		})
	}
}

func TestFormatSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatSize(tt.bytes)
			if got != tt.want {
				t.Errorf("FormatSize(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestExtractChecksumEdgeCases(t *testing.T) {
	t.Parallel()

	sha256Digest := strings.Repeat("a", 64)
	sha512Digest := strings.Repeat("b", 128)

	tests := []struct {
		name      string
		data      string
		algo      string
		assetName string
		want      string
		wantErr   string
	}{
		// BSD-style format (hash first, then filename)
		{
			name:      "BSD format with spaces",
			data:      sha256Digest + "  tool.tar.gz",
			algo:      "sha256",
			assetName: "tool.tar.gz",
			want:      sha256Digest,
		},
		// GNU coreutils format - asterisk is part of filename field
		// Note: current impl treats *tool.tar.gz as the filename (asterisk included)
		{
			name:      "GNU format with asterisk prefix",
			data:      sha256Digest + " *tool.tar.gz",
			algo:      "sha256",
			assetName: "*tool.tar.gz",
			want:      sha256Digest,
		},
		// Multiple entries
		{
			name: "multiple entries picks correct one",
			data: sha256Digest + "  wrong.tar.gz\n" +
				strings.Repeat("c", 64) + "  tool.tar.gz\n" +
				strings.Repeat("d", 64) + "  other.tar.gz",
			algo:      "sha256",
			assetName: "tool.tar.gz",
			want:      strings.Repeat("c", 64),
		},
		// Path stripping
		{
			name:      "strips directory path",
			data:      sha256Digest + "  ./dist/bin/tool",
			algo:      "sha256",
			assetName: "tool",
			want:      sha256Digest,
		},
		// Case normalization
		{
			name:      "uppercase digest normalized",
			data:      strings.ToUpper(sha256Digest),
			algo:      "sha256",
			assetName: "",
			want:      sha256Digest,
		},
		// SHA-512
		{
			name:      "sha512 digest",
			data:      sha512Digest + "  tool.tar.gz",
			algo:      "sha512",
			assetName: "tool.tar.gz",
			want:      sha512Digest,
		},
		// Error cases
		{
			name:      "wrong length digest",
			data:      "abcd  tool.tar.gz",
			algo:      "sha256",
			assetName: "tool.tar.gz",
			wantErr:   "not found",
		},
		{
			name:      "non-hex characters",
			data:      strings.Repeat("g", 64) + "  tool.tar.gz",
			algo:      "sha256",
			assetName: "tool.tar.gz",
			wantErr:   "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ExtractChecksum([]byte(tt.data), tt.algo, tt.assetName)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSignatureFormatFromExtensionEdgeCases(t *testing.T) {
	t.Parallel()

	formats := model.SignatureFormats{
		Minisign: []string{".minisig"},
		PGP:      []string{".asc", ".gpg"},
		Ed25519:  []string{".sig.ed25519"},
	}

	tests := []struct {
		filename string
		want     string
	}{
		// Minisign
		{"SHA256SUMS.minisig", FormatMinisign},
		{"tool.tar.gz.minisig", FormatMinisign},
		{"TOOL.MINISIG", FormatMinisign},
		// PGP
		{"SHA256SUMS.asc", FormatPGP},
		{"tool.tar.gz.gpg", FormatPGP},
		{"TOOL.ASC", FormatPGP},
		// Generic .sig handling
		{"SHA256SUMS.sig", FormatPGP},     // checksum sig -> PGP
		{"sha256sums.sig", FormatPGP},     // checksum sig -> PGP
		{"checksums.sig", FormatPGP},      // checksum sig -> PGP
		{"tool.tar.gz.sig", FormatBinary}, // asset sig -> binary
		{"TOOL.SIG", FormatBinary},        // asset sig -> binary
		// Ed25519
		{"tool.sig.ed25519", FormatBinary},
		{"TOOL.SIG.ED25519", FormatBinary},
		// Unknown
		{"tool.txt", ""},
		{"tool.tar.gz", ""},
		{"SHA256SUMS", ""},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := SignatureFormatFromExtension(tt.filename, formats)
			if got != tt.want {
				t.Errorf("SignatureFormatFromExtension(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestIsHexDigest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		value       string
		expectedLen int
		want        bool
	}{
		{"valid sha256", strings.Repeat("a", 64), 64, true},
		{"valid sha512", strings.Repeat("b", 128), 128, true},
		{"valid uppercase", strings.Repeat("A", 64), 64, true},
		{"valid mixed case", strings.Repeat("aB", 32), 64, true},
		{"valid with numbers", strings.Repeat("a1", 32), 64, true},
		{"wrong length", strings.Repeat("a", 63), 64, false},
		{"too long", strings.Repeat("a", 65), 64, false},
		{"odd length", strings.Repeat("a", 63), 0, false},
		{"non-hex characters", strings.Repeat("g", 64), 64, false},
		{"empty string", "", 64, false},
		{"any length mode", strings.Repeat("ab", 10), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHexDigest(tt.value, tt.expectedLen)
			if got != tt.want {
				t.Errorf("isHexDigest(%q, %d) = %v, want %v", tt.value, tt.expectedLen, got, tt.want)
			}
		})
	}
}

func TestExpectedDigestLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		algo string
		want int
	}{
		{"sha256", 64},
		{"SHA256", 64},
		{"sha512", 128},
		{"SHA512", 128},
		{"md5", 0},
		{"unknown", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			got := expectedDigestLength(tt.algo)
			if got != tt.want {
				t.Errorf("expectedDigestLength(%q) = %d, want %d", tt.algo, got, tt.want)
			}
		})
	}
}
