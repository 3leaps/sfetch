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
