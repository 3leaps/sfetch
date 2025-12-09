package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"hash"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestGetConfig(t *testing.T) {
	tests := []struct {
		repo    string
		wantBin string
	}{
		{"3leaps/sfetch", "sfetch"},
		{"unknown/repo", "repo"},          // BinaryName inferred from repo name
		{"jedisct1/minisign", "minisign"}, // BinaryName inferred from repo name
	}
	for _, tt := range tests {
		t.Run(tt.repo, func(t *testing.T) {
			cfg := getConfig(tt.repo)
			if len(cfg.AssetPatterns) == 0 {
				t.Fatalf("expected default asset patterns")
			}
			rendered := renderPattern(cfg.AssetPatterns[0], cfg, runtime.GOOS, runtime.GOARCH)
			if !strings.Contains(rendered, strings.ToLower(runtime.GOOS)) {
				t.Errorf("pattern %q does not reference GOOS", rendered)
			}
			if cfg.BinaryName != tt.wantBin {
				t.Errorf("BinaryName got %q want %q", cfg.BinaryName, tt.wantBin)
			}
		})
	}
}

func TestHashSwitch(t *testing.T) {
	tests := []struct {
		algo string
	}{
		{"sha256"},
		{"sha512"},
	}
	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			cfg := &RepoConfig{HashAlgo: tt.algo}
			var h hash.Hash
			switch cfg.HashAlgo {
			case "sha256":
				h = sha256.New()
			case "sha512":
				h = sha512.New()
			default:
				t.Fatal("unknown algo")
			}
			if h == nil {
				t.Error("no hash")
			}
		})
	}
}

func TestSigVerify(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test")
	sig := ed25519.Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("good sig failed")
	}
	badSig := append(sig, 0)
	if ed25519.Verify(pub, msg, badSig) {
		t.Error("bad sig passed")
	}
	// size check in code
}

func TestVersion(t *testing.T) {
	// manual --version "sfetch dev"
}

func TestResolvePGPKey(t *testing.T) {
	t.Run("local file", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "key.asc")
		if err := os.WriteFile(path, []byte("local"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		got, err := resolvePGPKey(path, "", "", nil, tmp)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got != path {
			t.Fatalf("want %s got %s", path, got)
		}
	})

	t.Run("remote via pgp-key-url", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("url"))
		}))
		defer server.Close()
		tmp := t.TempDir()
		got, err := resolvePGPKey("", server.URL+"/key.asc", "", nil, tmp)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		data, err := os.ReadFile(got)
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		if string(data) != "url" {
			t.Fatalf("unexpected data: %s", data)
		}
	})

	t.Run("release asset", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("asset"))
		}))
		defer server.Close()
		tmp := t.TempDir()
		assets := []Asset{{Name: "release-key.asc", BrowserDownloadUrl: server.URL + "/release-key.asc"}}
		got, err := resolvePGPKey("", "", "release-key.asc", assets, tmp)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		data, err := os.ReadFile(got)
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		if string(data) != "asset" {
			t.Fatalf("unexpected data: %s", data)
		}
	})

	t.Run("auto-detect", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("auto"))
		}))
		defer server.Close()
		tmp := t.TempDir()
		assets := []Asset{{Name: "fulmen-release-key.asc", BrowserDownloadUrl: server.URL + "/fulmen-release-key.asc"}}
		got, err := resolvePGPKey("", "", "", assets, tmp)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		data, err := os.ReadFile(got)
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		if string(data) != "auto" {
			t.Fatalf("unexpected data: %s", data)
		}
	})

	t.Run("missing inputs", func(t *testing.T) {
		_, err := resolvePGPKey("", "", "", nil, t.TempDir())
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestVerifyMinisignSignature(t *testing.T) {
	// Test with fixtures from testdata/minisign/
	checksumFile := "testdata/minisign/SHA256SUMS"
	sigFile := "testdata/minisign/SHA256SUMS.minisig"
	pubKeyFile := "testdata/keys/test-minisign.pub"

	// Read checksum file content
	checksumBytes, err := os.ReadFile(checksumFile)
	if err != nil {
		t.Fatalf("read checksum file: %v", err)
	}

	t.Run("valid signature", func(t *testing.T) {
		err := verifyMinisignSignature(checksumBytes, sigFile, pubKeyFile)
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}
	})

	t.Run("tampered content", func(t *testing.T) {
		tampered := append(checksumBytes, []byte("tampered")...)
		err := verifyMinisignSignature(tampered, sigFile, pubKeyFile)
		if err == nil {
			t.Fatal("expected error for tampered content")
		}
	})

	t.Run("missing pubkey", func(t *testing.T) {
		err := verifyMinisignSignature(checksumBytes, sigFile, "nonexistent.pub")
		if err == nil {
			t.Fatal("expected error for missing pubkey")
		}
	})

	t.Run("missing sigfile", func(t *testing.T) {
		err := verifyMinisignSignature(checksumBytes, "nonexistent.minisig", pubKeyFile)
		if err == nil {
			t.Fatal("expected error for missing sigfile")
		}
	})
}

func TestFindChecksumSignature(t *testing.T) {
	cfg := &defaults

	t.Run("finds SHA256SUMS.minisig", func(t *testing.T) {
		assets := []Asset{
			{Name: "binary.tar.gz"},
			{Name: "SHA256SUMS"},
			{Name: "SHA256SUMS.minisig"},
		}
		sigAsset, checksumName := findChecksumSignature(assets, cfg)
		if sigAsset == nil {
			t.Fatal("expected to find checksum signature")
		}
		if sigAsset.Name != "SHA256SUMS.minisig" {
			t.Errorf("expected SHA256SUMS.minisig, got %s", sigAsset.Name)
		}
		if checksumName != "SHA256SUMS" {
			t.Errorf("expected SHA256SUMS, got %s", checksumName)
		}
	})

	t.Run("finds SHA256SUMS.asc", func(t *testing.T) {
		assets := []Asset{
			{Name: "binary.tar.gz"},
			{Name: "SHA256SUMS"},
			{Name: "SHA256SUMS.asc"},
		}
		sigAsset, checksumName := findChecksumSignature(assets, cfg)
		if sigAsset == nil {
			t.Fatal("expected to find checksum signature")
		}
		if sigAsset.Name != "SHA256SUMS.asc" {
			t.Errorf("expected SHA256SUMS.asc, got %s", sigAsset.Name)
		}
		if checksumName != "SHA256SUMS" {
			t.Errorf("expected SHA256SUMS, got %s", checksumName)
		}
	})

	t.Run("prefers minisig over asc", func(t *testing.T) {
		assets := []Asset{
			{Name: "SHA256SUMS"},
			{Name: "SHA256SUMS.minisig"},
			{Name: "SHA256SUMS.asc"},
		}
		sigAsset, _ := findChecksumSignature(assets, cfg)
		if sigAsset == nil {
			t.Fatal("expected to find checksum signature")
		}
		// minisig comes before asc in ChecksumSigCandidates
		if sigAsset.Name != "SHA256SUMS.minisig" {
			t.Errorf("expected SHA256SUMS.minisig (preferred), got %s", sigAsset.Name)
		}
	})

	t.Run("no checksum sig found", func(t *testing.T) {
		assets := []Asset{
			{Name: "binary.tar.gz"},
			{Name: "SHA256SUMS"},
			{Name: "binary.tar.gz.asc"}, // per-asset sig, not checksum sig
		}
		sigAsset, _ := findChecksumSignature(assets, cfg)
		if sigAsset != nil {
			t.Errorf("expected nil, got %s", sigAsset.Name)
		}
	})
}

func TestMergeConfigPreferChecksumSig(t *testing.T) {
	t.Run("default is true", func(t *testing.T) {
		cfg := defaults
		if !cfg.preferChecksumSig() {
			t.Error("expected default preferChecksumSig to be true")
		}
	})

	t.Run("override to false", func(t *testing.T) {
		override := RepoConfig{
			BinaryName:        "test",
			PreferChecksumSig: boolPtr(false),
		}
		cfg := mergeConfig(defaults, override)
		if cfg.preferChecksumSig() {
			t.Error("expected preferChecksumSig to be false after override")
		}
	})

	t.Run("no override keeps default", func(t *testing.T) {
		override := RepoConfig{
			BinaryName: "test",
			// PreferChecksumSig not set (nil)
		}
		cfg := mergeConfig(defaults, override)
		if !cfg.preferChecksumSig() {
			t.Error("expected preferChecksumSig to remain true when not overridden")
		}
	})
}

func TestSignatureFormatFromExtension(t *testing.T) {
	formats := defaults.SignatureFormats

	tests := []struct {
		filename string
		want     string
	}{
		{"SHA256SUMS.minisig", sigFormatMinisign},
		{"binary.tar.gz.minisig", sigFormatMinisign},
		{"SHA256SUMS.asc", sigFormatPGP},
		{"binary.tar.gz.asc", sigFormatPGP},
		{"binary.tar.gz.sig", sigFormatBinary},
		{"binary.tar.gz.sig.ed25519", sigFormatBinary},
		{"unknown.txt", ""},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := signatureFormatFromExtension(tt.filename, formats)
			if got != tt.want {
				t.Errorf("signatureFormatFromExtension(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestAutoDetectMinisignKeyAsset(t *testing.T) {
	tests := []struct {
		name   string
		assets []Asset
		want   string // expected asset name, "" if nil
	}{
		{
			name: "finds sfetch-release-minisign.pub",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "SHA256SUMS"},
				{Name: "sfetch-release-minisign.pub"},
			},
			want: "sfetch-release-minisign.pub",
		},
		{
			name: "finds project-signing-key.pub",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "project-signing-key.pub"},
			},
			want: "project-signing-key.pub",
		},
		{
			name: "finds release-key.pub",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "release-key.pub"},
			},
			want: "release-key.pub",
		},
		{
			name: "prefers minisign over signing-key",
			assets: []Asset{
				{Name: "project-minisign.pub"},
				{Name: "project-signing-key.pub"},
			},
			want: "project-minisign.pub",
		},
		{
			name: "ignores non-.pub files",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "SHA256SUMS"},
				{Name: "minisign.key"}, // private key, not .pub
			},
			want: "",
		},
		{
			name: "ignores archive-like names",
			assets: []Asset{
				{Name: "minisign.tar.gz.pub"}, // unlikely but possible
			},
			want: "",
		},
		{
			name: "no minisign key found",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "SHA256SUMS"},
				{Name: "release-key.asc"}, // PGP, not minisign
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := autoDetectMinisignKeyAsset(tt.assets)
			if tt.want == "" {
				if got != nil {
					t.Errorf("expected nil, got %s", got.Name)
				}
			} else {
				if got == nil {
					t.Errorf("expected %s, got nil", tt.want)
				} else if got.Name != tt.want {
					t.Errorf("expected %s, got %s", tt.want, got.Name)
				}
			}
		})
	}
}

func TestAssessRelease(t *testing.T) {
	cfg := &defaults

	tests := []struct {
		name         string
		assets       []Asset
		flags        assessmentFlags
		wantWorkflow string
		wantTrust    string
		wantSigAvail bool
		wantCSAvail  bool
	}{
		{
			name: "workflow A: checksum-level minisign",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "SHA256SUMS"},
				{Name: "SHA256SUMS.minisig"},
			},
			flags:        assessmentFlags{},
			wantWorkflow: workflowA,
			wantTrust:    trustHigh,
			wantSigAvail: true,
			wantCSAvail:  true,
		},
		{
			name: "workflow A: checksum-level PGP",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "SHA256SUMS"},
				{Name: "SHA256SUMS.asc"},
			},
			flags:        assessmentFlags{},
			wantWorkflow: workflowA,
			wantTrust:    trustHigh,
			wantSigAvail: true,
			wantCSAvail:  true,
		},
		{
			name: "workflow B: per-asset minisign",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "binary.tar.gz.minisig"},
			},
			flags:        assessmentFlags{},
			wantWorkflow: workflowB,
			wantTrust:    trustMedium, // no checksum file
			wantSigAvail: true,
			wantCSAvail:  false,
		},
		{
			name: "workflow B: per-asset with checksum",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "binary.tar.gz.minisig"},
				{Name: "SHA256SUMS"},
			},
			flags:        assessmentFlags{},
			wantWorkflow: workflowB,
			wantTrust:    trustHigh,
			wantSigAvail: true,
			wantCSAvail:  true,
		},
		{
			name: "workflow C: checksum-only consolidated",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "SHA256SUMS"},
			},
			flags:        assessmentFlags{},
			wantWorkflow: workflowC,
			wantTrust:    trustLow,
			wantSigAvail: false,
			wantCSAvail:  true,
		},
		{
			name: "workflow C: checksum-only per-asset",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "binary.tar.gz.sha256"},
			},
			flags:        assessmentFlags{},
			wantWorkflow: workflowC,
			wantTrust:    trustLow,
			wantSigAvail: false,
			wantCSAvail:  true,
		},
		{
			name: "nothing available",
			assets: []Asset{
				{Name: "binary.tar.gz"},
			},
			flags:        assessmentFlags{},
			wantWorkflow: "",
			wantTrust:    trustNone,
			wantSigAvail: false,
			wantCSAvail:  false,
		},
		{
			name: "insecure flag bypasses everything",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "SHA256SUMS"},
				{Name: "SHA256SUMS.minisig"},
			},
			flags:        assessmentFlags{insecure: true},
			wantWorkflow: workflowInsecure,
			wantTrust:    trustNone,
			wantSigAvail: false,
			wantCSAvail:  false,
		},
		{
			name: "skip-sig falls back to checksum-only",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "SHA256SUMS"},
				{Name: "SHA256SUMS.minisig"},
			},
			flags:        assessmentFlags{skipSig: true},
			wantWorkflow: workflowC,
			wantTrust:    trustLow,
			wantSigAvail: false, // sig is available but we're skipping it
			wantCSAvail:  true,
		},
		{
			name: "prefer-per-asset bypasses workflow A",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "SHA256SUMS"},
				{Name: "SHA256SUMS.minisig"},
				{Name: "binary.tar.gz.minisig"},
			},
			flags:        assessmentFlags{preferPerAsset: true},
			wantWorkflow: workflowB,
			wantTrust:    trustHigh,
			wantSigAvail: true,
			wantCSAvail:  true,
		},
		{
			name: "skip-checksum with workflow A",
			assets: []Asset{
				{Name: "binary.tar.gz"},
				{Name: "SHA256SUMS"},
				{Name: "SHA256SUMS.minisig"},
			},
			flags:        assessmentFlags{skipChecksum: true},
			wantWorkflow: workflowA,
			wantTrust:    trustMedium, // downgraded because checksum skipped
			wantSigAvail: true,
			wantCSAvail:  true, // still available, just not verified
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel := &Release{
				TagName: "v1.0.0",
				Assets:  tt.assets,
			}
			selected := &tt.assets[0] // assume first asset is the binary

			assessment := assessRelease(rel, cfg, selected, tt.flags)

			if assessment.Workflow != tt.wantWorkflow {
				t.Errorf("Workflow = %q, want %q", assessment.Workflow, tt.wantWorkflow)
			}
			if assessment.TrustLevel != tt.wantTrust {
				t.Errorf("TrustLevel = %q, want %q", assessment.TrustLevel, tt.wantTrust)
			}
			if assessment.SignatureAvailable != tt.wantSigAvail {
				t.Errorf("SignatureAvailable = %v, want %v", assessment.SignatureAvailable, tt.wantSigAvail)
			}
			if assessment.ChecksumAvailable != tt.wantCSAvail {
				t.Errorf("ChecksumAvailable = %v, want %v", assessment.ChecksumAvailable, tt.wantCSAvail)
			}
		})
	}
}

func TestDetectChecksumType(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"SHA256SUMS", "consolidated"},
		{"SHA256SUMS.txt", "consolidated"},
		{"checksums.txt", "consolidated"},
		{"CHECKSUMS", "consolidated"},
		{"binary.tar.gz.sha256", "per-asset"},
		{"binary.tar.gz.sha512", "per-asset"},
		{"binary.sha256.txt", "per-asset"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := detectChecksumType(tt.filename)
			if got != tt.want {
				t.Errorf("detectChecksumType(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatSize(tt.bytes)
			if got != tt.want {
				t.Errorf("formatSize(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestValidateMinisignPubkey(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid pubkey with comment",
			content: "untrusted comment: minisign public key\nRWT7e+JKNBATSnK/uQd5IPchvhZAw/P5v+dYoH/+rEULIvRd4G0Ij4JK",
			wantErr: false,
		},
		{
			name:    "valid pubkey bare (no comment)",
			content: "RWT7e+JKNBATSnK/uQd5IPchvhZAw/P5v+dYoH/+rEULIvRd4G0Ij4JK",
			wantErr: false,
		},
		{
			name:      "encrypted secret key",
			content:   "untrusted comment: minisign encrypted secret key\nRWRTY0IypQdxXD6UGpLJaA2v/ep2RmonxICtwcBI4LIOhefmQ7sAAAACAAAAAAAAAEAAAAAAOwDTdHAVwJzYARwOq2xRuxiFuTcY+zpt9F3qhgMiuOC95OHFWC6kS+Djp5PAYHAxOl41vYwOVoxV4l/RrulUnddrrjt4Qt3uDCRznG4xyj+byeLKPoPT/iNDTp5rDXp9gxlUyh/Us4U=",
			wantErr:   true,
			errSubstr: "SECRET KEY",
		},
		{
			name:      "unencrypted secret key",
			content:   "untrusted comment: minisign secret key\nRWQAAEIyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzqVnQoBzwWZuDYZU8WK9MTT4mESA+kiXcitMr5vZgZaC0t/MDURK3i5F//E7JbxKYl0ou9JImxHXSE7f+Jx9LKlRAGGoqRoyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			wantErr:   true,
			errSubstr: "SECRET KEY",
		},
		{
			name:      "signature file (4 lines)",
			content:   "untrusted comment: signature\ntrusted comment: timestamp\nRWsomesig==\nsomeotherstuff",
			wantErr:   true,
			errSubstr: "4 lines",
		},
		{
			name:      "empty file",
			content:   "",
			wantErr:   true,
			errSubstr: "not a minisign key", // empty string doesn't start with RW
		},
		{
			name:      "wrong prefix",
			content:   "ABC7e+JKNBATSnK/uQd5IPchvhZAw/P5v+dYoH/+rEULIvRd4G0Ij4JK",
			wantErr:   true,
			errSubstr: "not a minisign key",
		},
		{
			name:      "too short",
			content:   "RWT7e+JKNBAT",
			wantErr:   true,
			errSubstr: "too short",
		},
		{
			name:      "too long (but not secret key)",
			content:   "RWT7e+JKNBATSnK/uQd5IPchvhZAw/P5v+dYoH/+rEULIvRd4G0Ij4JKEXTRA",
			wantErr:   true,
			errSubstr: "invalid key length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write content to temp file
			tmpFile, err := os.CreateTemp("", "minisign-test-*.pub")
			if err != nil {
				t.Fatalf("create temp: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.WriteString(tt.content); err != nil {
				t.Fatalf("write temp: %v", err)
			}
			tmpFile.Close()

			err = ValidateMinisignPubkey(tmpFile.Name())

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestResolveMinisignKey(t *testing.T) {
	t.Run("local file", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "key.pub")
		if err := os.WriteFile(path, []byte("local minisign key"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		got, err := resolveMinisignKey(path, "", "", nil, tmp)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got != path {
			t.Fatalf("want %s got %s", path, got)
		}
	})

	t.Run("remote via minisign-key-url", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("remote minisign key"))
		}))
		defer server.Close()
		tmp := t.TempDir()
		got, err := resolveMinisignKey("", server.URL+"/key.pub", "", nil, tmp)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		data, err := os.ReadFile(got)
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		if string(data) != "remote minisign key" {
			t.Fatalf("unexpected data: %s", data)
		}
	})

	t.Run("release asset via minisign-key-asset", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("asset minisign key"))
		}))
		defer server.Close()
		tmp := t.TempDir()
		assets := []Asset{{Name: "project-minisign.pub", BrowserDownloadUrl: server.URL + "/project-minisign.pub"}}
		got, err := resolveMinisignKey("", "", "project-minisign.pub", assets, tmp)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		data, err := os.ReadFile(got)
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		if string(data) != "asset minisign key" {
			t.Fatalf("unexpected data: %s", data)
		}
	})

	t.Run("auto-detect minisign key", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("auto-detected minisign key"))
		}))
		defer server.Close()
		tmp := t.TempDir()
		assets := []Asset{{Name: "sfetch-release-minisign.pub", BrowserDownloadUrl: server.URL + "/sfetch-release-minisign.pub"}}
		got, err := resolveMinisignKey("", "", "", assets, tmp)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		data, err := os.ReadFile(got)
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		if string(data) != "auto-detected minisign key" {
			t.Fatalf("unexpected data: %s", data)
		}
	})

	t.Run("local path as URL", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("url-as-local-path key"))
		}))
		defer server.Close()
		tmp := t.TempDir()
		// Pass URL in localPath position (first arg)
		got, err := resolveMinisignKey(server.URL+"/key.pub", "", "", nil, tmp)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		data, err := os.ReadFile(got)
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		if string(data) != "url-as-local-path key" {
			t.Fatalf("unexpected data: %s", data)
		}
	})

	t.Run("missing asset", func(t *testing.T) {
		tmp := t.TempDir()
		assets := []Asset{{Name: "other-asset.txt"}}
		_, err := resolveMinisignKey("", "", "nonexistent.pub", assets, tmp)
		if err == nil {
			t.Fatal("expected error for missing asset")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("expected 'not found' in error, got: %v", err)
		}
	})

	t.Run("missing local file", func(t *testing.T) {
		tmp := t.TempDir()
		_, err := resolveMinisignKey("/nonexistent/path.pub", "", "", nil, tmp)
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("no inputs and no auto-detect match", func(t *testing.T) {
		tmp := t.TempDir()
		assets := []Asset{{Name: "binary.tar.gz"}}
		_, err := resolveMinisignKey("", "", "", assets, tmp)
		if err == nil {
			t.Fatal("expected error when no key sources available")
		}
		if !strings.Contains(err.Error(), "--minisign-key") {
			t.Errorf("expected helpful error message mentioning flags, got: %v", err)
		}
	})
}

// TestProvenanceSchemaValidity validates that provenance.schema.json is valid JSON Schema 2020-12.
// This catches schema syntax errors during development.
func TestProvenanceSchemaValidity(t *testing.T) {
	c := jsonschema.NewCompiler()
	_, err := c.Compile("schemas/provenance.schema.json")
	if err != nil {
		t.Fatalf("provenance schema is not valid JSON Schema 2020-12: %v", err)
	}
}

// TestRepoConfigSchemaValidity validates that repo-config.schema.json is valid JSON Schema 2020-12.
func TestRepoConfigSchemaValidity(t *testing.T) {
	c := jsonschema.NewCompiler()
	_, err := c.Compile("schemas/repo-config.schema.json")
	if err != nil {
		t.Fatalf("repo-config schema is not valid JSON Schema 2020-12: %v", err)
	}
}

// TestProvenanceRecordValidation validates that ProvenanceRecord output conforms to the schema.
func TestProvenanceRecordValidation(t *testing.T) {
	c := jsonschema.NewCompiler()
	schema, err := c.Compile("schemas/provenance.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	tests := []struct {
		name    string
		record  ProvenanceRecord
		wantErr bool
	}{
		{
			name: "valid workflow A (high trust)",
			record: ProvenanceRecord{
				Schema:        "https://github.com/3leaps/sfetch/schemas/provenance.schema.json",
				Version:       "1.0.0",
				Timestamp:     "2025-12-09T14:30:00Z",
				SfetchVersion: "v2025.12.09",
				Source: ProvenanceSource{
					Type:       "github",
					Repository: "3leaps/sfetch",
					Release:    &ProvenanceRelease{Tag: "v2025.12.09", URL: "https://github.com/3leaps/sfetch/releases/tag/v2025.12.09"},
				},
				Asset: ProvenanceAsset{
					Name: "sfetch_darwin_arm64.tar.gz",
					Size: 2200000,
					URL:  "https://github.com/3leaps/sfetch/releases/download/v2025.12.09/sfetch_darwin_arm64.tar.gz",
					ComputedChecksum: &ProvenanceHash{
						Algorithm: "sha256",
						Value:     "abc123def456",
					},
				},
				Verification: ProvenanceVerify{
					Workflow: "A",
					Signature: ProvenanceSigStatus{
						Available: true,
						Format:    "minisign",
						File:      "SHA256SUMS.minisig",
						KeySource: "asset",
						Verified:  true,
						Skipped:   false,
					},
					Checksum: ProvenanceCSStatus{
						Available: true,
						Algorithm: "sha256",
						File:      "SHA256SUMS",
						Type:      "consolidated",
						Verified:  true,
						Skipped:   false,
					},
				},
				TrustLevel: "high",
			},
			wantErr: false,
		},
		{
			name: "valid workflow C (low trust)",
			record: ProvenanceRecord{
				Schema:        "https://github.com/3leaps/sfetch/schemas/provenance.schema.json",
				Version:       "1.0.0",
				Timestamp:     "2025-12-09T14:30:00Z",
				SfetchVersion: "v2025.12.09",
				Source: ProvenanceSource{
					Type:       "github",
					Repository: "BurntSushi/ripgrep",
					Release:    &ProvenanceRelease{Tag: "v15.1.0", URL: "https://github.com/BurntSushi/ripgrep/releases/tag/v15.1.0"},
				},
				Asset: ProvenanceAsset{
					Name: "ripgrep-15.1.0-aarch64-apple-darwin.tar.gz",
					Size: 1700000,
					URL:  "https://github.com/BurntSushi/ripgrep/releases/download/v15.1.0/ripgrep-15.1.0-aarch64-apple-darwin.tar.gz",
					ComputedChecksum: &ProvenanceHash{
						Algorithm: "sha256",
						Value:     "fedcba987654",
					},
				},
				Verification: ProvenanceVerify{
					Workflow: "C",
					Signature: ProvenanceSigStatus{
						Available: false,
						Verified:  false,
						Skipped:   false,
						Reason:    "no signature file found in release",
					},
					Checksum: ProvenanceCSStatus{
						Available: true,
						Algorithm: "sha256",
						File:      "ripgrep-15.1.0-aarch64-apple-darwin.tar.gz.sha256",
						Type:      "per-asset",
						Verified:  true,
						Skipped:   false,
					},
				},
				TrustLevel: "low",
				Warnings:   []string{"No signature available; authenticity cannot be proven"},
			},
			wantErr: false,
		},
		{
			name: "valid insecure workflow",
			record: ProvenanceRecord{
				Schema:        "https://github.com/3leaps/sfetch/schemas/provenance.schema.json",
				Version:       "1.0.0",
				Timestamp:     "2025-12-09T14:30:00Z",
				SfetchVersion: "v2025.12.09",
				Source: ProvenanceSource{
					Type:       "github",
					Repository: "sharkdp/bat",
					Release:    &ProvenanceRelease{Tag: "v0.24.0", URL: "https://github.com/sharkdp/bat/releases/tag/v0.24.0"},
				},
				Asset: ProvenanceAsset{
					Name: "bat-v0.24.0-aarch64-apple-darwin.tar.gz",
					Size: 1500000,
					URL:  "https://github.com/sharkdp/bat/releases/download/v0.24.0/bat-v0.24.0-aarch64-apple-darwin.tar.gz",
				},
				Verification: ProvenanceVerify{
					Workflow: "insecure",
					Signature: ProvenanceSigStatus{
						Available: false,
						Verified:  false,
						Skipped:   true,
						Reason:    "--insecure flag specified",
					},
					Checksum: ProvenanceCSStatus{
						Available: false,
						Verified:  false,
						Skipped:   true,
						Reason:    "--insecure flag specified",
					},
				},
				TrustLevel: "none",
				Flags:      ProvenanceFlags{Insecure: true},
				Warnings:   []string{"No verification performed (--insecure)"},
			},
			wantErr: false,
		},
		{
			name: "valid dry-run assessment",
			record: ProvenanceRecord{
				Schema:        "https://github.com/3leaps/sfetch/schemas/provenance.schema.json",
				Version:       "1.0.0",
				Timestamp:     "2025-12-09T14:30:00Z",
				SfetchVersion: "v2025.12.09",
				Source: ProvenanceSource{
					Type:       "github",
					Repository: "jesseduffield/lazygit",
					Release:    &ProvenanceRelease{Tag: "v0.40.2", URL: "https://github.com/jesseduffield/lazygit/releases/tag/v0.40.2"},
				},
				Asset: ProvenanceAsset{
					Name: "lazygit_0.40.2_Darwin_arm64.tar.gz",
					Size: 5000000,
					URL:  "https://github.com/jesseduffield/lazygit/releases/download/v0.40.2/lazygit_0.40.2_Darwin_arm64.tar.gz",
					// No ComputedChecksum for dry-run (not downloaded)
				},
				Verification: ProvenanceVerify{
					Workflow: "C",
					Signature: ProvenanceSigStatus{
						Available: false,
						Verified:  false,
						Skipped:   false,
						Reason:    "no signature file found in release",
					},
					Checksum: ProvenanceCSStatus{
						Available: true,
						Algorithm: "sha256",
						File:      "checksums.txt",
						Type:      "consolidated",
						Verified:  false, // not verified in dry-run
						Skipped:   false,
					},
				},
				TrustLevel: "low",
				Flags:      ProvenanceFlags{DryRun: true},
				Warnings:   []string{"No signature available; authenticity cannot be proven"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON and back to interface{} for validation
			jsonBytes, err := json.Marshal(tt.record)
			if err != nil {
				t.Fatalf("marshal record: %v", err)
			}

			var doc interface{}
			if err := json.Unmarshal(jsonBytes, &doc); err != nil {
				t.Fatalf("unmarshal to interface: %v", err)
			}

			err = schema.Validate(doc)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected validation error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected validation error: %v\nJSON: %s", err, jsonBytes)
				}
			}
		})
	}
}

// TestProvenanceSchemaRejectsInvalid ensures the schema properly rejects invalid records.
func TestProvenanceSchemaRejectsInvalid(t *testing.T) {
	c := jsonschema.NewCompiler()
	schema, err := c.Compile("schemas/provenance.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	tests := []struct {
		name string
		json string
	}{
		{
			name: "missing required version field",
			json: `{
				"$schema": "https://github.com/3leaps/sfetch/schemas/provenance.schema.json",
				"timestamp": "2025-12-09T14:30:00Z",
				"source": {"type": "github"},
				"asset": {"name": "test.tar.gz"},
				"verification": {
					"workflow": "A",
					"signature": {"available": true, "verified": true, "skipped": false},
					"checksum": {"available": true, "verified": true, "skipped": false}
				},
				"trustLevel": "high"
			}`,
		},
		{
			name: "invalid trust level",
			json: `{
				"$schema": "https://github.com/3leaps/sfetch/schemas/provenance.schema.json",
				"version": "1.0.0",
				"timestamp": "2025-12-09T14:30:00Z",
				"source": {"type": "github"},
				"asset": {"name": "test.tar.gz"},
				"verification": {
					"workflow": "A",
					"signature": {"available": true, "verified": true, "skipped": false},
					"checksum": {"available": true, "verified": true, "skipped": false}
				},
				"trustLevel": "super-high"
			}`,
		},
		{
			name: "invalid workflow value",
			json: `{
				"$schema": "https://github.com/3leaps/sfetch/schemas/provenance.schema.json",
				"version": "1.0.0",
				"timestamp": "2025-12-09T14:30:00Z",
				"source": {"type": "github"},
				"asset": {"name": "test.tar.gz"},
				"verification": {
					"workflow": "X",
					"signature": {"available": true, "verified": true, "skipped": false},
					"checksum": {"available": true, "verified": true, "skipped": false}
				},
				"trustLevel": "high"
			}`,
		},
		{
			name: "invalid source type",
			json: `{
				"$schema": "https://github.com/3leaps/sfetch/schemas/provenance.schema.json",
				"version": "1.0.0",
				"timestamp": "2025-12-09T14:30:00Z",
				"source": {"type": "gitlab"},
				"asset": {"name": "test.tar.gz"},
				"verification": {
					"workflow": "A",
					"signature": {"available": true, "verified": true, "skipped": false},
					"checksum": {"available": true, "verified": true, "skipped": false}
				},
				"trustLevel": "high"
			}`,
		},
		{
			name: "invalid signature format",
			json: `{
				"$schema": "https://github.com/3leaps/sfetch/schemas/provenance.schema.json",
				"version": "1.0.0",
				"timestamp": "2025-12-09T14:30:00Z",
				"source": {"type": "github"},
				"asset": {"name": "test.tar.gz"},
				"verification": {
					"workflow": "A",
					"signature": {"available": true, "format": "rsa", "verified": true, "skipped": false},
					"checksum": {"available": true, "verified": true, "skipped": false}
				},
				"trustLevel": "high"
			}`,
		},
		{
			name: "additional properties not allowed",
			json: `{
				"$schema": "https://github.com/3leaps/sfetch/schemas/provenance.schema.json",
				"version": "1.0.0",
				"timestamp": "2025-12-09T14:30:00Z",
				"source": {"type": "github"},
				"asset": {"name": "test.tar.gz"},
				"verification": {
					"workflow": "A",
					"signature": {"available": true, "verified": true, "skipped": false},
					"checksum": {"available": true, "verified": true, "skipped": false}
				},
				"trustLevel": "high",
				"extraField": "should fail"
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc interface{}
			if err := json.Unmarshal([]byte(tt.json), &doc); err != nil {
				t.Fatalf("unmarshal test JSON: %v", err)
			}

			err := schema.Validate(doc)
			if err == nil {
				t.Errorf("expected validation error for invalid record, got nil")
			}
		})
	}
}
