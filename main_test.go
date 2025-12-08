package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGetConfig(t *testing.T) {
	tests := []struct {
		repo    string
		wantBin string
	}{
		{"3leaps/sfetch", "sfetch"},
		{"unknown/repo", "sfetch"},
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
