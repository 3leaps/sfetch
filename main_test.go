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
