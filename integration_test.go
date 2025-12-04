package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type fakeRelease struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

func TestIntegrationPGPSignature(t *testing.T) {
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not found in PATH")
	}

	assetBytes, err := os.ReadFile("testdata/integration/sfetch_test_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatalf("read asset: %v", err)
	}
	shaBytes, err := os.ReadFile("testdata/integration/SHA256SUMS")
	if err != nil {
		t.Fatalf("read checksum: %v", err)
	}
	sigBytes, err := os.ReadFile("testdata/integration/sfetch_test_darwin_arm64.tar.gz.asc")
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/test/example/releases/latest":
			base := fmt.Sprintf("http://%s", r.Host)
			rel := fakeRelease{
				TagName: "v0.1.0",
				Assets: []Asset{
					{Name: "sfetch_test_darwin_amd64.tar.gz", BrowserDownloadUrl: base + "/assets/amd64"}, // tie candidate
					{Name: "sfetch_test_darwin_arm64.tar.gz", BrowserDownloadUrl: base + "/assets/bin"},   // expected
					{Name: "SHA256SUMS", BrowserDownloadUrl: base + "/assets/sha"},
					{Name: "sfetch_test_darwin_arm64.tar.gz.asc", BrowserDownloadUrl: base + "/assets/sig"},
					{Name: "sfetch_test_darwin_amd64.tar.gz.asc", BrowserDownloadUrl: base + "/assets/sig-amd64"}, // supplemental
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(&rel); err != nil {
				t.Fatalf("encode release: %v", err)
			}
		case "/assets/amd64":
			w.Write(assetBytes) // fake same bytes
		case "/assets/bin":
			w.Write(assetBytes)
		case "/assets/sha":
			w.Write(shaBytes)
		case "/assets/sig":
			w.Write(sigBytes)
		case "/assets/sig-amd64":
			w.Write(sigBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	destDir := t.TempDir()
	cacheDir := filepath.Join(destDir, "cache")
	cmd := exec.Command("go", "run", ".", "--repo", "test/example", "--latest", "--dest-dir", destDir, "--pgp-key-file", "testdata/keys/test-pgp-pub.asc", "--gpg-bin", gpgPath, "--cache-dir", cacheDir)
	cmd.Env = append(os.Environ(), "SFETCH_API_BASE="+ts.URL)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("sfetch failed: %v\noutput:\n%s", err, output.String())
	}

	installed := filepath.Join(destDir, "sfetch")
	if _, err := os.Stat(installed); err != nil {
		t.Fatalf("expected installed binary at %s: %v", installed, err)
	}
}
