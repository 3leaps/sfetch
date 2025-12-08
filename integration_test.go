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

func TestIntegrationMinisignChecksumLevel(t *testing.T) {
	// Test checksum-level minisign verification (Workflow A)
	assetBytes, err := os.ReadFile("testdata/integration/sfetch_test_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatalf("read asset: %v", err)
	}
	shaBytes, err := os.ReadFile("testdata/integration/SHA256SUMS")
	if err != nil {
		t.Fatalf("read checksum: %v", err)
	}
	minisigBytes, err := os.ReadFile("testdata/integration/SHA256SUMS.minisig")
	if err != nil {
		t.Fatalf("read minisig: %v", err)
	}
	pubKeyBytes, err := os.ReadFile("testdata/integration/test-minisign.pub")
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/test/minisign-example/releases/latest":
			base := fmt.Sprintf("http://%s", r.Host)
			rel := fakeRelease{
				TagName: "v0.2.0",
				Assets: []Asset{
					{Name: "sfetch_test_darwin_amd64.tar.gz", BrowserDownloadUrl: base + "/assets/amd64"},
					{Name: "sfetch_test_darwin_arm64.tar.gz", BrowserDownloadUrl: base + "/assets/bin"},
					{Name: "SHA256SUMS", BrowserDownloadUrl: base + "/assets/sha"},
					{Name: "SHA256SUMS.minisig", BrowserDownloadUrl: base + "/assets/sha-minisig"},
					{Name: "test-minisign.pub", BrowserDownloadUrl: base + "/assets/pubkey"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(&rel); err != nil {
				t.Fatalf("encode release: %v", err)
			}
		case "/assets/amd64":
			_, _ = w.Write(assetBytes)
		case "/assets/bin":
			_, _ = w.Write(assetBytes)
		case "/assets/sha":
			_, _ = w.Write(shaBytes)
		case "/assets/sha-minisig":
			_, _ = w.Write(minisigBytes)
		case "/assets/pubkey":
			_, _ = w.Write(pubKeyBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	destDir := t.TempDir()
	cacheDir := filepath.Join(destDir, "cache")

	// Test with --minisign-key-asset (auto-fetch key from release)
	cmd := exec.Command("go", "run", ".",
		"--repo", "test/minisign-example",
		"--latest",
		"--dest-dir", destDir,
		"--minisign-key-asset", "test-minisign.pub",
		"--cache-dir", cacheDir,
	)
	cmd.Env = append(os.Environ(), "SFETCH_API_BASE="+ts.URL)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("sfetch failed: %v\noutput:\n%s", err, output.String())
	}

	// Verify output mentions minisign verification
	if !bytes.Contains(output.Bytes(), []byte("Minisign checksum signature verified OK")) {
		t.Errorf("expected minisign verification message in output:\n%s", output.String())
	}

	installed := filepath.Join(destDir, "sfetch")
	if _, err := os.Stat(installed); err != nil {
		t.Fatalf("expected installed binary at %s: %v", installed, err)
	}
}

func TestIntegrationMinisignAutoDetect(t *testing.T) {
	// Test auto-detection of minisign public key from release assets
	assetBytes, err := os.ReadFile("testdata/integration/sfetch_test_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatalf("read asset: %v", err)
	}
	shaBytes, err := os.ReadFile("testdata/integration/SHA256SUMS")
	if err != nil {
		t.Fatalf("read checksum: %v", err)
	}
	minisigBytes, err := os.ReadFile("testdata/integration/SHA256SUMS.minisig")
	if err != nil {
		t.Fatalf("read minisig: %v", err)
	}
	pubKeyBytes, err := os.ReadFile("testdata/integration/test-minisign.pub")
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/test/autodetect-example/releases/latest":
			base := fmt.Sprintf("http://%s", r.Host)
			rel := fakeRelease{
				TagName: "v0.3.0",
				Assets: []Asset{
					{Name: "sfetch_test_darwin_arm64.tar.gz", BrowserDownloadUrl: base + "/assets/bin"},
					{Name: "SHA256SUMS", BrowserDownloadUrl: base + "/assets/sha"},
					{Name: "SHA256SUMS.minisig", BrowserDownloadUrl: base + "/assets/sha-minisig"},
					// Auto-detectable minisign key name
					{Name: "release-minisign.pub", BrowserDownloadUrl: base + "/assets/pubkey"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(&rel); err != nil {
				t.Fatalf("encode release: %v", err)
			}
		case "/assets/bin":
			_, _ = w.Write(assetBytes)
		case "/assets/sha":
			_, _ = w.Write(shaBytes)
		case "/assets/sha-minisig":
			_, _ = w.Write(minisigBytes)
		case "/assets/pubkey":
			_, _ = w.Write(pubKeyBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	destDir := t.TempDir()
	cacheDir := filepath.Join(destDir, "cache")

	// Test auto-detection (no explicit key flag)
	cmd := exec.Command("go", "run", ".",
		"--repo", "test/autodetect-example",
		"--latest",
		"--dest-dir", destDir,
		"--cache-dir", cacheDir,
	)
	cmd.Env = append(os.Environ(), "SFETCH_API_BASE="+ts.URL)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("sfetch failed: %v\noutput:\n%s", err, output.String())
	}

	// Verify auto-detection message
	if !bytes.Contains(output.Bytes(), []byte("Auto-detected minisign key asset")) {
		t.Errorf("expected auto-detection message in output:\n%s", output.String())
	}

	installed := filepath.Join(destDir, "sfetch")
	if _, err := os.Stat(installed); err != nil {
		t.Fatalf("expected installed binary at %s: %v", installed, err)
	}
}

func TestIntegrationRequireMinisign(t *testing.T) {
	// Test --require-minisign fails when no minisign sig present
	assetBytes, err := os.ReadFile("testdata/integration/sfetch_test_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatalf("read asset: %v", err)
	}
	shaBytes, err := os.ReadFile("testdata/integration/SHA256SUMS")
	if err != nil {
		t.Fatalf("read checksum: %v", err)
	}
	pgpSigBytes, err := os.ReadFile("testdata/integration/sfetch_test_darwin_arm64.tar.gz.asc")
	if err != nil {
		t.Fatalf("read pgp sig: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/test/pgp-only/releases/latest":
			base := fmt.Sprintf("http://%s", r.Host)
			rel := fakeRelease{
				TagName: "v0.4.0",
				Assets: []Asset{
					{Name: "sfetch_test_darwin_arm64.tar.gz", BrowserDownloadUrl: base + "/assets/bin"},
					{Name: "SHA256SUMS", BrowserDownloadUrl: base + "/assets/sha"},
					// Only PGP sig, no minisig
					{Name: "sfetch_test_darwin_arm64.tar.gz.asc", BrowserDownloadUrl: base + "/assets/sig"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(&rel); err != nil {
				t.Fatalf("encode release: %v", err)
			}
		case "/assets/bin":
			_, _ = w.Write(assetBytes)
		case "/assets/sha":
			_, _ = w.Write(shaBytes)
		case "/assets/sig":
			_, _ = w.Write(pgpSigBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	destDir := t.TempDir()
	cacheDir := filepath.Join(destDir, "cache")

	// Test --require-minisign fails when no minisig available
	cmd := exec.Command("go", "run", ".",
		"--repo", "test/pgp-only",
		"--latest",
		"--dest-dir", destDir,
		"--require-minisign",
		"--cache-dir", cacheDir,
	)
	cmd.Env = append(os.Environ(), "SFETCH_API_BASE="+ts.URL)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err = cmd.Run()
	if err == nil {
		t.Fatalf("expected sfetch to fail with --require-minisign but no minisig present")
	}

	// Verify error message
	if !bytes.Contains(output.Bytes(), []byte("--require-minisign")) {
		t.Errorf("expected --require-minisign error in output:\n%s", output.String())
	}
}
