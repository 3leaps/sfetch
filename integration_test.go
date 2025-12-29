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
	cmd := exec.Command("go", "run", ".", "--repo", "test/example", "--latest", "--dest-dir", destDir, "--pgp-key-file", "testdata/keys/test-pgp-pub.asc", "--gpg-bin", gpgPath, "--cache-dir", cacheDir, "--binary-name", "sfetch")
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
		"--binary-name", "sfetch",
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
		"--binary-name", "sfetch",
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

func TestIntegrationInsecureStillInstalls(t *testing.T) {
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
		case "/repos/test/insecure/releases/latest":
			base := fmt.Sprintf("http://%s", r.Host)
			rel := fakeRelease{
				TagName: "v0.1.0",
				Assets: []Asset{
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
	cmd := exec.Command("go", "run", ".",
		"--repo", "test/insecure",
		"--latest",
		"--dest-dir", destDir,
		"--cache-dir", cacheDir,
		"--binary-name", "sfetch",
		"--insecure",
	)
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

	if !bytes.Contains(output.Bytes(), []byte("WARNING: verification bypass enabled (--insecure)")) {
		t.Fatalf("expected insecure warning in output:\n%s", output.String())
	}
}

func TestIntegrationTrustMinimumBlocksUnsigned(t *testing.T) {
	assetBytes, err := os.ReadFile("testdata/integration/sfetch_test_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatalf("read asset: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/test/unsigned/releases/latest":
			base := fmt.Sprintf("http://%s", r.Host)
			rel := fakeRelease{
				TagName: "v0.1.0",
				Assets: []Asset{
					// No signature or checksum assets.
					{Name: "sfetch_test_darwin_arm64.tar.gz", BrowserDownloadUrl: base + "/assets/bin"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(&rel); err != nil {
				t.Fatalf("encode release: %v", err)
			}
		case "/assets/bin":
			_, _ = w.Write(assetBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	destDir := t.TempDir()
	cacheDir := filepath.Join(destDir, "cache")
	cmd := exec.Command("go", "run", ".",
		"--repo", "test/unsigned",
		"--latest",
		"--dest-dir", destDir,
		"--cache-dir", cacheDir,
		"--trust-minimum", "30",
	)
	cmd.Env = append(os.Environ(), "SFETCH_API_BASE="+ts.URL)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err = cmd.Run()
	if err == nil {
		t.Fatalf("expected sfetch to fail due to --trust-minimum\noutput:\n%s", output.String())
	}
	if !bytes.Contains(output.Bytes(), []byte("below --trust-minimum 30")) {
		t.Fatalf("expected trust-minimum error in output:\n%s", output.String())
	}
	if _, err := os.Stat(filepath.Join(destDir, "sfetch")); err == nil {
		t.Fatalf("did not expect binary to be installed when trust-minimum blocks")
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

func TestIntegrationSelfUpdate(t *testing.T) {
	// Skip if network access not desired (this test hits mock server but could be extended)
	if os.Getenv("SFETCH_SKIP_NETWORK_TESTS") != "" {
		t.Skip("skipping network-dependent test")
	}

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
		case "/repos/3leaps/sfetch/releases/latest":
			base := fmt.Sprintf("http://%s", r.Host)
			rel := fakeRelease{
				TagName: "v0.3.0", // Major version jump from v0.2.2
				Assets: []Asset{
					{Name: "sfetch-darwin-arm64", BrowserDownloadUrl: base + "/assets/bin"}, // Raw binary for current platform
					{Name: "SHA256SUMS", BrowserDownloadUrl: base + "/assets/sha"},
					{Name: "SHA256SUMS.minisig", BrowserDownloadUrl: base + "/assets/sha-minisig"},
					{Name: "sfetch-minisign.pub", BrowserDownloadUrl: base + "/assets/pubkey"},
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

	// Test 1: Dry-run from dev build should succeed and show install message
	t.Run("dry-run-dev-build-proceeds", func(t *testing.T) {
		cmd := exec.Command("go", "run", ".",
			"--self-update",
			"--dry-run",
		)
		cmd.Env = append(os.Environ(), "SFETCH_API_BASE="+ts.URL)
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		err := cmd.Run()
		if err != nil {
			t.Fatalf("expected dry-run from dev build to succeed: %v\noutput:\n%s", err, output.String())
		}

		// Should show dev install message (replacing dev build)
		if !bytes.Contains(output.Bytes(), []byte("dev")) {
			t.Errorf("expected dev build mention in output:\n%s", output.String())
		}
	})

	// Test 2: Force flag should allow major version jump in dry-run
	t.Run("dry-run-force-allows-major-version", func(t *testing.T) {
		cmd := exec.Command("go", "run", ".",
			"--self-update",
			"--self-update-force",
			"--dry-run",
		)
		cmd.Env = append(os.Environ(), "SFETCH_API_BASE="+ts.URL)
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		if err := cmd.Run(); err != nil {
			t.Fatalf("dry-run with force should succeed: %v\noutput:\n%s", err, output.String())
		}

		// Should show successful assessment
		if !bytes.Contains(output.Bytes(), []byte("Self-update target:")) {
			t.Errorf("expected self-update target message in output:\n%s", output.String())
		}
	})

	// Test 3: Test path computation with custom dir
	t.Run("custom-install-dir", func(t *testing.T) {
		customDir := filepath.Join(destDir, "custom")
		cmd := exec.Command("go", "run", ".",
			"--self-update",
			"--self-update-dir", customDir,
			"--self-update-force",
			"--dry-run",
		)
		cmd.Env = append(os.Environ(), "SFETCH_API_BASE="+ts.URL)
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		if err := cmd.Run(); err != nil {
			t.Fatalf("dry-run with custom dir should succeed: %v\noutput:\n%s", err, output.String())
		}

		expectedPath := filepath.Join(customDir, "sfetch")
		if !bytes.Contains(output.Bytes(), []byte(expectedPath)) {
			t.Errorf("expected custom path %s in output:\n%s", expectedPath, output.String())
		}
	})
}
