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
	"runtime"
	"strings"
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
			_, _ = w.Write(assetBytes) // fake same bytes; error handled by http.ResponseWriter
		case "/assets/bin":
			_, _ = w.Write(assetBytes) //nolint:errcheck // test handler, error handled by http.ResponseWriter
		case "/assets/sha":
			_, _ = w.Write(shaBytes) //nolint:errcheck // test handler, error handled by http.ResponseWriter
		case "/assets/sig":
			_, _ = w.Write(sigBytes) //nolint:errcheck // test handler, error handled by http.ResponseWriter
		case "/assets/sig-amd64":
			_, _ = w.Write(sigBytes) //nolint:errcheck // test handler, error handled by http.ResponseWriter
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

// A raw release binary with a dotted version in its name installs under the
// repo-derived binary name and is executable.
func TestIntegrationRawVersionedBinaryInstallsAsBinaryName(t *testing.T) {
	assetName := fmt.Sprintf("chanvoy-v0.3.3-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}
	payload := []byte("#!/bin/sh\necho chanvoy\n")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/test/chanvoy/releases/latest":
			base := fmt.Sprintf("http://%s", r.Host)
			rel := fakeRelease{
				TagName: "v0.3.3",
				Assets:  []Asset{{Name: assetName, BrowserDownloadUrl: base + "/assets/bin"}},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(&rel); err != nil {
				t.Errorf("encode release: %v", err)
			}
		case "/assets/bin":
			_, _ = w.Write(payload)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	destDir := t.TempDir()
	cmd := exec.Command("go", "run", ".",
		"--repo", "test/chanvoy",
		"--latest",
		"--dest-dir", destDir,
		"--cache-dir", filepath.Join(t.TempDir(), "cache"),
		"--insecure",
	)
	cmd.Env = append(os.Environ(), "SFETCH_API_BASE="+ts.URL)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("sfetch failed: %v\noutput:\n%s", err, output.String())
	}

	want := "chanvoy"
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	installed := filepath.Join(destDir, want)
	info, err := os.Stat(installed)
	if err != nil {
		entries, _ := os.ReadDir(destDir)
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected %s: %v (dest contains %v)\noutput:\n%s", installed, err, names, output.String())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("installed %s mode %v is not executable", installed, info.Mode().Perm())
	}
}

// Self-update must verify only against the embedded trust anchor. A release
// whose SHA256SUMS is signed by another key, shipped alongside that key as a
// release asset, must be rejected rather than auto-detected and trusted.
func TestIntegrationSelfUpdateRejectsReleaseSuppliedKey(t *testing.T) {
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
	attackerKey, err := os.ReadFile("testdata/integration/test-minisign.pub")
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}
	if bytes.Contains(attackerKey, []byte(EmbeddedMinisignPubkey)) {
		t.Fatal("fixture key must differ from the embedded anchor")
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/3leaps/sfetch/releases"):
			base := fmt.Sprintf("http://%s", r.Host)
			rel := fakeRelease{
				TagName: "v9.9.9",
				Assets: []Asset{
					{Name: "sfetch_test_darwin_arm64.tar.gz", BrowserDownloadUrl: base + "/assets/bin"},
					{Name: "SHA256SUMS", BrowserDownloadUrl: base + "/assets/sha"},
					{Name: "SHA256SUMS.minisig", BrowserDownloadUrl: base + "/assets/sha-minisig"},
					{Name: "sfetch-minisign.pub", BrowserDownloadUrl: base + "/assets/pubkey"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(&rel); err != nil {
				t.Errorf("encode release: %v", err)
			}
		case r.URL.Path == "/assets/bin":
			_, _ = w.Write(assetBytes)
		case r.URL.Path == "/assets/sha":
			_, _ = w.Write(shaBytes)
		case r.URL.Path == "/assets/sha-minisig":
			_, _ = w.Write(minisigBytes)
		case r.URL.Path == "/assets/pubkey":
			_, _ = w.Write(attackerKey)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	run := func(extra ...string) (string, error) {
		args := append([]string{"run", ".",
			"--self-update", "--yes", "--self-update-force",
			"--tag", "v9.9.9",
			"--self-update-dir", t.TempDir(),
			"--cache-dir", filepath.Join(t.TempDir(), "cache"),
		}, extra...)
		cmd := exec.Command("go", args...)
		cmd.Env = append(os.Environ(), "SFETCH_API_BASE="+ts.URL)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		return out.String(), err
	}

	out, err := run()
	if err == nil {
		t.Fatalf("self-update accepted a release signed by a non-anchor key:\n%s", out)
	}
	if strings.Contains(out, "Auto-detected minisign key asset") {
		t.Fatalf("self-update consulted a release-supplied key:\n%s", out)
	}
	if strings.Contains(out, "Installed ") {
		t.Fatalf("self-update installed despite failed verification:\n%s", out)
	}

	keyFile := filepath.Join(t.TempDir(), "k.pub")
	if err := os.WriteFile(keyFile, attackerKey, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{
		{"--minisign-key", keyFile},
		{"--minisign-key-asset", "sfetch-minisign.pub"},
		{"--insecure"},
		{"--skip-sig"},
	} {
		out, err := run(extra...)
		if err == nil {
			t.Fatalf("self-update accepted %v:\n%s", extra, out)
		}
		if !strings.Contains(out, "--self-update") {
			t.Fatalf("expected a --self-update refusal for %v, got:\n%s", extra, out)
		}
	}
}

// A signature is verified in the format its file name declares. A .minisig
// file that holds a PGP signature must be refused before any key is resolved;
// otherwise the PGP branch would auto-detect a release-supplied .asc key and
// bypass the configured (or, for self-update, embedded) minisign key.
func TestIntegrationRejectsSignatureFormatMismatch(t *testing.T) {
	assetBytes, err := os.ReadFile("testdata/integration/sfetch_test_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatalf("read asset: %v", err)
	}
	shaBytes, err := os.ReadFile("testdata/integration/SHA256SUMS")
	if err != nil {
		t.Fatalf("read checksum: %v", err)
	}
	pgpSig, err := os.ReadFile("testdata/integration/sfetch_test_darwin_arm64.tar.gz.asc")
	if err != nil {
		t.Fatalf("read pgp sig: %v", err)
	}
	minisig, err := os.ReadFile("testdata/integration/SHA256SUMS.minisig")
	if err != nil {
		t.Fatalf("read minisig: %v", err)
	}
	releaseKey, err := os.ReadFile("testdata/keys/test-pgp-pub.asc")
	if err != nil {
		t.Fatalf("read pgp key: %v", err)
	}

	serve := func(repoPath, sigName string, sigBytes []byte) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasPrefix(r.URL.Path, repoPath):
				base := fmt.Sprintf("http://%s", r.Host)
				rel := fakeRelease{
					TagName: "v9.9.9",
					Assets: []Asset{
						{Name: "sfetch_test_darwin_arm64.tar.gz", BrowserDownloadUrl: base + "/assets/bin"},
						{Name: "SHA256SUMS", BrowserDownloadUrl: base + "/assets/sha"},
						// Signature bytes whose format differs from the file name.
						{Name: sigName, BrowserDownloadUrl: base + "/assets/sig"},
						{Name: "release-key.asc", BrowserDownloadUrl: base + "/assets/key"},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(&rel); err != nil {
					t.Errorf("encode release: %v", err)
				}
			case r.URL.Path == "/assets/bin":
				_, _ = w.Write(assetBytes)
			case r.URL.Path == "/assets/sha":
				_, _ = w.Write(shaBytes)
			case r.URL.Path == "/assets/sig":
				_, _ = w.Write(sigBytes)
			case r.URL.Path == "/assets/key":
				_, _ = w.Write(releaseKey)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
	}
	run := func(ts *httptest.Server, args ...string) (string, error) {
		cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
		cmd.Env = append(os.Environ(), "SFETCH_API_BASE="+ts.URL)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		return out.String(), err
	}
	check := func(t *testing.T, out string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("accepted a signature whose content format differs from its file name:\n%s", out)
		}
		if strings.Contains(out, "Auto-detected PGP key asset") || strings.Contains(out, "PGP signature verified OK") {
			t.Fatalf("resolved or verified with a release-supplied PGP key:\n%s", out)
		}
		if !strings.Contains(out, "signature format mismatch") {
			t.Fatalf("expected a signature format mismatch error:\n%s", out)
		}
	}

	t.Run("self-update", func(t *testing.T) {
		ts := serve("/repos/3leaps/sfetch/releases", "sfetch_test_darwin_arm64.tar.gz.minisig", pgpSig)
		defer ts.Close()
		out, err := run(ts, "--self-update", "--yes", "--self-update-force", "--tag", "v9.9.9",
			"--self-update-dir", t.TempDir(), "--cache-dir", filepath.Join(t.TempDir(), "cache"))
		check(t, out, err)
		if strings.Contains(out, "Installed ") {
			t.Fatalf("self-update installed despite the mismatch:\n%s", out)
		}
	})
	t.Run("pinned minisign key", func(t *testing.T) {
		ts := serve("/repos/test/example/releases", "sfetch_test_darwin_arm64.tar.gz.minisig", pgpSig)
		defer ts.Close()
		destDir := t.TempDir()
		out, err := run(ts, "--repo", "test/example", "--tag", "v9.9.9", "--dest-dir", destDir,
			"--minisign-key", "testdata/keys/test-minisign.pub", "--binary-name", "sfetch",
			"--cache-dir", filepath.Join(t.TempDir(), "cache"))
		check(t, out, err)
		if _, statErr := os.Stat(filepath.Join(destDir, "sfetch")); statErr == nil {
			t.Fatalf("installed despite the mismatch:\n%s", out)
		}
	})

	install := func(t *testing.T, sigName string, sigBytes []byte, keyArgs ...string) {
		t.Helper()
		ts := serve("/repos/test/example/releases", sigName, sigBytes)
		defer ts.Close()
		destDir := t.TempDir()
		args := append([]string{"--repo", "test/example", "--tag", "v9.9.9", "--dest-dir", destDir,
			"--binary-name", "sfetch", "--cache-dir", filepath.Join(t.TempDir(), "cache")}, keyArgs...)
		out, err := run(ts, args...)
		check(t, out, err)
		if _, statErr := os.Stat(filepath.Join(destDir, "sfetch")); statErr == nil {
			t.Fatalf("installed despite the mismatch:\n%s", out)
		}
	}
	t.Run("pgp in .sig with ed25519 key", func(t *testing.T) {
		install(t, "sfetch_test_darwin_arm64.tar.gz.sig", pgpSig, "--key", strings.Repeat("ab", 32))
	})
	t.Run("pgp in .sig.ed25519 with ed25519 key", func(t *testing.T) {
		install(t, "sfetch_test_darwin_arm64.tar.gz.sig.ed25519", pgpSig, "--key", strings.Repeat("ab", 32))
	})
	t.Run("minisign in .asc with pinned pgp key", func(t *testing.T) {
		install(t, "sfetch_test_darwin_arm64.tar.gz.asc", minisig, "--pgp-key-file", "testdata/keys/test-pgp-pub.asc")
	})
}
