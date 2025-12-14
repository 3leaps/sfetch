package main

import (
	"archive/zip"
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
	"syscall"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestCopyFilePreservesPermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	if err := os.WriteFile(src, []byte("x"), 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o755); got != want {
		t.Fatalf("dst perms: got %o want %o", got, want)
	}
}

func TestInstallFileRawChmodOnRename(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "bin")
	dst := filepath.Join(dstDir, "tool")

	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir dstDir: %v", err)
	}
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	cls := AssetClassification{Type: AssetTypeRaw, NeedsChmod: true}
	installed, err := installFileWithRename(src, dst, cls, false, os.Rename)
	if err != nil {
		t.Fatalf("installFileWithRename: %v", err)
	}
	if installed != dst {
		t.Fatalf("installed path: got %q want %q", installed, dst)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != 0o755 {
			t.Fatalf("dst perms: got %o want %o", info.Mode().Perm(), 0o755)
		}
	}
}

func TestInstallFileRawChmodOnCopyFallback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "bin", "tool")

	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	cls := AssetClassification{Type: AssetTypeRaw, NeedsChmod: true}
	rename := func(oldPath, newPath string) error { return syscall.EXDEV }
	installed, err := installFileWithRename(src, dst, cls, false, rename)
	if err != nil {
		t.Fatalf("installFileWithRename: %v", err)
	}
	if installed != dst {
		t.Fatalf("installed path: got %q want %q", installed, dst)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != 0o755 {
			t.Fatalf("dst perms: got %o want %o", info.Mode().Perm(), 0o755)
		}
	}
}

func TestInstallFileCopyFallbackPreservesPermsWhenNoChmodNeeded(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "bin", "tool")

	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	cls := AssetClassification{Type: AssetTypeRaw, NeedsChmod: false}
	rename := func(oldPath, newPath string) error { return syscall.EXDEV }
	if _, err := installFileWithRename(src, dst, cls, false, rename); err != nil {
		t.Fatalf("installFileWithRename: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("dst perms: got %o want %o", got, want)
	}
}

func TestInstallFileArchivePreservesExecOnRename(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "tool")
	dstDir := filepath.Join(dir, "bin")
	dst := filepath.Join(dstDir, "tool")

	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir dstDir: %v", err)
	}
	if err := os.WriteFile(src, []byte("x"), 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}

	cls := AssetClassification{Type: AssetTypeArchive}
	installed, err := installFileWithRename(src, dst, cls, false, os.Rename)
	if err != nil {
		t.Fatalf("installFileWithRename: %v", err)
	}
	if installed != dst {
		t.Fatalf("installed path: got %q want %q", installed, dst)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if runtime.GOOS != "windows" {
		if got, want := info.Mode().Perm(), os.FileMode(0o755); got != want {
			t.Fatalf("dst perms: got %o want %o", got, want)
		}
	}
}

func TestInstallFileArchivePreservesExecOnCopyFallback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "tool")
	dst := filepath.Join(dir, "bin", "tool")

	if err := os.WriteFile(src, []byte("x"), 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}

	cls := AssetClassification{Type: AssetTypeArchive}
	rename := func(oldPath, newPath string) error { return syscall.EXDEV }
	installed, err := installFileWithRename(src, dst, cls, false, rename)
	if err != nil {
		t.Fatalf("installFileWithRename: %v", err)
	}
	if installed != dst {
		t.Fatalf("installed path: got %q want %q", installed, dst)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if runtime.GOOS != "windows" {
		if got, want := info.Mode().Perm(), os.FileMode(0o755); got != want {
			t.Fatalf("dst perms: got %o want %o", got, want)
		}
	}
}

func TestExtractZip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "tool.zip")
	extractDir := filepath.Join(tmp, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		t.Fatalf("mkdir extractDir: %v", err)
	}

	out, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(out)

	hdr := &zip.FileHeader{Name: "tool", Method: zip.Deflate}
	hdr.SetMode(0o755)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		_ = zw.Close()
		_ = out.Close()
		t.Fatalf("CreateHeader: %v", err)
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		_ = zw.Close()
		_ = out.Close()
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		_ = out.Close()
		t.Fatalf("close zip writer: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close zip file: %v", err)
	}

	if err := extractZip(zipPath, extractDir); err != nil {
		t.Fatalf("extractZip: %v", err)
	}

	toolPath := filepath.Join(extractDir, "tool")
	data, err := os.ReadFile(toolPath)
	if err != nil {
		t.Fatalf("read extracted tool: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("extracted content: got %q want %q", string(data), "hello")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(toolPath)
		if err != nil {
			t.Fatalf("stat extracted tool: %v", err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("expected tool to be executable, mode=%o", info.Mode().Perm())
		}
	}
}

func TestExtractZipRejectsZipSlip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "evil.zip")
	extractDir := filepath.Join(tmp, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		t.Fatalf("mkdir extractDir: %v", err)
	}

	out, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(out)

	hdr := &zip.FileHeader{Name: "../evil", Method: zip.Deflate}
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		_ = zw.Close()
		_ = out.Close()
		t.Fatalf("CreateHeader: %v", err)
	}
	if _, err := w.Write([]byte("pwnd")); err != nil {
		_ = zw.Close()
		_ = out.Close()
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		_ = out.Close()
		t.Fatalf("close zip writer: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close zip file: %v", err)
	}

	if err := extractZip(zipPath, extractDir); err == nil {
		t.Fatalf("expected zip slip rejection")
	}
	if _, err := os.Stat(filepath.Join(tmp, "evil")); err == nil {
		t.Fatalf("zip slip wrote outside extraction dir")
	}
}

func TestExtractZipRejectsAbsolutePaths(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "abs.zip")
	extractDir := filepath.Join(tmp, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		t.Fatalf("mkdir extractDir: %v", err)
	}

	out, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(out)

	hdr := &zip.FileHeader{Name: "/evil", Method: zip.Deflate}
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		_ = zw.Close()
		_ = out.Close()
		t.Fatalf("CreateHeader: %v", err)
	}
	if _, err := w.Write([]byte("pwnd")); err != nil {
		_ = zw.Close()
		_ = out.Close()
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		_ = out.Close()
		t.Fatalf("close zip writer: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close zip file: %v", err)
	}

	if err := extractZip(zipPath, extractDir); err == nil {
		t.Fatalf("expected absolute path rejection")
	}
}

func TestExtractZipRejectsSymlinks(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "symlink.zip")
	extractDir := filepath.Join(tmp, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		t.Fatalf("mkdir extractDir: %v", err)
	}

	out, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(out)

	hdr := &zip.FileHeader{Name: "link", Method: zip.Deflate}
	hdr.SetMode(os.ModeSymlink | 0o777)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		_ = zw.Close()
		_ = out.Close()
		t.Fatalf("CreateHeader: %v", err)
	}
	if _, err := w.Write([]byte("/tmp/target")); err != nil {
		_ = zw.Close()
		_ = out.Close()
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		_ = out.Close()
		t.Fatalf("close zip writer: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close zip file: %v", err)
	}

	if err := extractZip(zipPath, extractDir); err == nil {
		t.Fatalf("expected symlink rejection")
	}
}

func TestExtractZipNestedPaths(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "nested.zip")
	extractDir := filepath.Join(tmp, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		t.Fatalf("mkdir extractDir: %v", err)
	}

	out, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(out)

	if _, err := zw.Create("bin/"); err != nil {
		_ = zw.Close()
		_ = out.Close()
		t.Fatalf("create dir entry: %v", err)
	}

	hdr := &zip.FileHeader{Name: "bin/tool", Method: zip.Deflate}
	hdr.SetMode(0o755)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		_ = zw.Close()
		_ = out.Close()
		t.Fatalf("CreateHeader: %v", err)
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		_ = zw.Close()
		_ = out.Close()
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		_ = out.Close()
		t.Fatalf("close zip writer: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close zip file: %v", err)
	}

	if err := extractZip(zipPath, extractDir); err != nil {
		t.Fatalf("extractZip: %v", err)
	}

	toolPath := filepath.Join(extractDir, "bin", "tool")
	data, err := os.ReadFile(toolPath)
	if err != nil {
		t.Fatalf("read extracted tool: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("extracted content: got %q want %q", string(data), "hello")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(toolPath)
		if err != nil {
			t.Fatalf("stat extracted tool: %v", err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("expected tool to be executable, mode=%o", info.Mode().Perm())
		}
	}
}

func TestHelpExtendedAlias(t *testing.T) {
	t.Parallel()

	tests := []string{"-helpextended", "-help-extended", "--help-extended"}
	for _, arg := range tests {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr strings.Builder
			code := run([]string{arg}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit code: got %d, stderr=%q", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "sfetch quickstart") {
				t.Fatalf("stdout missing quickstart header, got: %q", stdout.String())
			}
		})
	}
}

func TestInstallFlagMutualExclusion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		args []string
		want string
	}{
		{args: []string{"--install", "--dest-dir", "/tmp", "--skip-tools-check"}, want: "mutually exclusive"},
		{args: []string{"--install", "--output", "/tmp/tool", "--skip-tools-check"}, want: "mutually exclusive"},
		{args: []string{"--install", "--self-update", "--skip-tools-check"}, want: "cannot be used with --self-update"},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var stdout, stderr strings.Builder
			code := run(tc.args, &stdout, &stderr)
			if code == 0 {
				t.Fatalf("expected non-zero exit code; stdout=%q", stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr mismatch: got %q want substring %q", stderr.String(), tc.want)
			}
		})
	}
}

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

	t.Run("strips .sig extension", func(t *testing.T) {
		cfg := defaults
		assets := []Asset{
			{Name: "SHA2-256SUMS"},
			{Name: "SHA2-256SUMS.sig"},
		}
		sigAsset, checksumName := findChecksumSignature(assets, &cfg)
		if sigAsset == nil {
			t.Fatal("expected to find checksum signature")
		}
		if checksumName != "SHA2-256SUMS" {
			t.Errorf("expected checksum name SHA2-256SUMS, got %s", checksumName)
		}
	})
}

func TestMergeConfigPreferChecksumSig(t *testing.T) {
	t.Run("default is true", func(t *testing.T) {
		cfg := defaults
		if !preferChecksumSig(&cfg) {
			t.Error("expected default preferChecksumSig to be true")
		}
	})

	t.Run("override to false", func(t *testing.T) {
		override := RepoConfig{
			BinaryName:        "test",
			PreferChecksumSig: boolPtr(false),
		}
		cfg := mergeConfig(defaults, override)
		if preferChecksumSig(&cfg) {
			t.Error("expected preferChecksumSig to be false after override")
		}
	})

	t.Run("no override keeps default", func(t *testing.T) {
		override := RepoConfig{
			BinaryName: "test",
			// PreferChecksumSig not set (nil)
		}
		cfg := mergeConfig(defaults, override)
		if !preferChecksumSig(&cfg) {
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
		{"SHA2-256SUMS.sig", sigFormatPGP},
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

func TestApplyInferenceRulesPlatformExclusion(t *testing.T) {
	rules := mustLoadInferenceRules(t)
	assets := []Asset{{Name: "tool"}, {Name: "tool.exe"}}
	out := applyInferenceRules(assets, rules, "darwin", "amd64", defaults.ArchiveExtensions)
	if len(out) != 1 || out[0].Name != "tool" {
		t.Fatalf("expected only tool after darwin exclusions, got %v", out)
	}
}

func TestApplyInferenceRulesPreferRawOverArchive(t *testing.T) {
	rules := mustLoadInferenceRules(t)
	assets := []Asset{{Name: "yt-dlp_macos"}, {Name: "yt-dlp_macos.zip"}}
	out := applyInferenceRules(assets, rules, "darwin", "arm64", defaults.ArchiveExtensions)
	if len(out) != 1 || out[0].Name != "yt-dlp_macos" {
		t.Fatalf("expected raw binary preferred, got %v", out)
	}
}

func TestApplyInferenceRulesPlatformTokensCaseInsensitive(t *testing.T) {
	rules := mustLoadInferenceRules(t)
	assets := []Asset{
		{Name: "gh_2.0.0_macOS_arm64.zip"},
		{Name: "gh_2.0.0_linux_amd64.tar.gz"},
	}
	out := applyInferenceRules(assets, rules, "darwin", "arm64", defaults.ArchiveExtensions)
	if len(out) != 1 || out[0].Name != "gh_2.0.0_macOS_arm64.zip" {
		t.Fatalf("expected macOS asset selected, got %v", out)
	}
}

func TestInferAssetClassification(t *testing.T) {
	tests := []struct {
		name           string
		wantType       AssetType
		wantFmt        ArchiveFormat
		wantNeedsChmod bool
	}{
		{"sfetch_darwin_arm64.tar.gz", AssetTypeArchive, ArchiveFormatTarGz, false},
		{"tool.tgz", AssetTypeArchive, ArchiveFormatTarGz, false},
		{"tool.tar.xz", AssetTypeArchive, ArchiveFormatTarXz, false},
		{"tool.tar.bz2", AssetTypeArchive, ArchiveFormatTarBz2, false},
		{"tool.tar", AssetTypeArchive, ArchiveFormatTar, false},
		{"tool.zip", AssetTypeArchive, ArchiveFormatZip, false},
		{"install.sh", AssetTypeRaw, "", true},
		{"bootstrap.py", AssetTypeRaw, "", true},
		{"kubectl", AssetTypeRaw, "", true},
		{"terraform.exe", AssetTypeRaw, "", false},
		{"package.deb", AssetTypePackage, "", false},
		{"package.rpm", AssetTypePackage, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cls := inferAssetClassification(tt.name)
			if cls.Type != tt.wantType {
				t.Fatalf("Type = %s, want %s", cls.Type, tt.wantType)
			}
			if cls.ArchiveFormat != tt.wantFmt {
				t.Fatalf("ArchiveFormat = %s, want %s", cls.ArchiveFormat, tt.wantFmt)
			}
			if cls.NeedsChmod != tt.wantNeedsChmod {
				t.Fatalf("NeedsChmod = %v, want %v", cls.NeedsChmod, tt.wantNeedsChmod)
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

func mustLoadInferenceRules(t *testing.T) *InferenceRules {
	t.Helper()
	rules, err := loadInferenceRules()
	if err != nil {
		t.Fatalf("loadInferenceRules: %v", err)
	}
	if rules == nil {
		t.Fatalf("inference rules not loaded")
	}
	return rules
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

func TestInferenceRulesSchemaValidity(t *testing.T) {
	c := jsonschema.NewCompiler()
	if _, err := c.Compile("schemas/inference-rules.schema.json"); err != nil {
		t.Fatalf("inference rules schema is not valid JSON Schema 2020-12: %v", err)
	}
}

func TestInferenceRulesDocumentValidates(t *testing.T) {
	c := jsonschema.NewCompiler()
	schema, err := c.Compile("schemas/inference-rules.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	var doc interface{}
	if err := json.Unmarshal(defaultInferenceRulesJSON, &doc); err != nil {
		t.Fatalf("unmarshal inference-rules.json: %v", err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("embedded inference-rules.json does not validate: %v", err)
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

func TestUpdateTargetSchemaValidity(t *testing.T) {
	c := jsonschema.NewCompiler()
	repoSchemaBytes, err := os.ReadFile("schemas/repo-config.schema.json")
	if err != nil {
		t.Fatalf("read schemas/repo-config.schema.json: %v", err)
	}
	var repoSchemaDoc any
	if err := json.Unmarshal(repoSchemaBytes, &repoSchemaDoc); err != nil {
		t.Fatalf("unmarshal schemas/repo-config.schema.json: %v", err)
	}
	if err := c.AddResource("https://github.com/3leaps/sfetch/schemas/repo-config.schema.json", repoSchemaDoc); err != nil {
		t.Fatalf("add repo-config schema resource: %v", err)
	}
	if _, err := c.Compile("schemas/update-target.schema.json"); err != nil {
		t.Fatalf("update-target schema is not valid JSON Schema 2020-12: %v", err)
	}
}

func TestUpdateTargetConfigValidates(t *testing.T) {
	c := jsonschema.NewCompiler()
	repoSchemaBytes, err := os.ReadFile("schemas/repo-config.schema.json")
	if err != nil {
		t.Fatalf("read schemas/repo-config.schema.json: %v", err)
	}
	var repoSchemaDoc any
	if err := json.Unmarshal(repoSchemaBytes, &repoSchemaDoc); err != nil {
		t.Fatalf("unmarshal schemas/repo-config.schema.json: %v", err)
	}
	if err := c.AddResource("https://github.com/3leaps/sfetch/schemas/repo-config.schema.json", repoSchemaDoc); err != nil {
		t.Fatalf("add repo-config schema resource: %v", err)
	}
	schema, err := c.Compile("schemas/update-target.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	raw, err := os.ReadFile("configs/update/sfetch.json")
	if err != nil {
		t.Fatalf("read configs/update/sfetch.json: %v", err)
	}
	var doc interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal configs/update/sfetch.json: %v", err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("configs/update/sfetch.json does not validate: %v", err)
	}
}

func TestEmbeddedUpdateTargetConfigValidates(t *testing.T) {
	c := jsonschema.NewCompiler()
	repoSchemaBytes, err := os.ReadFile("schemas/repo-config.schema.json")
	if err != nil {
		t.Fatalf("read schemas/repo-config.schema.json: %v", err)
	}
	var repoSchemaDoc any
	if err := json.Unmarshal(repoSchemaBytes, &repoSchemaDoc); err != nil {
		t.Fatalf("unmarshal schemas/repo-config.schema.json: %v", err)
	}
	if err := c.AddResource("https://github.com/3leaps/sfetch/schemas/repo-config.schema.json", repoSchemaDoc); err != nil {
		t.Fatalf("add repo-config schema resource: %v", err)
	}
	schema, err := c.Compile("schemas/update-target.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	if len(embeddedUpdateTargetJSON) == 0 {
		t.Fatal("embeddedUpdateTargetJSON is empty")
	}
	var doc interface{}
	if err := json.Unmarshal(embeddedUpdateTargetJSON, &doc); err != nil {
		t.Fatalf("unmarshal embedded update config: %v", err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("embedded update config does not validate: %v", err)
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

// TestEmbeddedTrustAnchors validates the embedded trust anchor constants.
func TestEmbeddedTrustAnchors(t *testing.T) {
	t.Run("minisign pubkey has correct format", func(t *testing.T) {
		// Minisign public keys start with "RW" and are 56 chars
		if !strings.HasPrefix(EmbeddedMinisignPubkey, "RW") {
			t.Errorf("EmbeddedMinisignPubkey should start with 'RW', got %q", EmbeddedMinisignPubkey[:2])
		}
		if len(EmbeddedMinisignPubkey) != 56 {
			t.Errorf("EmbeddedMinisignPubkey should be 56 chars, got %d", len(EmbeddedMinisignPubkey))
		}
	})

	t.Run("key ID is set", func(t *testing.T) {
		if EmbeddedMinisignKeyID == "" {
			t.Error("EmbeddedMinisignKeyID should not be empty")
		}
	})

	t.Run("matches install script", func(t *testing.T) {
		// Read install script and check key matches
		installScript, err := os.ReadFile("scripts/install-sfetch.sh")
		if err != nil {
			t.Fatalf("read install script: %v", err)
		}
		if !strings.Contains(string(installScript), EmbeddedMinisignPubkey) {
			t.Error("EmbeddedMinisignPubkey does not match key in scripts/install-sfetch.sh")
		}
	})
}

func TestEmbeddedUpdateTargetConfigMatchesFile(t *testing.T) {
	fileBytes, err := os.ReadFile("configs/update/sfetch.json")
	if err != nil {
		t.Fatalf("read configs/update/sfetch.json: %v", err)
	}

	var a any
	if err := json.Unmarshal(fileBytes, &a); err != nil {
		t.Fatalf("unmarshal configs/update/sfetch.json: %v", err)
	}
	var b any
	if err := json.Unmarshal(embeddedUpdateTargetJSON, &b); err != nil {
		t.Fatalf("unmarshal embedded update config: %v", err)
	}

	aj, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal file JSON: %v", err)
	}
	bj, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal embedded JSON: %v", err)
	}
	if string(aj) != string(bj) {
		t.Fatal("embedded update config does not match configs/update/sfetch.json")
	}
}

// TestSelfVerifyAssetName validates asset name generation for different platforms.
func TestSelfVerifyAssetName(t *testing.T) {
	name := selfVerifyAssetName()

	// Should contain platform info
	if !strings.Contains(name, runtime.GOOS) {
		t.Errorf("asset name should contain GOOS %q, got %q", runtime.GOOS, name)
	}
	if !strings.Contains(name, runtime.GOARCH) {
		t.Errorf("asset name should contain GOARCH %q, got %q", runtime.GOARCH, name)
	}

	// Should have correct extension based on OS
	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(name, ".zip") {
			t.Errorf("Windows asset should end with .zip, got %q", name)
		}
	} else {
		if !strings.HasSuffix(name, ".tar.gz") {
			t.Errorf("non-Windows asset should end with .tar.gz, got %q", name)
		}
	}
}

// TestChecksumCommand validates platform-specific checksum command output.
func TestChecksumCommand(t *testing.T) {
	cmd := checksumCommand()

	if runtime.GOOS == "darwin" {
		if cmd != "shasum -a 256" {
			t.Errorf("macOS should use 'shasum -a 256', got %q", cmd)
		}
	} else {
		if cmd != "sha256sum" {
			t.Errorf("non-macOS should use 'sha256sum', got %q", cmd)
		}
	}
}

// TestFetchExpectedHash tests the SHA256SUMS parsing logic.
func TestFetchExpectedHash(t *testing.T) {
	t.Run("dev build returns error", func(t *testing.T) {
		_, err := fetchExpectedHash("dev", "sfetch_darwin_arm64.tar.gz")
		if err == nil {
			t.Error("expected error for dev build")
		}
		if !strings.Contains(err.Error(), "dev build") {
			t.Errorf("error should mention dev build, got: %v", err)
		}
	})
}

// TestFetchExpectedHashParsing tests SHA256SUMS parsing with a mock server.
func TestFetchExpectedHashParsing(t *testing.T) {
	// Note: fetchExpectedHash uses a hardcoded GitHub URL, so we can't directly
	// inject a mock server. Instead, we test the parsing logic via extractChecksum
	// which is the same code path. This test documents the expected behavior.

	t.Run("parses standard format", func(t *testing.T) {
		content := `b66cd9d99e70edec01980fe8f8587ce426f556f8bcb102f4a94c3d72b7690d0b  sfetch_darwin_arm64.tar.gz
abc123def456789012345678901234567890123456789012345678901234  sfetch_linux_amd64.tar.gz
def456789012345678901234567890123456789012345678901234567890  sfetch_windows_amd64.zip`

		hash, err := extractChecksum([]byte(content), "sha256", "sfetch_darwin_arm64.tar.gz")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash != "b66cd9d99e70edec01980fe8f8587ce426f556f8bcb102f4a94c3d72b7690d0b" {
			t.Errorf("wrong hash: got %q", hash)
		}
	})

	t.Run("handles missing asset", func(t *testing.T) {
		content := `abc123def456789012345678901234567890123456789012345678901234  other_file.tar.gz`
		_, err := extractChecksum([]byte(content), "sha256", "sfetch_darwin_arm64.tar.gz")
		if err == nil {
			t.Error("expected error for missing asset")
		}
	})

	t.Run("ignores comments", func(t *testing.T) {
		content := `# Generated by sfetch release process
# Date: 2025-12-10
b66cd9d99e70edec01980fe8f8587ce426f556f8bcb102f4a94c3d72b7690d0b  sfetch_darwin_arm64.tar.gz`

		hash, err := extractChecksum([]byte(content), "sha256", "sfetch_darwin_arm64.tar.gz")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash != "b66cd9d99e70edec01980fe8f8587ce426f556f8bcb102f4a94c3d72b7690d0b" {
			t.Errorf("wrong hash: got %q", hash)
		}
	})
}

// TestExtractChecksumForSelfVerify tests the checksum extraction used in self-verify.
// This uses the existing extractChecksum function which fetchExpectedHash relies on.
func TestExtractChecksumForSelfVerify(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		assetName string
		want      string
		wantErr   bool
	}{
		{
			name: "standard SHA256SUMS format",
			content: `b66cd9d99e70edec01980fe8f8587ce426f556f8bcb102f4a94c3d72b7690d0b  sfetch_darwin_arm64.tar.gz
abc123def456789012345678901234567890123456789012345678901234  sfetch_linux_amd64.tar.gz`,
			assetName: "sfetch_darwin_arm64.tar.gz",
			want:      "b66cd9d99e70edec01980fe8f8587ce426f556f8bcb102f4a94c3d72b7690d0b",
			wantErr:   false,
		},
		{
			name:      "single space separator",
			content:   "b66cd9d99e70edec01980fe8f8587ce426f556f8bcb102f4a94c3d72b7690d0b sfetch_darwin_arm64.tar.gz",
			assetName: "sfetch_darwin_arm64.tar.gz",
			want:      "b66cd9d99e70edec01980fe8f8587ce426f556f8bcb102f4a94c3d72b7690d0b",
			wantErr:   false,
		},
		{
			name:      "asset not found",
			content:   "abc123def456789012345678901234567890123456789012345678901234  other_file.tar.gz",
			assetName: "sfetch_darwin_arm64.tar.gz",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "empty file",
			content:   "",
			assetName: "sfetch_darwin_arm64.tar.gz",
			want:      "",
			wantErr:   true,
		},
		{
			name: "with comments",
			content: `# SHA256 checksums
b66cd9d99e70edec01980fe8f8587ce426f556f8bcb102f4a94c3d72b7690d0b  sfetch_darwin_arm64.tar.gz`,
			assetName: "sfetch_darwin_arm64.tar.gz",
			want:      "b66cd9d99e70edec01980fe8f8587ce426f556f8bcb102f4a94c3d72b7690d0b",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractChecksum([]byte(tt.content), "sha256", tt.assetName)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Errorf("got %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestExtractChecksumSHA512(t *testing.T) {
	t.Parallel()

	digest := strings.Repeat("a", 128)
	content := digest + "  sfetch_darwin_arm64.tar.gz\n"
	got, err := extractChecksum([]byte(content), "sha512", "sfetch_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatalf("extractChecksum sha512: %v", err)
	}
	if got != digest {
		t.Fatalf("got %q, want %q", got, digest)
	}
}

func TestDetectChecksumAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		filename    string
		defaultAlgo string
		want        string
	}{
		{"sha256sums", "SHA256SUMS", "sha256", "sha256"},
		{"sha2-256sums", "SHA2-256SUMS", "sha512", "sha256"},
		{"sha512sums", "SHA512SUMS", "sha256", "sha512"},
		{"sha2-512sums", "SHA2-512SUMS", "sha256", "sha512"},
		{"per-asset sha256", "thing.tar.gz.sha256", "sha512", "sha256"},
		{"per-asset sha512", "thing.tar.gz.sha512.txt", "sha256", "sha512"},
		{"unknown falls back", "CHECKSUMS.txt", "sha256", "sha256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectChecksumAlgorithm(tt.filename, tt.defaultAlgo)
			if got != tt.want {
				t.Fatalf("detectChecksumAlgorithm(%q, %q) = %q, want %q", tt.filename, tt.defaultAlgo, got, tt.want)
			}
		})
	}
}

func TestAssessReleasePrefersSHA512ManifestSetsAlgo(t *testing.T) {
	t.Parallel()

	cfg := defaults
	cfg.HashAlgo = "sha256"
	cfg.PreferChecksumSig = boolPtr(true)

	rel := &Release{
		TagName: "v0.2.4",
		Assets: []Asset{
			{Name: "sfetch_darwin_arm64.tar.gz"},
			{Name: "SHA2-512SUMS"},
			{Name: "SHA2-512SUMS.minisig"},
			{Name: "SHA256SUMS"},
			{Name: "SHA256SUMS.minisig"},
		},
	}

	selected := &rel.Assets[0]
	flags := assessmentFlags{}

	assessment := assessRelease(rel, &cfg, selected, flags)
	if assessment.Workflow != workflowA {
		t.Fatalf("workflow = %q, want %q", assessment.Workflow, workflowA)
	}
	if assessment.ChecksumFile != "SHA2-512SUMS" {
		t.Fatalf("checksum file = %q, want %q", assessment.ChecksumFile, "SHA2-512SUMS")
	}
	if assessment.ChecksumAlgorithm != "sha512" {
		t.Fatalf("checksum algorithm = %q, want %q", assessment.ChecksumAlgorithm, "sha512")
	}
}

// TestSelfVerifyOutputJSON validates JSON output structure.
func TestSelfVerifyOutputJSON(t *testing.T) {
	// Test that the JSON struct marshals correctly
	output := SelfVerifyOutput{
		Version:     "0.2.1",
		Platform:    "darwin/arm64",
		BuildTime:   "2025-12-10T16:00:00Z",
		GitCommit:   "abc123",
		IsDev:       false,
		Asset:       "sfetch_darwin_arm64.tar.gz",
		ExpectedSHA: "b66cd9d99e70edec01980fe8f8587ce426f556f8bcb102f4a94c3d72b7690d0b",
		URLs: &SelfVerifyURLs{
			SHA256SUMS:        "https://github.com/3leaps/sfetch/releases/download/v0.2.1/SHA256SUMS",
			SHA256SUMSMinisig: "https://github.com/3leaps/sfetch/releases/download/v0.2.1/SHA256SUMS.minisig",
			SHA256SUMSAsc:     "https://github.com/3leaps/sfetch/releases/download/v0.2.1/SHA256SUMS.asc",
		},
		TrustAnchor: &TrustAnchorInfo{
			MinisignPubkey: EmbeddedMinisignPubkey,
			KeyID:          EmbeddedMinisignKeyID,
		},
		Commands: &VerifyCommands{
			Checksum: "shasum -a 256 $(which sfetch)",
			Minisign: "minisign -Vm /tmp/SHA256SUMS -P " + EmbeddedMinisignPubkey,
		},
		Warning: "A compromised binary could lie. Run verification commands yourself.",
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Verify it can be unmarshalled back
	var parsed SelfVerifyOutput
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Check key fields
	if parsed.Version != "0.2.1" {
		t.Errorf("version mismatch: got %q", parsed.Version)
	}
	if parsed.TrustAnchor.MinisignPubkey != EmbeddedMinisignPubkey {
		t.Errorf("pubkey mismatch")
	}
	if parsed.IsDev {
		t.Error("isDev should be false")
	}
	if parsed.Warning == "" {
		t.Error("warning should be present")
	}
}

// TestSelfVerifyDevBuild validates dev build output structure.
func TestSelfVerifyDevBuild(t *testing.T) {
	output := SelfVerifyOutput{
		Version:   "dev",
		Platform:  "darwin/arm64",
		BuildTime: "unknown",
		GitCommit: "unknown",
		IsDev:     true,
		TrustAnchor: &TrustAnchorInfo{
			MinisignPubkey: EmbeddedMinisignPubkey,
			KeyID:          EmbeddedMinisignKeyID,
		},
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Dev builds should not have URLs, Asset, ExpectedSHA, or Commands
	jsonStr := string(data)
	if strings.Contains(jsonStr, "sha256sums") {
		t.Error("dev build JSON should not contain URLs")
	}
	if strings.Contains(jsonStr, "expectedSHA256") {
		t.Error("dev build JSON should not contain expectedSHA256")
	}

	// But should have trustAnchor
	if !strings.Contains(jsonStr, "trustAnchor") {
		t.Error("dev build JSON should contain trustAnchor")
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
