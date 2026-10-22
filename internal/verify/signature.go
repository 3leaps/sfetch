package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jedisct1/go-minisign"
)

const (
	FormatBinary   = "binary"
	FormatPGP      = "pgp"
	FormatMinisign = "minisign"

	maxCommandError = 512
)

type SignatureData struct {
	Format string
	Bytes  []byte
}

func LoadSignature(path string) (SignatureData, error) {
	// #nosec G304 -- path sig tmp controlled
	data, err := os.ReadFile(path)
	if err != nil {
		return SignatureData{}, fmt.Errorf("read sig: %w", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "-----BEGIN PGP SIGNATURE-----") {
		return SignatureData{Format: FormatPGP}, nil
	}
	if strings.HasPrefix(trimmed, "untrusted comment:") {
		return SignatureData{Format: FormatMinisign}, nil
	}
	if len(data) == ed25519.SignatureSize {
		return SignatureData{Format: FormatBinary, Bytes: data}, nil
	}
	decoded, err := hex.DecodeString(trimmed)
	if err == nil && len(decoded) == ed25519.SignatureSize {
		return SignatureData{Format: FormatBinary, Bytes: decoded}, nil
	}
	return SignatureData{}, fmt.Errorf("unsupported signature format in %s", path)
}

func VerifyMinisignSignature(contentToVerify []byte, sigPath, pubKeyPath string) error {
	pubKey, err := minisign.NewPublicKeyFromFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("read minisign pubkey: %w", err)
	}

	sig, err := minisign.NewSignatureFromFile(sigPath)
	if err != nil {
		return fmt.Errorf("read minisign signature: %w", err)
	}

	valid, err := pubKey.Verify(contentToVerify, sig)
	if err != nil {
		return fmt.Errorf("minisign: verification error: %w", err)
	}
	if !valid {
		return fmt.Errorf("minisign: signature verification failed")
	}

	return nil
}

func VerifyPGPSignature(assetPath, sigPath, pubKeyPath, gpgBin string) error {
	home, err := os.MkdirTemp("", "sfetch-gpg-")
	if err != nil {
		return fmt.Errorf("create gpg home: %w", err)
	}
	defer os.RemoveAll(home) //nolint:errcheck // best-effort cleanup of temp dir

	homeArg := gpgPathArg(gpgBin, home)
	importArgs := []string{"--batch", "--no-tty", "--homedir", homeArg, "--import", gpgPathArg(gpgBin, pubKeyPath)}
	if err := runCommand(gpgBin, importArgs...); err != nil {
		return fmt.Errorf("import pgp key: %w", err)
	}

	verifyArgs := []string{"--batch", "--no-tty", "--homedir", homeArg, "--trust-model", "always", "--verify", gpgPathArg(gpgBin, sigPath), gpgPathArg(gpgBin, assetPath)}
	if err := runCommand(gpgBin, verifyArgs...); err != nil {
		return fmt.Errorf("verify pgp signature: %w", err)
	}

	return nil
}

// gpgPathArg converts a filesystem path for the given gpg binary. Git for
// Windows / MSYS gpg concatenates cwd onto a Windows --homedir (producing
// "/d/a/sfetch/sfetch/C:\\Users\\..."), so those binaries get POSIX paths.
func gpgPathArg(gpgBin, path string) string {
	if needsMSYSPathConversion(gpgBin) {
		return toMSYSPath(path)
	}
	return path
}

func needsMSYSPathConversion(gpgBin string) bool {
	if gpgBin == "" {
		return false
	}
	norm := strings.ToLower(strings.ReplaceAll(gpgBin, `\`, "/"))
	if strings.Contains(norm, "/git/usr/bin/") {
		return true
	}
	if strings.Contains(norm, "/mingw64/bin/") || strings.Contains(norm, "/mingw32/bin/") {
		return true
	}
	// MSYS2 usr/bin (C:\msys64\usr\bin\gpg.exe). A bare Linux /usr/bin/gpg
	// has no drive letter, so it stays on native paths.
	if strings.Contains(norm, "/usr/bin/") && strings.Contains(norm, ":") {
		return true
	}
	return false
}

func toMSYSPath(p string) string {
	if p == "" {
		return p
	}
	if p[0] == '/' {
		return p
	}
	// Drive-letter paths must be recognized on every GOOS: tests run on Unix,
	// and filepath.VolumeName ignores Windows volumes there.
	if len(p) >= 2 && p[1] == ':' && isDriveLetter(p[0]) {
		rest := strings.ReplaceAll(p[2:], `\`, "/")
		if rest == "" {
			rest = "/"
		} else if rest[0] != '/' {
			rest = "/" + rest
		}
		return "/" + strings.ToLower(string(p[0])) + rest
	}
	return strings.ReplaceAll(p, `\`, "/")
}

func isDriveLetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func runCommand(bin string, args ...string) error {
	cmd := exec.Command(bin, args...) // #nosec G204 -- verifier binary is user-configured; args are fixed by verification flow
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %s", bin, strings.Join(args, " "), trimCommandOutput(combined.String()))
	}
	return nil
}

func trimCommandOutput(out string) string {
	clean := strings.TrimSpace(out)
	if clean == "" {
		return "command failed"
	}
	if len(clean) > maxCommandError {
		return clean[:maxCommandError] + "..."
	}
	return clean
}
