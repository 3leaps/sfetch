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
	defer os.RemoveAll(home)

	importArgs := []string{"--batch", "--no-tty", "--homedir", home, "--import", pubKeyPath}
	if err := runCommand(gpgBin, importArgs...); err != nil {
		return fmt.Errorf("import pgp key: %w", err)
	}

	verifyArgs := []string{"--batch", "--no-tty", "--homedir", home, "--trust-model", "always", "--verify", sigPath, assetPath}
	if err := runCommand(gpgBin, verifyArgs...); err != nil {
		return fmt.Errorf("verify pgp signature: %w", err)
	}

	return nil
}

func runCommand(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
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
