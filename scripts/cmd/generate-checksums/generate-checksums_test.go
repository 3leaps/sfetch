package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGeneratesChecksumsAndSkipsNonArtifacts(t *testing.T) {
	dir := t.TempDir()

	writeFile := func(name, contents string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	writeFile("sfetch_one", "one")
	writeFile("sfetch_one.asc", "sig")          // skipped
	writeFile("install-sfetch.sh", "installer") // included
	writeFile("release-notes-v0.0.1.md", "notes")
	writeFile("SHA256SUMS", "old") // skipped/overwritten

	if err := run(dir, "sha256"); err != nil {
		t.Fatalf("run: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatalf("read SHA256SUMS: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(lines), lines)
	}

	expect := map[string]string{
		"sfetch_one":        hashHex("one"),
		"install-sfetch.sh": hashHex("installer"),
	}

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("unexpected line format: %q", line)
		}
		hash := fields[0]
		name := fields[1]
		if exp, ok := expect[name]; !ok {
			t.Fatalf("unexpected file hashed: %s", name)
		} else if hash != exp {
			t.Fatalf("hash mismatch for %s: expected %s, got %s", name, exp, hash)
		}
		delete(expect, name)
	}

	if len(expect) != 0 {
		t.Fatalf("missing expected entries: %v", expect)
	}
}

func hashHex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return strings.ToLower(hex.EncodeToString(sum[:]))
}
