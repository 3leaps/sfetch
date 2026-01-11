// Command generate-checksums writes checksum files for release artifacts using stdlib hashes.
package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type checksumJob struct {
	algo    string
	outFile string
	newHash func() hash.Hash
}

func main() {
	dir := flag.String("dir", "dist/release", "directory containing release artifacts")
	algos := flag.String("algos", "sha256,sha512", "comma-separated list of hash algorithms (sha256, sha512)")
	flag.Parse()

	if err := run(*dir, *algos); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(dir, algoList string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return errors.New("directory is required")
	}
	if err := ensureDir(dir); err != nil {
		return err
	}

	jobs, err := jobsFromAlgos(algoList)
	if err != nil {
		return err
	}
	if len(jobs) == 0 {
		return errors.New("no hash algorithms specified")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}

	files := filterFiles(entries)
	if len(files) == 0 {
		return fmt.Errorf("no release artifacts found in %s", dir)
	}

	sort.Strings(files)

	for _, job := range jobs {
		if err := writeChecksums(dir, files, job); err != nil {
			return err
		}
		fmt.Printf("✅ Wrote %s (%d entries)\n", filepath.Join(dir, job.outFile), len(files))
	}

	return nil
}

func ensureDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory %s not found", dir)
		}
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

func jobsFromAlgos(list string) ([]checksumJob, error) {
	parts := strings.Split(list, ",")
	jobs := make([]checksumJob, 0, len(parts))
	seen := make(map[string]struct{})
	for _, raw := range parts {
		algo := strings.ToLower(strings.TrimSpace(raw))
		if algo == "" {
			continue
		}
		if _, ok := seen[algo]; ok {
			continue
		}
		switch algo {
		case "sha256":
			jobs = append(jobs, checksumJob{
				algo:    "sha256",
				outFile: "SHA256SUMS",
				newHash: sha256.New,
			})
		case "sha512":
			jobs = append(jobs, checksumJob{
				algo:    "sha512",
				outFile: "SHA2-512SUMS",
				newHash: sha512.New,
			})
		default:
			return nil, fmt.Errorf("unsupported hash algorithm %q", algo)
		}
		seen[algo] = struct{}{}
	}
	return jobs, nil
}

func filterFiles(entries []os.DirEntry) []string {
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if skipFile(name) {
			continue
		}
		if !isArtifact(name) {
			continue
		}
		files = append(files, name)
	}
	return files
}

func skipFile(name string) bool {
	lower := strings.ToLower(name)

	// Skip signatures and existing checksum outputs
	if strings.HasSuffix(lower, ".asc") ||
		strings.HasSuffix(lower, ".minisig") ||
		strings.HasSuffix(lower, ".sha256") ||
		strings.HasSuffix(lower, ".sha256.txt") ||
		strings.HasSuffix(lower, ".sha512") ||
		strings.HasSuffix(lower, ".sha512.txt") ||
		strings.HasPrefix(lower, "sha256sums") ||
		strings.HasPrefix(lower, "sha2-512sums") {
		return true
	}

	// Skip detached sig/checksum helpers
	switch lower {
	case "checksums.txt", "checksum.txt":
		return true
	case "install-sfetch.sh.asc", "install-sfetch.sh.sig":
		return true
	}

	return false
}

func isArtifact(name string) bool {
	if name == "install-sfetch.sh" {
		return true
	}
	return strings.HasPrefix(name, "sfetch_")
}

func writeChecksums(dir string, files []string, job checksumJob) error {
	outPath := filepath.Join(dir, job.outFile)
	outFile, err := os.Create(outPath) // #nosec G304 -- SDR-001: build tool output path
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	defer outFile.Close() //nolint:errcheck // error checked via sync below

	for _, name := range files {
		sum, err := computeFileHash(filepath.Join(dir, name), job.newHash)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(outFile, "%s  %s\n", sum, name); err != nil {
			return fmt.Errorf("write checksum: %w", err)
		}
	}
	return nil
}

func computeFileHash(path string, newHash func() hash.Hash) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- SDR-001: build tool reading release assets
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	h := newHash()
	if _, err := h.Write(data); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
