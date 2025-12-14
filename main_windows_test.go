//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallFileWithRenameWindowsSelfUpdateWritesNewFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "sfetch.exe")
	dst := filepath.Join(dir, "bin", "sfetch.exe")

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	var calls []string
	rename := func(oldPath, newPath string) error {
		calls = append(calls, newPath)
		if len(calls) == 1 {
			return os.ErrPermission
		}
		return nil
	}

	cls := AssetClassification{Type: AssetTypeRaw, NeedsChmod: true}
	installed, err := installFileWithRename(src, dst, cls, true, rename)
	if err != nil {
		t.Fatalf("installFileWithRename: %v", err)
	}

	want := dst + ".new"
	if installed != want {
		t.Fatalf("installed path: got %q want %q", installed, want)
	}

	if len(calls) != 2 {
		t.Fatalf("expected 2 rename attempts, got %d", len(calls))
	}
	if calls[0] != dst {
		t.Fatalf("first rename target: got %q want %q", calls[0], dst)
	}
	if calls[1] != want {
		t.Fatalf("second rename target: got %q want %q", calls[1], want)
	}
}
