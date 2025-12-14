package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeTargetPathRespectsDirOverride(t *testing.T) {
	t.Parallel()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	base := filepath.Base(exe)

	dir := t.TempDir()
	got, err := ComputeTargetPath(dir)
	if err != nil {
		t.Fatalf("ComputeTargetPath: %v", err)
	}
	want := filepath.Join(dir, base)
	if got != want {
		t.Fatalf("target: got %q want %q", got, want)
	}
}

func TestComputeTargetPathKeepsExecutableBasename(t *testing.T) {
	t.Parallel()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	got, err := ComputeTargetPath("")
	if err != nil {
		t.Fatalf("ComputeTargetPath: %v", err)
	}
	if filepath.Base(got) != filepath.Base(exe) {
		t.Fatalf("basename: got %q want %q", filepath.Base(got), filepath.Base(exe))
	}
}
