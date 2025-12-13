package selfupdate

import (
	"fmt"
	"os"
	"path/filepath"
)

func ComputeTargetPath(dir string) (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("determine current executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}
	targetDir := filepath.Dir(exePath)
	if dir != "" {
		targetDir = dir
	}
	base := filepath.Base(exePath)
	return filepath.Join(targetDir, base), nil
}
