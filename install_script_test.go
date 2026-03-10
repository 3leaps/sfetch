package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScriptDetectPlatform(t *testing.T) {
	scriptBytes, err := os.ReadFile("scripts/install-sfetch.sh")
	if err != nil {
		t.Fatalf("read install script: %v", err)
	}

	script := strings.TrimSuffix(string(scriptBytes), "main \"$@\"\n")
	if script == string(scriptBytes) {
		t.Fatal("install script missing main invocation suffix")
	}

	scriptPath := filepath.Join(t.TempDir(), "install-sfetch-lib.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write temp script: %v", err)
	}

	tests := []struct {
		name   string
		unameS string
		unameM string
		env    map[string]string
		want   string
	}{
		{
			name:   "windows arm64 uses processor architecture over uname",
			unameS: "MINGW64_NT-10.0",
			unameM: "x86_64",
			env: map[string]string{
				"PROCESSOR_ARCHITECTURE": "ARM64",
			},
			want: "windows_arm64",
		},
		{
			name:   "windows arm64 uses wow64 architecture hint",
			unameS: "MSYS_NT-10.0",
			unameM: "x86_64",
			env: map[string]string{
				"PROCESSOR_ARCHITECTURE": "x86",
				"PROCESSOR_ARCHITEW6432": "ARM64",
			},
			want: "windows_arm64",
		},
		{
			name:   "non windows still uses uname",
			unameS: "Linux",
			unameM: "aarch64",
			want:   "linux_arm64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdText := `
uname() {
	case "$1" in
		-s) printf '%s\n' "$MOCK_UNAME_S" ;;
		-m) printf '%s\n' "$MOCK_UNAME_M" ;;
		*) command uname "$@" ;;
	esac
}
source "$1"
detect_platform
`
			cmd := exec.Command("bash", "-c", cmdText, "bash", scriptPath)
			cmd.Env = append(os.Environ(),
				"MOCK_UNAME_S="+tt.unameS,
				"MOCK_UNAME_M="+tt.unameM,
			)
			for k, v := range tt.env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}

			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("detect_platform failed: %v\noutput:\n%s", err, out)
			}

			got := strings.TrimSpace(string(out))
			if got != tt.want {
				t.Fatalf("detect_platform = %q, want %q", got, tt.want)
			}
		})
	}
}
