package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
		name             string
		unameS           string
		unameM           string
		env              map[string]string
		mockPowerShellOS string
		want             string
	}{
		{
			name:   "windows arm64 uses github runner architecture over emulated process hints",
			unameS: "MINGW64_NT-10.0",
			unameM: "x86_64",
			env: map[string]string{
				"RUNNER_ARCH":            "ARM64",
				"PROCESSOR_ARCHITECTURE": "AMD64",
			},
			want: "windows_arm64",
		},
		{
			name:             "windows arm64 uses powershell os architecture over env and uname",
			unameS:           "MINGW64_NT-10.0",
			unameM:           "x86_64",
			mockPowerShellOS: "Arm64",
			env: map[string]string{
				"PROCESSOR_ARCHITECTURE": "AMD64",
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
			toolDir := t.TempDir()
			powershellPath := filepath.Join(toolDir, "powershell.exe")
			powershellScript := "#!/usr/bin/env bash\nif [ -n \"$MOCK_POWERSHELL_OS\" ]; then\n\tprintf '%s\\r\\n' \"$MOCK_POWERSHELL_OS\"\n\texit 0\nfi\nexit 1\n"
			if err := os.WriteFile(powershellPath, []byte(powershellScript), 0o755); err != nil {
				t.Fatalf("write fake powershell: %v", err)
			}

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
			cmd.Env = filteredEnv(os.Environ(),
				"PATH",
				"PROCESSOR_ARCHITECTURE",
				"PROCESSOR_ARCHITEW6432",
				"RUNNER_ARCH",
				"MOCK_UNAME_S",
				"MOCK_UNAME_M",
				"MOCK_POWERSHELL_OS",
			)
			cmd.Env = append(cmd.Env,
				"MOCK_UNAME_S="+tt.unameS,
				"MOCK_UNAME_M="+tt.unameM,
				"MOCK_POWERSHELL_OS="+tt.mockPowerShellOS,
				"PATH="+toolDir+string(os.PathListSeparator)+os.Getenv("PATH"),
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

func filteredEnv(env []string, dropKeys ...string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if ok && slices.Contains(dropKeys, key) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}
