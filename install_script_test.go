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

// TestInstallScriptDarwinAMD64GuardHonorsExplicitTag exercises the
// ADR-0002 retirement guard in scripts/install-sfetch.sh. Devrev caught
// a regression where the original guard fired for every Intel Mac
// invocation, including the documented recovery path
// `--tag v0.4.6`. The fix gates the guard on `$tag = "latest"`, so an
// explicit tag always wins.
func TestInstallScriptDarwinAMD64GuardHonorsExplicitTag(t *testing.T) {
	scriptBytes, err := os.ReadFile("scripts/install-sfetch.sh")
	if err != nil {
		t.Fatalf("read install script: %v", err)
	}
	// Strip `main "$@"` so the harness can call main() with controlled
	// argv and we never hit the network.
	script := strings.TrimSuffix(string(scriptBytes), "main \"$@\"\n")
	if script == string(scriptBytes) {
		t.Fatal("install script missing main invocation suffix")
	}

	scriptPath := filepath.Join(t.TempDir(), "install-sfetch-lib.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write temp script: %v", err)
	}

	tests := []struct {
		name         string
		args         string // space-separated main() args
		wantExit     bool   // true = script should exit non-zero at the guard
		wantContains string
	}{
		{
			name:         "no --tag on Intel Mac fires the guard",
			args:         "",
			wantExit:     true,
			wantContains: "darwin/amd64 (Intel Mac) is no longer supported",
		},
		{
			name:         "--tag v0.4.6 on Intel Mac bypasses the guard",
			args:         "--tag v0.4.6",
			wantExit:     false,
			wantContains: "",
		},
		{
			name:         "--tag v0.3.0 on Intel Mac bypasses the guard",
			args:         "--tag v0.3.0",
			wantExit:     false,
			wantContains: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Harness:
			// - Stub uname to report Darwin/x86_64 (Intel Mac).
			// - Redefine err() so the guard's exit is detectable without
			//   killing the test shell.
			// - Stub every network-touching helper invoked AFTER the
			//   guard so the test terminates deterministically on success.
			//   We only care whether the guard fired.
			harness := `
set -u
uname() {
	case "$1" in
		-s) printf 'Darwin\n' ;;
		-m) printf 'x86_64\n' ;;
		*) command uname "$@" ;;
	esac
}
source "$1"
# Replace err with a deterministic marker; the real err calls exit 1.
err() {
	printf 'ERR: %s\n' "$*" >&2
	exit 42
}
# Neutralize the downstream functions the guard precedes so the test
# exits cleanly if the guard is correctly skipped.
check_verification_tools() { :; }
fetch_release_meta() { exit 0; }
main ` + tc.args + `
# If main returns (no exit), the guard did not fire and downstream
# was stubbed. Report success explicitly.
echo "GUARD_SKIPPED"
`
			cmd := exec.Command("bash", "-c", harness, "bash", scriptPath)
			cmd.Env = filteredEnv(os.Environ(), "PATH")
			cmd.Env = append(cmd.Env, "PATH=/usr/bin:/bin")

			out, _ := cmd.CombinedOutput()
			exitCode := cmd.ProcessState.ExitCode()

			if tc.wantExit {
				if exitCode != 42 {
					t.Fatalf("expected guard exit (42), got %d\noutput:\n%s", exitCode, out)
				}
				if !strings.Contains(string(out), tc.wantContains) {
					t.Errorf("output should contain %q, got:\n%s", tc.wantContains, out)
				}
			} else {
				if strings.Contains(string(out), "darwin/amd64 (Intel Mac) is no longer supported") {
					t.Errorf("guard fired unexpectedly on %q; output:\n%s", tc.args, out)
				}
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
