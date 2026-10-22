package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVersionSubcommandNotParsedAsURL(t *testing.T) {
	t.Parallel()

	var stdout, stderr strings.Builder
	code := run([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("version exit %d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.Contains(stderr.String(), "invalid URL") {
		t.Fatalf("version was parsed as a URL: stderr=%q", stderr.String())
	}
	if got, want := strings.TrimSpace(stdout.String()), "sfetch "+version; got != want {
		t.Fatalf("version stdout: got %q want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("version wrote stderr: %q", stderr.String())
	}
}

func TestVersionAndVersionFlagShareStdout(t *testing.T) {
	t.Parallel()

	var subOut, flagOut, subErr, flagErr strings.Builder
	if code := run([]string{"version"}, &subOut, &subErr); code != 0 {
		t.Fatalf("version exit %d stderr=%q", code, subErr.String())
	}
	if code := run([]string{"--version"}, &flagOut, &flagErr); code != 0 {
		t.Fatalf("--version exit %d stderr=%q", code, flagErr.String())
	}
	if subOut.String() != flagOut.String() {
		t.Fatalf("version vs --version stdout: %q vs %q", subOut.String(), flagOut.String())
	}
	if subErr.Len() != 0 || flagErr.Len() != 0 {
		t.Fatalf("stderr not empty: sub=%q flag=%q", subErr.String(), flagErr.String())
	}
}

func TestVersionExtended(t *testing.T) {
	t.Parallel()

	cases := [][]string{
		{"version", "--extended"},
		{"version", "-e"},
		{"--version-extended"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			code := run(args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit %d stderr=%q", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("wrote stderr: %q", stderr.String())
			}
			got := stdout.String()
			for _, want := range []string{
				"sfetch " + version,
				"git commit:",
				"build time:",
				"go version:",
				"os/arch:",
				runtime.Version(),
				runtime.GOOS + "/" + runtime.GOARCH,
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("missing %q in stdout:\n%s", want, got)
				}
			}
		})
	}
}

func TestVersionJSON(t *testing.T) {
	t.Parallel()

	cases := [][]string{
		{"version", "--json"},
		{"--version", "--json"},
		{"--json", "version"},
		{"version", "--extended", "--json"},
		{"--version-extended", "--json"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			code := run(args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit %d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("wrote stderr: %q", stderr.String())
			}
			var info versionInfoJSON
			if err := json.Unmarshal([]byte(stdout.String()), &info); err != nil {
				t.Fatalf("json: %v\nstdout=%q", err, stdout.String())
			}
			if info.Version != version {
				t.Fatalf("version: got %q want %q", info.Version, version)
			}
			if info.GitCommit != gitCommit {
				t.Fatalf("gitCommit: got %q want %q", info.GitCommit, gitCommit)
			}
			if info.BuildTime != buildTime {
				t.Fatalf("buildTime: got %q want %q", info.BuildTime, buildTime)
			}
			if info.GoVersion != runtime.Version() {
				t.Fatalf("goVersion: got %q want %q", info.GoVersion, runtime.Version())
			}
			if info.OS != runtime.GOOS || info.Arch != runtime.GOARCH {
				t.Fatalf("os/arch: got %s/%s want %s/%s", info.OS, info.Arch, runtime.GOOS, runtime.GOARCH)
			}
		})
	}
}

func TestVersionRejectsExtraPositionals(t *testing.T) {
	t.Parallel()

	var stdout, stderr strings.Builder
	code := run([]string{"version", "https://example.com/"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected failure, stdout=%q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "positional") {
		t.Fatalf("stderr: got %q", stderr.String())
	}
}

func TestVersionPositionalURLStillWorks(t *testing.T) {
	t.Parallel()

	var stdout, stderr strings.Builder
	code := run([]string{"https://example.com/", "--dry-run", "--skip-tools-check"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("positional URL exit %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "sfetch dry-run assessment") {
		t.Fatalf("stderr: got %q", stderr.String())
	}
}

func TestCLIHelpMentionsVersionSubcommand(t *testing.T) {
	t.Parallel()

	var stdout, stderr strings.Builder
	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("--help exit %d", code)
	}
	if !strings.Contains(stdout.String(), "sfetch version") {
		t.Fatalf("help missing version subcommand:\n%s", stdout.String())
	}
}

func TestVersionIsolatedMakefileBinary(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not found")
	}

	expectedVersionBytes, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	expectedVersion := strings.TrimSpace(string(expectedVersionBytes))
	if expectedVersion == "" || expectedVersion == "dev" {
		t.Fatalf("VERSION file is %q", expectedVersion)
	}

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	tmp := t.TempDir()
	artifact := filepath.Join(tmp, "build", "sfetch"+ext)
	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		t.Fatalf("mkdir build: %v", err)
	}

	build := exec.Command("make", "build", "BUILD_ARTIFACT="+artifact)
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("make build: %v\n%s", err, out)
	}

	isolated := filepath.Join(tmp, "isolated")
	if err := os.MkdirAll(isolated, 0o755); err != nil {
		t.Fatalf("mkdir isolated: %v", err)
	}
	bin := filepath.Join(isolated, "sfetch"+ext)
	if err := copyFile(artifact, bin); err != nil {
		t.Fatalf("copy binary: %v", err)
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}

	runBin := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = isolated
		cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v: %v\nstderr=%s\nstdout=%s", args, err, stderr.String(), stdout.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("%v wrote stderr: %q", args, stderr.String())
		}
		return stdout.String()
	}

	for _, args := range [][]string{{"version"}, {"--version"}, {"version", "--extended"}} {
		got := runBin(args...)
		if !strings.Contains(got, expectedVersion) {
			t.Fatalf("%v output %q missing VERSION %q", args, got, expectedVersion)
		}
		if strings.Contains(got, "sfetch dev") {
			t.Fatalf("%v output is uninjected dev: %q", args, got)
		}
	}

	extended := runBin("version", "--extended")
	if strings.Contains(extended, "git commit: unknown") {
		t.Fatalf("commit is unknown:\n%s", extended)
	}
}

func TestVersionHelp(t *testing.T) {
	t.Parallel()

	var stdout, stderr strings.Builder
	code := run([]string{"version", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("version --help exit %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "sfetch version") {
		t.Fatalf("version help: %q", stdout.String())
	}
}
