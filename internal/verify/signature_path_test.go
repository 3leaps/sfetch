package verify

import (
	"strings"
	"testing"
)

func TestNeedsMSYSPathConversion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		bin  string
		want bool
	}{
		{name: "git for windows", bin: `C:\Program Files\Git\usr\bin\gpg.exe`, want: true},
		{name: "git for windows slash", bin: `C:/Program Files/Git/usr/bin/gpg`, want: true},
		{name: "msys2 usr", bin: `C:\msys64\usr\bin\gpg.exe`, want: true},
		{name: "mingw64", bin: `C:\msys64\mingw64\bin\gpg.exe`, want: true},
		{name: "linux usr bin", bin: `/usr/bin/gpg`, want: false},
		{name: "bare name", bin: `gpg`, want: false},
		{name: "gpg4win", bin: `C:\Program Files (x86)\GnuPG\bin\gpg.exe`, want: false},
		{name: "empty", bin: ``, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := needsMSYSPathConversion(tc.bin); got != tc.want {
				t.Fatalf("needsMSYSPathConversion(%q)=%v want %v", tc.bin, got, tc.want)
			}
		})
	}
}

func TestToMSYSPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
	}{
		{`C:\Users\RUNNER~\AppData\Local\Temp\sfetch-gpg-1`, `/c/Users/RUNNER~/AppData/Local/Temp/sfetch-gpg-1`},
		{`D:\a\sfetch\sfetch`, `/d/a/sfetch/sfetch`},
		{`C:/Users/runner/tmp`, `/c/Users/runner/tmp`},
		{`C:`, `/c/`},
		{`/tmp/gpg-home`, `/tmp/gpg-home`},
		{`testdata/keys/test-pgp-pub.asc`, `testdata/keys/test-pgp-pub.asc`},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := toMSYSPath(tc.in); got != tc.want {
				t.Fatalf("toMSYSPath(%q)=%q want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestGpgPathArg(t *testing.T) {
	t.Parallel()

	winHome := `C:\Users\RUNNER~\AppData\Local\Temp\sfetch-gpg-1`
	msysHome := `/c/Users/RUNNER~/AppData/Local/Temp/sfetch-gpg-1`
	gitGPG := `C:\Program Files\Git\usr\bin\gpg.exe`

	got := gpgPathArg(gitGPG, winHome)
	if got != msysHome {
		t.Fatalf("git gpg homedir: got %q want %q", got, msysHome)
	}
	if strings.Contains(got, `C:`) || strings.Contains(got, `\`) {
		t.Fatalf("git gpg homedir still looks like a Windows path: %q", got)
	}

	native := gpgPathArg(`/usr/bin/gpg`, `/tmp/sfetch-gpg-1`)
	if native != `/tmp/sfetch-gpg-1` {
		t.Fatalf("linux gpg homedir: got %q want /tmp/sfetch-gpg-1", native)
	}

	gpg4win := gpgPathArg(`C:\Program Files (x86)\GnuPG\bin\gpg.exe`, winHome)
	if gpg4win != winHome {
		t.Fatalf("gpg4win homedir: got %q want %q", gpg4win, winHome)
	}
}
