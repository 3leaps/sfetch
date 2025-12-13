package update

import (
	"strings"
	"testing"
)

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		input  string
		want   string
		wantOK bool
	}{
		{"v0.2.5", "0.2.5", true},
		{"0.2.5", "0.2.5", true},
		{"v1.0.0", "1.0.0", true},
		{"1.0.0", "1.0.0", true},
		{"v10.20.30", "10.20.30", true},
		{"v0.1", "0.1", true},
		{"1.2", "1.2", true},
		{"v0.2.5-rc1", "0.2.5-rc1", true},
		{"v1.0.0+build123", "1.0.0+build123", true},

		{"dev", "", false},
		{"0.0.0-dev", "", false},
		{"", "", false},
		{"   ", "", false},
		{"v", "", false},
		{"vx.y.z", "", false},
		{"not-a-version", "", false},
		{"1", "", false},
		{"v1", "", false},
		{"abc.def.ghi", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := NormalizeVersion(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("NormalizeVersion(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("NormalizeVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a       string
		b       string
		want    int
		wantErr bool
	}{
		{"0.2.5", "0.2.5", 0, false},
		{"1.0.0", "1.0.0", 0, false},
		{"10.20.30", "10.20.30", 0, false},

		{"0.2.4", "0.2.5", -1, false},
		{"0.2.5", "0.3.0", -1, false},
		{"0.2.5", "1.0.0", -1, false},
		{"1.0.0", "1.0.1", -1, false},
		{"1.0.0", "1.1.0", -1, false},
		{"1.0.0", "2.0.0", -1, false},

		{"0.2.5", "0.2.4", 1, false},
		{"0.3.0", "0.2.5", 1, false},
		{"1.0.0", "0.2.5", 1, false},
		{"1.0.1", "1.0.0", 1, false},
		{"1.1.0", "1.0.0", 1, false},
		{"2.0.0", "1.0.0", 1, false},

		{"1.0", "1.0.0", 0, false},
		{"1.0", "1.0.1", -1, false},
		{"1.1", "1.0.0", 1, false},

		{"0.2.5-rc1", "0.2.5", -1, false},
		{"0.2.5", "0.2.5-beta", 1, false},
		{"0.2.5-rc1", "0.2.5-rc2", -1, false},
		{"0.2.5-rc.10", "0.2.5-rc.2", 1, false},

		{"invalid", "0.2.5", 0, true},
		{"0.2.5", "invalid", 0, true},
		{"1", "1.0.0", 0, true},
	}

	for _, tt := range tests {
		name := tt.a + "_vs_" + tt.b
		t.Run(name, func(t *testing.T) {
			got, err := CompareSemver(tt.a, tt.b)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("CompareSemver(%q, %q) expected error, got nil", tt.a, tt.b)
				}
				return
			}
			if err != nil {
				t.Fatalf("CompareSemver(%q, %q) unexpected error: %v", tt.a, tt.b, err)
			}
			if got != tt.want {
				t.Fatalf("CompareSemver(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestDecideSelfUpdate(t *testing.T) {
	tests := []struct {
		name        string
		current     string
		target      string
		explicitTag bool
		force       bool
		wantDec     Decision
		wantExit    int
	}{
		{"same version skips", "0.2.5", "v0.2.5", false, false, DecisionSkip, 0},
		{"same version with force reinstalls", "0.2.5", "v0.2.5", false, true, DecisionReinstall, 0},

		{"upgrade available proceeds", "0.2.4", "v0.2.5", false, false, DecisionProceed, 0},
		{"major upgrade refused without force", "0.2.5", "v1.0.0", false, false, DecisionRefuse, 1},
		{"major upgrade allowed with force", "0.2.5", "v1.0.0", false, true, DecisionProceed, 0},

		{"downgrade with tag proceeds", "0.2.5", "v0.2.3", true, false, DecisionDowngrade, 0},
		{"downgrade without tag skips", "0.2.5", "v0.2.3", false, false, DecisionSkip, 0},
		{"major downgrade refused without force", "1.0.0", "v0.2.5", true, false, DecisionRefuse, 1},
		{"major downgrade allowed with force", "1.0.0", "v0.2.5", true, true, DecisionDowngrade, 0},

		{"dev build proceeds", "dev", "v0.2.5", false, false, DecisionDevInstall, 0},
		{"0.0.0-dev build proceeds", "0.0.0-dev", "v0.2.5", false, false, DecisionDevInstall, 0},
		{"empty version proceeds", "", "v0.2.5", false, false, DecisionDevInstall, 0},

		{"unparseable target proceeds with warning", "0.2.5", "not-a-version", false, false, DecisionProceed, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec, msg, exitCode := DecideSelfUpdate(tt.current, tt.target, tt.explicitTag, tt.force)
			if dec != tt.wantDec {
				t.Fatalf("decision = %v, want %v (msg: %s)", dec, tt.wantDec, msg)
			}
			if exitCode != tt.wantExit {
				t.Fatalf("exitCode = %d, want %d", exitCode, tt.wantExit)
			}
			if msg == "" {
				t.Fatal("message should not be empty")
			}
		})
	}
}

func TestFormatVersionDisplay(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0.2.5", "v0.2.5"},
		{"v0.2.5", "v0.2.5"},
		{"dev", "dev"},
		{"", ""},
		{"0.0.0-dev", "0.0.0-dev"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := FormatVersionDisplay(tt.input)
			if got != tt.want {
				t.Fatalf("FormatVersionDisplay(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDescribeDecision(t *testing.T) {
	tests := []struct {
		decision     Decision
		wantContains string
	}{
		{DecisionSkip, "latest"},
		{DecisionRefuse, "refused"},
		{DecisionProceed, "available"},
		{DecisionReinstall, "reinstall"},
		{DecisionDowngrade, "downgrade"},
		{DecisionDevInstall, "dev"},
	}

	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			got := DescribeDecision(tt.decision)
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tt.wantContains)) {
				t.Fatalf("DescribeDecision(%v) = %q, want to contain %q", tt.decision, got, tt.wantContains)
			}
		})
	}
}
