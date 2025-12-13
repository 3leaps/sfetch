package update

import (
	"fmt"
	"strconv"
	"strings"
)

type Decision string

const (
	DecisionProceed    Decision = "proceed"    // Proceed with update
	DecisionSkip       Decision = "skip"       // Skip, already at target version
	DecisionRefuse     Decision = "refuse"     // Refuse (e.g., cross-major without force)
	DecisionReinstall  Decision = "reinstall"  // Force reinstall same version
	DecisionDowngrade  Decision = "downgrade"  // Explicit downgrade with --tag
	DecisionDevInstall Decision = "devinstall" // Installing release from dev build
)

// FormatVersionDisplay formats a version string for display, adding "v" prefix if needed.
func FormatVersionDisplay(v string) string {
	if v == "" || v == "dev" || v == "0.0.0-dev" {
		return v
	}
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// NormalizeVersion strips the leading "v" prefix and validates that the version
// is semver-like (at least MAJOR.MINOR, optionally with PATCH, prerelease, and/or build metadata).
// Returns the normalized version string and a boolean indicating whether comparison is possible.
// "dev", empty strings, and non-semver formats return ("", false).
func NormalizeVersion(v string) (string, bool) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" || trimmed == "dev" || trimmed == "0.0.0-dev" {
		return "", false
	}

	normalized := strings.TrimPrefix(trimmed, "v")
	parts := strings.Split(normalized, ".")
	if len(parts) < 2 {
		return "", false
	}

	for i := 0; i < 2; i++ {
		if _, err := strconv.Atoi(parts[i]); err != nil {
			return "", false
		}
	}

	if len(parts) >= 3 {
		patchPart := parts[2]
		if idx := strings.IndexAny(patchPart, "-+"); idx >= 0 {
			patchPart = patchPart[:idx]
		}
		if patchPart != "" {
			if _, err := strconv.Atoi(patchPart); err != nil {
				return "", false
			}
		}
	}

	return normalized, true
}

type semverParts struct {
	major      int
	minor      int
	patch      int
	prerelease []string
}

func parseSemver(normalized string) (semverParts, error) {
	var out semverParts

	base := normalized
	if idx := strings.IndexByte(base, '+'); idx >= 0 {
		base = base[:idx]
	}

	var prerelease string
	if idx := strings.IndexByte(base, '-'); idx >= 0 {
		prerelease = base[idx+1:]
		base = base[:idx]
	}

	parts := strings.Split(base, ".")
	if len(parts) < 2 {
		return semverParts{}, fmt.Errorf("invalid semver format")
	}

	var err error
	out.major, err = strconv.Atoi(parts[0])
	if err != nil {
		return semverParts{}, fmt.Errorf("parse major %q: %w", parts[0], err)
	}
	out.minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return semverParts{}, fmt.Errorf("parse minor %q: %w", parts[1], err)
	}
	out.patch = 0
	if len(parts) >= 3 && parts[2] != "" {
		out.patch, err = strconv.Atoi(parts[2])
		if err != nil {
			return semverParts{}, fmt.Errorf("parse patch %q: %w", parts[2], err)
		}
	}

	if prerelease != "" {
		out.prerelease = strings.Split(prerelease, ".")
	}

	return out, nil
}

func comparePrerelease(a, b []string) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}

	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		ai, bi := a[i], b[i]
		aNum, aErr := strconv.Atoi(ai)
		bNum, bErr := strconv.Atoi(bi)
		aIsNum := aErr == nil
		bIsNum := bErr == nil

		switch {
		case aIsNum && bIsNum:
			if aNum < bNum {
				return -1
			}
			if aNum > bNum {
				return 1
			}
		case aIsNum && !bIsNum:
			return -1
		case !aIsNum && bIsNum:
			return 1
		default:
			if ai < bi {
				return -1
			}
			if ai > bi {
				return 1
			}
		}
	}

	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// CompareSemver compares two normalized semver-like strings.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Supports MAJOR.MINOR[.PATCH] with optional prerelease/build metadata; build metadata is ignored.
// Returns an error if either version cannot be parsed.
func CompareSemver(a, b string) (int, error) {
	av, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	bv, err := parseSemver(b)
	if err != nil {
		return 0, err
	}

	switch {
	case av.major < bv.major:
		return -1, nil
	case av.major > bv.major:
		return 1, nil
	case av.minor < bv.minor:
		return -1, nil
	case av.minor > bv.minor:
		return 1, nil
	case av.patch < bv.patch:
		return -1, nil
	case av.patch > bv.patch:
		return 1, nil
	}

	return comparePrerelease(av.prerelease, bv.prerelease), nil
}

func majorVersionFromNormalized(normalized string) (int, error) {
	t := strings.TrimSpace(normalized)
	if t == "" {
		return 0, fmt.Errorf("empty version")
	}
	parts := strings.Split(t, ".")
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("parse major: %w", err)
	}
	return major, nil
}

// DecideSelfUpdate determines whether a self-update should proceed.
//
// current: running binary version (e.g. "0.2.5" or "dev")
// target:  target release tag (e.g. "v0.2.6")
// explicitTag: true if user specified --tag (allows downgrades)
// force: true if --self-update-force was specified
//
// Returns a Decision, a human message, and an exit code suggestion (0=success/skip, 1=refuse).
func DecideSelfUpdate(current, target string, explicitTag, force bool) (Decision, string, int) {
	currentNorm, currentOK := NormalizeVersion(current)
	targetNorm, targetOK := NormalizeVersion(target)

	if !currentOK {
		if current == "dev" || current == "0.0.0-dev" || current == "" {
			msg := fmt.Sprintf("Installing sfetch %s (replacing dev build)", FormatVersionDisplay(target))
			return DecisionDevInstall, msg, 0
		}
		msg := fmt.Sprintf("Version comparison skipped (current=%q, target=%s). Proceeding with verified install.", current, FormatVersionDisplay(target))
		return DecisionProceed, msg, 0
	}

	if !targetOK {
		msg := fmt.Sprintf("Version comparison skipped (current=%s, target=%q). Proceeding with verified install.", FormatVersionDisplay(currentNorm), target)
		return DecisionProceed, msg, 0
	}

	cmp, err := CompareSemver(currentNorm, targetNorm)
	if err != nil {
		msg := fmt.Sprintf("Version comparison failed: %v. Proceeding with verified install.", err)
		return DecisionProceed, msg, 0
	}

	currentMajor, _ := majorVersionFromNormalized(currentNorm)
	targetMajor, _ := majorVersionFromNormalized(targetNorm)

	switch cmp {
	case 0:
		if force {
			msg := fmt.Sprintf("Reinstalling sfetch %s...", FormatVersionDisplay(targetNorm))
			return DecisionReinstall, msg, 0
		}
		msg := fmt.Sprintf("Already at latest version (%s). Use --self-update-force to reinstall.", FormatVersionDisplay(targetNorm))
		return DecisionSkip, msg, 0

	case -1:
		if currentMajor != targetMajor && !force {
			msg := fmt.Sprintf("Refusing self-update across major versions (%s → %s); rerun with --self-update-force to proceed.",
				FormatVersionDisplay(currentNorm), FormatVersionDisplay(targetNorm))
			return DecisionRefuse, msg, 1
		}
		msg := fmt.Sprintf("Updating sfetch: %s → %s", FormatVersionDisplay(currentNorm), FormatVersionDisplay(targetNorm))
		return DecisionProceed, msg, 0

	case 1:
		if !explicitTag {
			msg := fmt.Sprintf("Already at version %s (target %s is older). Use --tag to downgrade.",
				FormatVersionDisplay(currentNorm), FormatVersionDisplay(targetNorm))
			return DecisionSkip, msg, 0
		}
		if currentMajor != targetMajor && !force {
			msg := fmt.Sprintf("Refusing downgrade across major versions (%s → %s); rerun with --self-update-force to proceed.",
				FormatVersionDisplay(currentNorm), FormatVersionDisplay(targetNorm))
			return DecisionRefuse, msg, 1
		}
		msg := fmt.Sprintf("Downgrading sfetch: %s → %s", FormatVersionDisplay(currentNorm), FormatVersionDisplay(targetNorm))
		return DecisionDowngrade, msg, 0
	}

	return DecisionProceed, "", 0
}

// DescribeDecision returns a human-readable dry-run status.
func DescribeDecision(d Decision) string {
	switch d {
	case DecisionSkip:
		return "Already at latest version (no update needed)"
	case DecisionRefuse:
		return "Update refused (cross-major version change)"
	case DecisionProceed:
		return "Update available"
	case DecisionReinstall:
		return "Force reinstall requested"
	case DecisionDowngrade:
		return "Downgrade available"
	case DecisionDevInstall:
		return "Installing release (replacing dev build)"
	default:
		return string(d)
	}
}
