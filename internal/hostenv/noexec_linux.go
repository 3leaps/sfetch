//go:build linux

package hostenv

import "os"

func IsNoExecMount(destPath string) bool {
	// Best effort only: if anything looks odd, return false.
	if destPath == "" {
		return false
	}

	// Try mountinfo first (more detailed, includes overlay setups).
	if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil { // #nosec G304 -- fixed procfs path
		mounts := parseMountinfo(string(data))
		if len(mounts) > 0 {
			return detectNoExec(destPath, mounts)
		}
	}

	// Fall back to /proc/mounts.
	data, err := os.ReadFile("/proc/mounts") // #nosec G304 -- fixed procfs path
	if err != nil {
		return false
	}
	mounts := parseProcMounts(string(data))
	if len(mounts) == 0 {
		return false
	}
	return detectNoExec(destPath, mounts)
}
