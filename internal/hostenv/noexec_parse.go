package hostenv

import (
	"path/filepath"
	"strings"
)

type mountEntry struct {
	mountPoint string
	options    map[string]struct{}
}

func parseMountinfo(content string) []mountEntry {
	var out []mountEntry
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || len(fields) < 6 {
			continue
		}
		// mountinfo format (kernel docs):
		// 1:id 2:parent 3:major:minor 4:root 5:mountpoint 6:options ... "-" fstype source superopts
		if len(fields) <= 5 {
			continue
		}

		mountPoint := unescapeMountPath(fields[4])
		opts := parseMountOptions(fields[5])

		// Also consider super options (after the "-" separator) since some flags appear there.
		if sep+3 < len(fields) {
			super := parseMountOptions(fields[sep+3])
			for k := range super {
				opts[k] = struct{}{}
			}
		}

		out = append(out, mountEntry{mountPoint: mountPoint, options: opts})
	}
	return out
}

func parseProcMounts(content string) []mountEntry {
	var out []mountEntry
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mountPoint := unescapeMountPath(fields[1])
		opts := parseMountOptions(fields[3])
		out = append(out, mountEntry{mountPoint: mountPoint, options: opts})
	}
	return out
}

func parseMountOptions(opt string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, part := range strings.Split(opt, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		m[part] = struct{}{}
	}
	return m
}

func unescapeMountPath(value string) string {
	// Procfs encodes spaces and a few special characters with octal escapes.
	// See: https://man7.org/linux/man-pages/man5/proc.5.html
	repl := strings.NewReplacer(
		"\\040", " ",
		"\\011", "\t",
		"\\012", "\n",
		"\\134", "\\",
	)
	return repl.Replace(value)
}

func detectNoExec(destPath string, mounts []mountEntry) bool {
	dest := filepath.ToSlash(filepath.Clean(destPath))
	if dest == "." || dest == "" {
		return false
	}

	bestLen := -1
	bestNoExec := false

	for _, m := range mounts {
		mountPoint := filepath.ToSlash(filepath.Clean(m.mountPoint))
		if mountPoint == "." || mountPoint == "" {
			continue
		}

		if !pathHasPrefix(dest, mountPoint) {
			continue
		}

		if len(mountPoint) > bestLen {
			bestLen = len(mountPoint)
			_, bestNoExec = m.options["noexec"]
		}
	}

	return bestNoExec
}

func pathHasPrefix(path, prefix string) bool {
	if prefix == "/" {
		return strings.HasPrefix(path, "/")
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}
