//go:build !linux

package hostenv

func IsNoExecMount(destPath string) bool {
	return false
}
