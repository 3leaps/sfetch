package hostenv

import "testing"

func TestDetectNoExecMountinfoLongestMatchWins(t *testing.T) {
	content := `36 25 0:32 / / rw,relatime - overlay overlay rw,noexec
40 36 0:45 / /home rw,relatime - ext4 /dev/sda rw
41 40 0:46 / /home/user rw,relatime - ext4 /dev/sda rw,noexec
`

	mounts := parseMountinfo(content)
	if len(mounts) != 3 {
		t.Fatalf("expected 3 mounts, got %d", len(mounts))
	}

	if got := detectNoExec("/tmp/bin", mounts); !got {
		t.Fatalf("expected /tmp/bin to inherit / noexec")
	}
	if got := detectNoExec("/home/other/bin", mounts); got {
		t.Fatalf("expected /home/other/bin to be exec")
	}
	if got := detectNoExec("/home/user/bin", mounts); !got {
		t.Fatalf("expected /home/user/bin to be noexec (longest match)")
	}
}

func TestDetectNoExecProcMounts(t *testing.T) {
	content := `/dev/sda1 / ext4 rw,relatime,noexec 0 0
/dev/sda2 /home ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0
`
	mounts := parseProcMounts(content)
	if len(mounts) != 3 {
		t.Fatalf("expected 3 mounts, got %d", len(mounts))
	}

	if got := detectNoExec("/tmp/foo", mounts); !got {
		t.Fatalf("expected /tmp/foo to be noexec")
	}
	if got := detectNoExec("/home/user/bin", mounts); got {
		t.Fatalf("expected /home/user/bin to be exec")
	}
	if got := detectNoExec("/bin", mounts); !got {
		t.Fatalf("expected /bin to inherit / noexec")
	}
}

func TestUnescapeMountPath(t *testing.T) {
	content := `1 2 3:4 / /path\040with\040space rw,relatime - ext4 /dev/sda rw,noexec
`
	mounts := parseMountinfo(content)
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}

	if got := mounts[0].mountPoint; got != "/path with space" {
		t.Fatalf("mountPoint unescape: got %q", got)
	}
	if got := detectNoExec("/path with space/bin", mounts); !got {
		t.Fatalf("expected /path with space/bin to be noexec")
	}
}

func TestDetectNoExecEmptyInput(t *testing.T) {
	if got := detectNoExec("/tmp", nil); got {
		t.Fatalf("expected false")
	}
	mounts := parseMountinfo("garbage")
	if got := detectNoExec("/tmp", mounts); got {
		t.Fatalf("expected false")
	}
}
