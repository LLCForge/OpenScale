//go:build linux

package posture

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"time"
)

func collect() Report {
	root := os.DirFS("/")
	return Report{
		DiskEncryption: rootEncrypted(root),
		Firewall:       linuxFirewall(root),
	}
}

func isWireless(name string) bool {
	if strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return false
	}
	if _, err := os.Stat("/sys/class/net/" + name + "/wireless"); err == nil {
		return true
	}
	if _, err := os.Stat("/sys/class/net/" + name + "/phy80211"); err == nil {
		return true
	}
	return false
}

// linuxFirewall reports ufw's own switch first, then nftables input
// filtering (root only; the ruleset is not readable otherwise).
func linuxFirewall(fsys fs.FS) State {
	if conf, err := readSmall(fsys, "etc/ufw/ufw.conf"); err == nil && ufwEnabled(conf) {
		return On
	}
	if os.Geteuid() != 0 {
		return Unknown
	}
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, p, "list", "ruleset")
		cmd.Stdout = &limitWriter{w: &out, n: 1 << 20}
		err := cmd.Run()
		cancel()
		if err != nil {
			return Unknown
		}
		return nftInputFiltering(out.String())
	}
	return Unknown
}

type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	if _, err := l.w.Write(q); err != nil {
		return 0, err
	}
	return len(p), nil
}

// DiskEncryption checks only the root file system's encryption.
func DiskEncryption() State { return rootEncrypted(os.DirFS("/")) }

// DeviceEncryption reports whether the block device "major:minor" sits
// on dm-crypt (LUKS), like DiskEncryption does for the root file system.
func DeviceEncryption(devnum string) State { return DeviceEncryptedIn(os.DirFS("/"), devnum) }

// VolumeEncryption is the Windows per-drive-letter check; Linux volumes
// use DeviceEncryption.
func VolumeEncryption() map[string]State { return nil }
