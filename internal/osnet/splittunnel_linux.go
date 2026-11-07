//go:build linux

package osnet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	splitTable    = "openscale_split"
	cgroupRoot    = "/sys/fs/cgroup"
	splitCgroupFS = cgroupRoot + "/" + BypassCgroup
)

// splitRules marks every socket of the bypass group with the tunnel bypass
// mark. A "route" chain re-routes the packet after the mark is set.
func splitRules() string {
	mark := "0x" + strconv.FormatUint(TunnelBypassMark, 16)
	return "table inet " + splitTable + "\n" +
		"delete table inet " + splitTable + "\n" +
		"table inet " + splitTable + " {\n" +
		"\tchain output {\n" +
		"\t\ttype route hook output priority mangle - 5; policy accept;\n" +
		"\t\tsocket cgroupv2 level 1 \"" + BypassCgroup + "\" meta mark set " + mark + "\n" +
		"\t}\n" +
		"}\n"
}

// splitFS is how the split tunnel touches cgroupfs (tests replace it).
var splitFS = struct {
	mkdir     func(path string) error
	writeFile func(path string, data []byte) error
	stat      func(path string) error
}{
	mkdir:     func(p string) error { return os.Mkdir(p, 0o755) },
	writeFile: func(p string, d []byte) error { return os.WriteFile(p, d, 0o644) },
	stat:      func(p string) error { _, err := os.Stat(p); return err },
}

// EnableSplitTunnel creates the bypass group and installs the marking
// rules. It needs cgroup v2 and nft.
func EnableSplitTunnel(ctx context.Context) error {
	return enableSplitTunnel(ctx, hostOps)
}

func enableSplitTunnel(ctx context.Context, o sysOps) error {
	if err := splitFS.stat(cgroupRoot + "/cgroup.controllers"); err != nil {
		return errors.New("cgroup v2 bulunamadı; uygulama bazlı tünel kullanılamıyor")
	}
	if !o.has("nft") {
		return errors.New("nft bulunamadı; uygulama bazlı tünel kullanılamıyor")
	}
	if err := splitFS.mkdir(splitCgroupFS); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("cgroup oluşturulamadı: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := o.run(ctx, []byte(splitRules()), "nft", "-f", "-")
	return err
}

// DisableSplitTunnel removes the marking rules; programs still in the
// group then use the exit node like every other program.
func DisableSplitTunnel(ctx context.Context) error {
	return disableSplitTunnel(ctx, hostOps)
}

func disableSplitTunnel(ctx context.Context, o sysOps) error {
	if !o.has("nft") {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, _ = o.run(ctx, nil, "nft", "delete", "table", "inet", splitTable)
	return nil
}

// JoinBypassGroup moves process pid into the bypass group, for example the
// CLI itself right before it starts the excluded program.
func JoinBypassGroup(pid int) error {
	if pid <= 0 {
		return errors.New("invalid pid")
	}
	if err := splitFS.writeFile(splitCgroupFS+"/cgroup.procs", []byte(strconv.Itoa(pid))); err != nil {
		return fmt.Errorf("süreç gruba alınamadı (root gerekir): %w", err)
	}
	return nil
}

// SplitTunnelSupported reports whether this system has per-application
// split tunneling.
func SplitTunnelSupported() bool { return true }
