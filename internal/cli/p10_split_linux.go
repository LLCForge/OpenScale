//go:build linux

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/openscale/openscale/internal/osnet"
)

// cmdSplitTunnelRun starts a program outside the exit node (#78,
// ADR-0134): it installs the bypass rules, moves this process into the
// bypass cgroup and replaces itself with the program, so the program and
// everything it starts inherit the group.
func cmdSplitTunnelRun(env *Env, args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return usageError("çalıştırılacak komut gerekli: openscale split-tunnel run -- <komut> [argümanlar]")
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("komut bulunamadı: %w", err)
	}
	if err := osnet.EnableSplitTunnel(envContext(env)); err != nil {
		return err
	}
	if err := osnet.JoinBypassGroup(os.Getpid()); err != nil {
		return err
	}
	fmt.Fprintf(env.Stderr, "%s çıkış düğümü dışında çalışıyor (kill switch bu programı engellemez).\n", args[0])
	return syscall.Exec(path, args, os.Environ())
}
