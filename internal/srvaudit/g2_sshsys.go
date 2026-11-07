package srvaudit

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// hostSSHSystem is the real SSHSystem (Linux, root).
type hostSSHSystem struct{}

// HostSSHSystem returns the SSHSystem of this computer. It refuses to act
// outside Linux.
func HostSSHSystem() (SSHSystem, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("yalnızca Linux sunucularda desteklenir")
	}
	return hostSSHSystem{}, nil
}

func (hostSSHSystem) abs(name string) string { return filepath.Join("/", filepath.FromSlash(name)) }

func (h hostSSHSystem) WriteFile(name string, data []byte) error {
	p := h.abs(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".openscale-tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil { //nolint:gosec // sshd configuration is world-readable
		return err
	}
	return os.Rename(tmp, p)
}

func (h hostSSHSystem) Remove(name string) error { return os.Remove(h.abs(name)) }

func (hostSSHSystem) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // fixed programs
}

func (hostSSHSystem) HostAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out, nil
}

// SessionSource parses SSH_CONNECTION ("client port server port").
func (hostSSHSystem) SessionSource() (netip.Addr, bool) {
	return sessionFromEnv(os.Getenv("SSH_CONNECTION"))
}

func sessionFromEnv(v string) (netip.Addr, bool) {
	f := strings.Fields(v)
	if len(f) < 1 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(f[0])
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func (hostSSHSystem) Listeners() []Listener { return ReadListeners(os.DirFS("/")) }

func (hostSSHSystem) Sleep(d time.Duration) { time.Sleep(d) }
