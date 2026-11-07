//go:build darwin

package osnet

import (
	"context"
	"net"
	"net/netip"
	"os"

	"github.com/openscale/openscale/internal/securefile"
)

// darwinRun is how the macOS code touches the system.
var darwinRun darwinRunner = runDarwinCommand

func configure(ctx context.Context, c Config) error {
	return configureDarwin(ctx, darwinRun, c)
}

func defaultGateways4() ([]netip.Addr, error) {
	return defaultGatewaysDarwin(context.Background(), darwinRun)
}

// platformTUNName maps the requested name to utun / utunN (ADR-0100).
func platformTUNName(name string) string { return darwinTUNName(name) }

func darwinIfIndex(name string) (int, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifi.Index, nil
}

func darwinExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// writePublicFile replaces p atomically with a root-owned, world-readable
// file (launchd refuses group- or world-writable daemons).
func writePublicFile(p string, data []byte) error {
	tmp := p + ".openscale-tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

var (
	hostDarwinDNS = darwinDNS{dir: darwinResolverDir, run: darwinRun}

	hostDarwinExit = func() *darwinExit {
		return &darwinExit{
			run:      darwinRun,
			stateDir: darwinStateDir,
			write:    securefile.Replace,
			read:     securefile.ReadPrivate,
			remove:   os.Remove,
			ifIndex:  darwinIfIndex,
		}
	}

	hostKillSwitch = &pfKillSwitch{
		run:         darwinRun,
		stateDir:    darwinStateDir,
		launchDir:   "/Library/LaunchDaemons",
		pfConf:      pfConfPath,
		write:       securefile.Replace,
		writePublic: writePublicFile,
		read:        securefile.ReadPrivate,
		remove:      os.Remove,
		exists:      darwinExists,
	}
)
