//go:build freebsd || openbsd

package osnet

import (
	"context"
	"net/netip"
	"runtime"
)

// bsdRun is how the BSD code touches the system.
var bsdRun bsdRunner = runBSDCommand

func hostBSDFlavor() bsdFlavor {
	if runtime.GOOS == "openbsd" {
		return flavorOpenBSD
	}
	return flavorFreeBSD
}

func configure(ctx context.Context, c Config) error {
	return configureBSD(ctx, bsdRun, hostBSDFlavor(), c)
}

func defaultGateways4() ([]netip.Addr, error) {
	return defaultGatewaysBSD(context.Background(), bsdRun)
}
