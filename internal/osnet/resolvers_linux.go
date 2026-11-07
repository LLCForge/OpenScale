//go:build linux

package osnet

import (
	"context"
	"time"
)

// SystemResolvers returns the DNS servers in use: every link's servers
// from systemd-resolved when it runs, plus the nameservers of
// /etc/resolv.conf (the stub 127.0.0.53 with resolved). Nothing is
// queried.
func SystemResolvers() ([]SystemResolver, error) {
	return systemResolvers(hostOps)
}

func systemResolvers(o sysOps) ([]SystemResolver, error) {
	var res []SystemResolver
	if o.has("resolvectl") {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := o.run(ctx, nil, "resolvectl", "dns"); err == nil {
			res = append(res, parseResolvectlDNS(string(out))...)
		}
	}
	data, err := o.read("/etc/resolv.conf")
	if err != nil && res == nil {
		return nil, err
	}
	return append(res, parseResolvConf(string(data))...), nil
}

// LeakGuardInstalled reports whether the DNS and IPv6 leak guard table is
// in place (the exit node is in use with nft available).
func LeakGuardInstalled() (bool, error) {
	if !hostOps.has("nft") {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := hostOps.run(ctx, nil, "nft", "list", "table", "inet", leakGuardTable)
	switch {
	case err == nil:
		return true, nil
	case nftMissing(err):
		return false, nil
	default:
		return false, err
	}
}
