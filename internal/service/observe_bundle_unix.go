//go:build !windows

package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// bundleTool finds a tool in the root-owned system folders only.
func bundleTool(name string) (string, error) {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/run/current-system/sw/bin"} {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("sistem aracı bulunamadı")
}

// prepareBundleCommand gives the tool a fixed environment.
func prepareBundleCommand(cmd *exec.Cmd) {
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
}

// systemDumps are the routes, policy rules, addresses and nftables rules,
// read only.
func systemDumps(ctx context.Context) map[string]string {
	switch runtime.GOOS {
	case "linux":
		return map[string]string{
			"ip-addr.txt":        runForBundle(ctx, "ip", "addr", "show"),
			"ip-route-v4.txt":    runForBundle(ctx, "ip", "-4", "route", "show", "table", "all"),
			"ip-route-v6.txt":    runForBundle(ctx, "ip", "-6", "route", "show", "table", "all"),
			"ip-rule-v4.txt":     runForBundle(ctx, "ip", "-4", "rule", "show"),
			"ip-rule-v6.txt":     runForBundle(ctx, "ip", "-6", "rule", "show"),
			"nft-ruleset.txt":    runForBundle(ctx, "nft", "list", "ruleset"),
			"resolvectl.txt":     runForBundle(ctx, "resolvectl", "status"),
			"resolv-conf.txt":    readForBundle("/etc/resolv.conf"),
			"nsswitch-hosts.txt": readForBundle("/etc/nsswitch.conf"),
		}
	case "darwin", "freebsd", "openbsd", "netbsd":
		return map[string]string{
			"netstat-routes.txt": runForBundle(ctx, "netstat", "-rn"),
			"ifconfig.txt":       runForBundle(ctx, "ifconfig"),
			"resolv-conf.txt":    readForBundle("/etc/resolv.conf"),
		}
	}
	return nil
}

func readForBundle(path string) string {
	s, err := tailFile(path, maxBundleFile)
	if err != nil {
		return "(" + err.Error() + ")\n"
	}
	return s
}
