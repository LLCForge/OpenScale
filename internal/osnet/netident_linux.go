//go:build linux

package osnet

import (
	"context"
	"os"
	"strings"
	"time"
)

// CurrentNetworks lists the connected networks. It asks NetworkManager
// (nmcli) and falls back to the default route interfaces: an interface
// with a /sys/class/net/<if>/wireless directory is Wi-Fi (named by
// iwgetid), any other is wired.
func CurrentNetworks() ([]CurrentNetwork, error) {
	return currentNetworks(hostOps)
}

func currentNetworks(o sysOps) ([]CurrentNetwork, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if o.has("nmcli") {
		out, err := o.run(ctx, nil, "nmcli", "-t", "-f", "TYPE,STATE,CONNECTION", "device")
		if err == nil {
			return parseNmcliDevices(string(out)), nil
		}
	}
	var nets []CurrentNetwork
	for _, dev := range o.ipv4DefaultInterfaces() {
		if _, err := o.read("/sys/class/net/" + dev + "/wireless/"); err != nil && !isDirError(err) {
			nets = append(nets, CurrentNetwork{Kind: NetworkWired, Name: dev})
			continue
		}
		name := ""
		if o.has("iwgetid") {
			if out, err := o.run(ctx, nil, "iwgetid", dev, "-r"); err == nil {
				name = cleanNetworkName(strings.TrimSpace(string(out)))
			}
		}
		nets = append(nets, CurrentNetwork{Kind: NetworkWiFi, Name: name})
	}
	return nets, nil
}

// isDirError reports whether reading a path failed because it is a
// directory, which means it exists.
func isDirError(err error) bool {
	if pe, ok := err.(*os.PathError); ok {
		return strings.Contains(pe.Err.Error(), "directory")
	}
	return strings.Contains(err.Error(), "is a directory")
}
