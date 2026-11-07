//go:build windows

package osnet

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/trust"
)

const (
	exitNRPTComment = "OpenScale-exit"
	rebindEvery     = 5 * time.Second
)

// splitRoutes cover the whole internet while staying more specific than
// the real default route, which therefore never has to be touched.
var (
	splitRoutes4 = []string{"0.0.0.0/1", "128.0.0.0/1"}
	splitRoutes6 = []string{"::/1", "8000::/1"}
)

// windowsExitRouter sends all internet traffic into the tunnel while an
// exit node is used (ADR-0018). WireGuard's own UDP sockets are bound to
// the real default interface, so its packets never loop into the tunnel.
// If the exit node is unreachable, traffic stays in the tunnel instead of
// leaking out directly.
type windowsExitRouter struct {
	mu    sync.Mutex
	iface string
	stop  chan struct{}
	bind  conn.Bind
}

// NewExitRouter returns the OS router for using an exit node.
func NewExitRouter() interface {
	Enable(trust.Device, *trust.Document, string, conn.Bind) error
	Disable() error
} {
	return &windowsExitRouter{}
}

func (r *windowsExitRouter) Enable(exit trust.Device, _ *trust.Document, iface string, bind conn.Bind) error {
	if err := (DNSConfig{Interface: iface, Server: exit.IPv4, Domain: "x.internal"}).validate(); err != nil {
		return err
	}
	r.Disable()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tunIdx := interfaceIndex(iface)
	if err := bindToDefault(bind, tunIdx); err != nil {
		return err
	}
	for _, p := range splitRoutes4 {
		if err := run(ctx, "netsh", "interface", "ipv4", "add", "route", "prefix="+p, "interface="+iface, "store=active", "metric=1"); err != nil {
			r.cleanup(iface, bind)
			return err
		}
	}
	for _, p := range splitRoutes6 {
		// IPv6 without an IPv6 exit simply goes nowhere: no leak.
		_ = run(ctx, "netsh", "interface", "ipv6", "add", "route", "prefix="+p, "interface="+iface, "store=active", "metric=1")
	}
	script := "$ErrorActionPreference='Stop'; " +
		"Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" + exitNRPTComment + "' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }; " +
		"Add-DnsClientNrptRule -Namespace '.' -NameServers '" + exit.IPv4.String() + "' -Comment '" + exitNRPTComment + "' | Out-Null; " +
		"Clear-DnsClientCache"
	if err := runPowerShell(ctx, script); err != nil {
		r.cleanup(iface, bind)
		return err
	}

	stop := make(chan struct{})
	r.mu.Lock()
	r.iface, r.stop, r.bind = iface, stop, bind
	r.mu.Unlock()
	go func() {
		// Follow network changes (Wi-Fi to cable, VPN off) and re-bind.
		t := time.NewTicker(rebindEvery)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_ = bindToDefault(bind, tunIdx)
			}
		}
	}()
	return nil
}

func (r *windowsExitRouter) Disable() error {
	r.mu.Lock()
	iface, stop, bind := r.iface, r.stop, r.bind
	r.iface, r.stop, r.bind = "", nil, nil
	r.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if iface == "" {
		return nil
	}
	r.cleanup(iface, bind)
	return nil
}

func (r *windowsExitRouter) cleanup(iface string, bind conn.Bind) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, p := range splitRoutes4 {
		_ = run(ctx, "netsh", "interface", "ipv4", "delete", "route", "prefix="+p, "interface="+iface)
	}
	for _, p := range splitRoutes6 {
		_ = run(ctx, "netsh", "interface", "ipv6", "delete", "route", "prefix="+p, "interface="+iface)
	}
	_ = runPowerShell(ctx, "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '"+exitNRPTComment+"' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }; Clear-DnsClientCache")
	if b, ok := bind.(conn.BindSocketToInterface); ok {
		_ = b.BindSocketToInterface4(0, false)
		_ = b.BindSocketToInterface6(0, false)
	}
}

func interfaceIndex(name string) uint32 {
	ifi, err := net.InterfaceByName(name)
	if err != nil || ifi.Index < 0 {
		return 0
	}
	return uint32(ifi.Index)
}

// bindToDefault binds WireGuard's sockets to the interface of the best
// default route that is not the tunnel itself.
func bindToDefault(bind conn.Bind, tunIdx uint32) error {
	b, ok := bind.(conn.BindSocketToInterface)
	if !ok {
		return errors.New("WireGuard soketleri ağ kartına bağlanamıyor")
	}
	v4 := defaultInterface(windows.AF_INET, tunIdx)
	if v4 == 0 {
		return errors.New("internet bağlantısı olan bir ağ kartı bulunamadı")
	}
	if err := b.BindSocketToInterface4(v4, false); err != nil {
		return err
	}
	v6 := defaultInterface(windows.AF_INET6, tunIdx)
	// No IPv6 default route: drop IPv6 sends instead of routing them
	// into the tunnel.
	return b.BindSocketToInterface6(v6, v6 == 0)
}

func defaultInterface(family uint16, exclude uint32) uint32 {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(family, &table); err != nil || table == nil {
		return 0
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	best, bestMetric := uint32(0), ^uint32(0)
	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength != 0 || row.InterfaceIndex == exclude {
			continue
		}
		if row.Metric < bestMetric {
			best, bestMetric = row.InterfaceIndex, row.Metric
		}
	}
	return best
}

// EnableExitNAT: a Windows computer cannot be an exit node yet.
func EnableExitNAT(context.Context, ExitNAT) error { return ErrExitUnsupported }

// DisableExitNAT is a no-op on Windows.
func DisableExitNAT(context.Context) error { return nil }
