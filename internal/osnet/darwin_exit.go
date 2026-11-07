package osnet

// Using an exit node on macOS (ADR-0100, ADR-0018). Internet traffic goes
// into the tunnel through two split routes per family, which are more
// specific than the real default route, so that route is never touched.
// WireGuard's own UDP sockets are bound to the physical interface
// (IP_BOUND_IF, set through the bind's mark; node/mark_darwin.go), so its
// packets never loop into the tunnel. DNS of every network service points
// at the exit node through networksetup; the previous servers are saved
// first and restored on Disable and by crash recovery (ADR-0051).
// Untagged so the tests run on every platform; exit_darwin.go wires it.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/trust"
)

const (
	darwinExitDNSFile   = "exit-dns.json"
	maxDarwinExitDNS    = 64 << 10
	maxDarwinServices   = 64
	darwinRebindEvery   = 5 * time.Second
	darwinExitOpTimeout = 60 * time.Second
)

// darwinSplitRoutes cover the whole internet while staying more specific
// than the default route.
var (
	darwinSplitRoutes4 = []string{"0.0.0.0/1", "128.0.0.0/1"}
	darwinSplitRoutes6 = []string{"::/1", "8000::/1"}
)

// darwinServiceDNS is one network service's DNS servers before OpenScale
// changed them; empty means "from DHCP" (networksetup's "Empty").
type darwinServiceDNS struct {
	Service string   `json:"service"`
	Servers []string `json:"servers,omitempty"`
}

type darwinExitDNSState struct {
	Interface string             `json:"interface"`
	Services  []darwinServiceDNS `json:"services"`
}

// darwinExit is the macOS exit router; tests replace every system call.
type darwinExit struct {
	run      darwinRunner
	stateDir string
	write    func(path string, data []byte) error
	read     func(path string, limit int64) ([]byte, error)
	remove   func(path string) error
	ifIndex  func(name string) (int, error)
	every    time.Duration

	mu    sync.Mutex
	iface string
	stop  chan struct{}
	done  chan struct{}
	bind  conn.Bind
}

func (r *darwinExit) statePath() string { return r.stateDir + "/" + darwinExitDNSFile }

// validServiceName accepts what networksetup prints as a service name;
// it is passed as one argument, never through a shell.
func validServiceName(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// parseNetworkServices reads `networksetup -listallnetworkservices`. The
// first line is a note; disabled services start with "*" and are left
// alone.
func parseNetworkServices(out []byte) []string {
	var services []string
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "*") || strings.Contains(line, "asterisk") {
			continue
		}
		if validServiceName(line) && len(services) < maxDarwinServices {
			services = append(services, line)
		}
	}
	return services
}

// parseDNSServers reads `networksetup -getdnsservers <service>`: one
// address per line, or a sentence when none is set by hand.
func parseDNSServers(out []byte) []string {
	var servers []string
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		if a, err := netip.ParseAddr(strings.TrimSpace(s.Text())); err == nil {
			servers = append(servers, a.String())
		}
	}
	return servers
}

// bindPhysical binds WireGuard's sockets to the interface of the physical
// default route and returns its index.
func (r *darwinExit) bindPhysical(ctx context.Context, bind conn.Bind) (int, error) {
	if bind == nil {
		return 0, errors.New("WireGuard soketleri ağ arayüzüne bağlanamıyor")
	}
	routes, err := defaultRoutesDarwin(ctx, r.run)
	if err != nil {
		return 0, err
	}
	def, ok := darwinPhysicalDefault(routes)
	if !ok {
		return 0, errors.New("internet bağlantısı olan bir ağ arayüzü bulunamadı")
	}
	idx, err := r.ifIndex(def.Netif)
	if err != nil || idx <= 0 {
		return 0, fmt.Errorf("%s arayüzünün sırası okunamadı: %v", def.Netif, err)
	}
	if err := bind.SetMark(uint32(idx)); err != nil { //nolint:gosec // an interface index
		return 0, fmt.Errorf("WireGuard soketleri %s arayüzüne bağlanamadı: %w", def.Netif, err)
	}
	return idx, nil
}

func (r *darwinExit) Enable(exit trust.Device, _ *trust.Document, iface string, bind conn.Bind) error {
	if !validDarwinIface(iface) {
		return fmt.Errorf("geçersiz tünel arayüzü %q", iface)
	}
	if !exit.IPv4.Is4() {
		return errors.New("çıkış düğümünün IPv4 adresi yok")
	}
	_ = r.Disable()
	ctx, cancel := context.WithTimeout(context.Background(), darwinExitOpTimeout)
	defer cancel()
	// DNS left by a crashed run goes back first, so its saved servers
	// are not overwritten with the exit node's address.
	if err := r.restoreDNS(ctx); err != nil {
		return fmt.Errorf("önceki çalışmanın DNS ayarları geri alınamadı: %w", err)
	}
	idx, err := r.bindPhysical(ctx, bind)
	if err != nil {
		return err
	}
	for _, p := range darwinSplitRoutes4 {
		out, err := r.run(ctx, nil, darwinRoute, "-q", "-n", "add", "-inet", p, "-interface", iface)
		if err != nil && !routeExists(out) {
			_ = r.cleanup(ctx, iface, bind)
			return err
		}
	}
	for _, p := range darwinSplitRoutes6 {
		// IPv6 without an IPv6 exit simply goes nowhere: no leak.
		_, _ = r.run(ctx, nil, darwinRoute, "-q", "-n", "add", "-inet6", p, "-interface", iface)
	}
	if err := r.pointDNS(ctx, iface, exit.IPv4); err != nil {
		_ = r.cleanup(ctx, iface, bind)
		return err
	}
	stop, done := make(chan struct{}), make(chan struct{})
	r.mu.Lock()
	r.iface, r.stop, r.done, r.bind = iface, stop, done, bind
	r.mu.Unlock()
	go r.follow(stop, done, bind, idx)
	return nil
}

// follow re-binds WireGuard's sockets when the physical network changes
// (Wi-Fi to cable, a VPN of another vendor going away).
func (r *darwinExit) follow(stop, done chan struct{}, bind conn.Bind, idx int) {
	defer close(done)
	every := r.every
	if every <= 0 {
		every = darwinRebindEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
			routes, err := defaultRoutesDarwin(ctx, r.run)
			cancel()
			if err != nil {
				continue
			}
			def, ok := darwinPhysicalDefault(routes)
			if !ok {
				continue
			}
			if next, err := r.ifIndex(def.Netif); err == nil && next > 0 && next != idx {
				if bind.SetMark(uint32(next)) == nil { //nolint:gosec // an interface index
					idx = next
				}
			}
		}
	}
}

// pointDNS saves every enabled service's DNS servers, then sets them to
// the exit node's address.
func (r *darwinExit) pointDNS(ctx context.Context, iface string, server netip.Addr) error {
	out, err := r.run(ctx, nil, darwinNetworksetup, "-listallnetworkservices")
	if err != nil {
		return err
	}
	st := darwinExitDNSState{Interface: iface}
	for _, svc := range parseNetworkServices(out) {
		cur, err := r.run(ctx, nil, darwinNetworksetup, "-getdnsservers", svc)
		if err != nil {
			continue // a service that cannot be read is not changed either
		}
		st.Services = append(st.Services, darwinServiceDNS{Service: svc, Servers: parseDNSServers(cur)})
	}
	if len(st.Services) == 0 {
		return errors.New("DNS ayarlanacak bir ağ servisi bulunamadı")
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := r.write(r.statePath(), data); err != nil {
		return fmt.Errorf("önceki DNS ayarları kaydedilemedi: %w", err)
	}
	for _, s := range st.Services {
		if _, err := r.run(ctx, nil, darwinNetworksetup, "-setdnsservers", s.Service, server.String()); err != nil {
			return err
		}
	}
	return nil
}

// restoreDNS puts back the servers pointDNS saved and deletes the saved
// file once every service is restored. Nothing saved is not an error.
func (r *darwinExit) restoreDNS(ctx context.Context) error {
	data, err := r.read(r.statePath(), maxDarwinExitDNS)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st darwinExitDNSState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("kayıtlı DNS ayarları bozuk: %w", err)
	}
	var errs []error
	for _, s := range st.Services {
		if !validServiceName(s.Service) {
			continue
		}
		args := []string{"-setdnsservers", s.Service}
		var servers []string
		for _, v := range s.Servers {
			if a, err := netip.ParseAddr(v); err == nil {
				servers = append(servers, a.String())
			}
		}
		if len(servers) == 0 {
			args = append(args, "Empty")
		} else {
			args = append(args, servers...)
		}
		if _, err := r.run(ctx, nil, darwinNetworksetup, args...); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if err := r.remove(r.statePath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_, _ = r.run(ctx, nil, darwinDscacheutil, "-flushcache")
	_, _ = r.run(ctx, nil, darwinKillall, "-HUP", "mDNSResponder")
	return nil
}

// deleteRoutes removes the split routes of iface. Missing routes are
// fine: they vanish with the interface anyway.
func (r *darwinExit) deleteRoutes(ctx context.Context, iface string) {
	for _, p := range darwinSplitRoutes4 {
		_, _ = r.run(ctx, nil, darwinRoute, "-q", "-n", "delete", "-inet", p, "-interface", iface)
	}
	for _, p := range darwinSplitRoutes6 {
		_, _ = r.run(ctx, nil, darwinRoute, "-q", "-n", "delete", "-inet6", p, "-interface", iface)
	}
}

func (r *darwinExit) cleanup(ctx context.Context, iface string, bind conn.Bind) error {
	r.deleteRoutes(ctx, iface)
	err := r.restoreDNS(ctx)
	if bind != nil {
		_ = bind.SetMark(0)
	}
	return err
}

func (r *darwinExit) Disable() error {
	r.mu.Lock()
	iface, stop, done, bind := r.iface, r.stop, r.done, r.bind
	r.iface, r.stop, r.done, r.bind = "", nil, nil, nil
	r.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
	if iface == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), darwinExitOpTimeout)
	defer cancel()
	return r.cleanup(ctx, iface, bind)
}

// recoverClient undoes what a crashed run left (ADR-0051): the split
// routes of iface and the exit node DNS.
func (r *darwinExit) recoverClient(ctx context.Context, iface string) error {
	if validDarwinIface(iface) {
		r.deleteRoutes(ctx, iface)
	}
	return r.restoreDNS(ctx)
}
