// Package offlinetest checks the zero-telemetry promise (#35, ADR-0008) at
// run time: "no component connects to an address the owner did not
// configure". tools/telemetrycheck proves that no outside address is built
// into the program; the tests here start the service and the panel with
// every connection to a non-loopback address refused and recorded.
//
// Two layers:
//
//   - in process, Guard routes net.DefaultResolver and http.DefaultTransport
//     through a dialer that refuses non-loopback addresses and records each
//     attempt (code that builds its own dialer is not covered);
//   - around the process, scripts/offline-tests.sh runs the tests in a
//     Linux network namespace that has only a loopback interface, so any
//     other connection fails whatever dialer it uses. Isolated reports that
//     mode, and the tests then require it (CheckIsolated).
//
// It is test support only; the product does not import it.
package offlinetest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// IsolatedEnv is set to "1" by scripts/offline-tests.sh inside the network
// namespace.
const IsolatedEnv = "OPENSCALE_OFFLINE"

// ErrBlocked is returned for a refused connection.
var ErrBlocked = errors.New("offlinetest: connection to a non-loopback address refused")

// maxAttempts bounds the recorded attempts.
const maxAttempts = 256

// Allowed reports whether a dial to address (host:port or a bare host)
// stays on this computer: a loopback IP, "localhost", or a Unix socket
// path.
func Allowed(network, address string) bool {
	if strings.HasPrefix(network, "unix") {
		return true
	}
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return a.Unmap().IsLoopback()
}

// Guard refuses and records connections that leave the computer.
type Guard struct {
	mu       sync.Mutex
	attempts []string

	prevResolver  *net.Resolver
	prevTransport http.RoundTripper
	installed     bool
}

// New returns a guard that is not installed; its Dialer still refuses.
func New() *Guard { return &Guard{} }

// Control is a net.Dialer Control hook: it runs with the resolved address
// before every connect and refuses the non-loopback ones.
func (g *Guard) Control(network, address string, _ syscall.RawConn) error {
	if Allowed(network, address) {
		return nil
	}
	g.mu.Lock()
	if len(g.attempts) < maxAttempts {
		g.attempts = append(g.attempts, network+" "+address)
	}
	g.mu.Unlock()
	return fmt.Errorf("%w: %s %s", ErrBlocked, network, address)
}

// Dialer returns a dialer with the guard's Control hook.
func (g *Guard) Dialer() *net.Dialer {
	return &net.Dialer{Timeout: 5 * time.Second, Control: g.Control}
}

// Install routes net.DefaultResolver and http.DefaultTransport through the
// guard until Restore. Not safe while other goroutines change them; tests
// using it must not run in parallel with tests that use the network.
func Install() *Guard {
	g := New()
	d := g.Dialer()
	g.prevResolver = net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, network, address)
	}}
	g.prevTransport = http.DefaultTransport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		tr := base.Clone()
		tr.DialContext = d.DialContext
		tr.Proxy = nil // a proxy from the environment is an outside address too
		http.DefaultTransport = tr
	}
	g.installed = true
	return g
}

// Restore puts back what Install replaced.
func (g *Guard) Restore() {
	if !g.installed {
		return
	}
	net.DefaultResolver = g.prevResolver
	http.DefaultTransport = g.prevTransport
	g.installed = false
}

// Attempts returns the refused connections so far.
func (g *Guard) Attempts() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.attempts)
}

// Reset forgets the recorded attempts.
func (g *Guard) Reset() {
	g.mu.Lock()
	g.attempts = nil
	g.mu.Unlock()
}

// Isolated reports whether the tests run inside the offline namespace.
func Isolated() bool { return os.Getenv(IsolatedEnv) == "1" }

// CheckIsolated returns an error when an interface that is up has an
// address other than loopback: the namespace would not be isolated.
func CheckIsolated() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	var outside []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			return err
		}
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil || !p.Addr().IsLoopback() {
				outside = append(outside, ifc.Name+" "+a.String())
			}
		}
	}
	if len(outside) > 0 {
		return fmt.Errorf("offlinetest: not isolated, interfaces with outside addresses: %s", strings.Join(outside, ", "))
	}
	return nil
}
