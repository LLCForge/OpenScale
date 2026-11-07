package node

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
)

// Static endpoints given by DNS name (#387). The owner may name this
// device's fixed address with a dynamic DNS name ("home.example.net:51820")
// instead of an IP. The name is resolved locally and periodically; the
// resulting addresses are reported to the coordinator as candidates exactly
// like IP static endpoints (F-012). Nothing in the signed document changes:
// peers still receive plain addresses.
const (
	// staticNameRefresh is how often names are resolved again.
	staticNameRefresh = 5 * time.Minute
	// staticNameRetry is the wait after a failed resolution.
	staticNameRetry = 30 * time.Second
	// staticNameTimeout bounds one resolution.
	staticNameTimeout = 5 * time.Second
	// maxStaticNameAddrs bounds the addresses taken from one name.
	maxStaticNameAddrs = 2
	maxDNSNameLen      = 253
)

// ValidStaticEndpointName checks "name:port" for a static endpoint name: a
// DNS name (letters, digits, hyphens and dots, labels of 1-63 characters,
// not all digits) and a port from 1 to 65535. IP literals are refused (they
// belong in StaticEndpoints).
func ValidStaticEndpointName(s string) (host string, port uint16, err error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("statik uç nokta %q ad:port biçiminde olmalı", s)
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return "", 0, fmt.Errorf("statik uç nokta %q: port 1-65535 olmalı", s)
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if _, err := netip.ParseAddr(h); err == nil {
		return "", 0, fmt.Errorf("statik uç nokta %q bir ad değil", s)
	}
	if !validDNSName(h) {
		return "", 0, fmt.Errorf("statik uç nokta adı %q geçersiz", h)
	}
	return h, uint16(n), nil
}

func validDNSName(h string) bool {
	if h == "" || len(h) > maxDNSNameLen || h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false // a single label resolves through search domains
	}
	allDigits := true
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c == '-':
				allDigits = false
			case c >= '0' && c <= '9':
			default:
				return false
			}
		}
	}
	return !allDigits
}

// usableStaticAddr is the same check as for IP static endpoints.
func usableStaticAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && a.Zone() == "" && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast()
}

// checkStaticNames is called by New.
func checkStaticNames(names []string, ips int) error {
	if len(names)+ips > control.MaxCandidates {
		return fmt.Errorf("en fazla %d statik uç nokta tanımlanabilir", control.MaxCandidates)
	}
	for _, s := range names {
		if _, _, err := ValidStaticEndpointName(s); err != nil {
			return err
		}
	}
	return nil
}

type staticName struct {
	host string
	port uint16
}

// staticNames resolves the names in the background and keeps the result.
type staticNames struct {
	names   []staticName
	resolve func(context.Context, string) ([]netip.Addr, error)
	now     func() time.Time
	logger  *slog.Logger

	mu        sync.Mutex
	addrs     []netip.AddrPort
	nextAt    time.Time
	resolving bool
}

func newStaticNames(in []string, resolve func(context.Context, string) ([]netip.Addr, error), now func() time.Time, logger *slog.Logger) *staticNames {
	s := &staticNames{resolve: resolve, now: now, logger: logger}
	for _, v := range in {
		if h, p, err := ValidStaticEndpointName(v); err == nil {
			s.names = append(s.names, staticName{host: h, port: p})
		}
	}
	return s
}

// current returns the last resolved addresses and starts a resolution in
// the background when they are due. It never blocks on DNS.
func (s *staticNames) current() []netip.AddrPort {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.resolving && !s.now().Before(s.nextAt) {
		s.resolving = true
		go s.refresh()
	}
	return slices.Clone(s.addrs)
}

// invalidate resolves again at the next use (network change).
func (s *staticNames) invalidate() {
	s.mu.Lock()
	s.nextAt = time.Time{}
	s.mu.Unlock()
}

func (s *staticNames) refresh() {
	addrs, failed := s.lookup()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resolving = false
	if failed && len(addrs) == 0 {
		// Keep the previous addresses: a DNS hiccup must not hide the device.
		s.nextAt = s.now().Add(staticNameRetry)
		return
	}
	s.addrs = addrs
	s.nextAt = s.now().Add(staticNameRefresh)
}

// lookup resolves every name; failed reports whether any name failed.
func (s *staticNames) lookup() ([]netip.AddrPort, bool) {
	var out []netip.AddrPort
	failed := false
	for _, n := range s.names {
		ctx, cancel := context.WithTimeout(context.Background(), staticNameTimeout)
		addrs, err := s.resolve(ctx, n.host)
		cancel()
		if err != nil {
			failed = true
			s.logger.Debug("static endpoint name", "name", n.host, "error", err.Error())
			continue
		}
		taken := 0
		for _, a := range addrs {
			a = a.Unmap()
			if taken >= maxStaticNameAddrs || !usableStaticAddr(a) {
				continue
			}
			ap := netip.AddrPortFrom(a, n.port)
			if !slices.Contains(out, ap) {
				out = append(out, ap)
				taken++
			}
		}
	}
	return out, failed
}
