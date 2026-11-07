package netwatch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"syscall"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Open port audit (#731). The exit node connects, from outside the home
// network, to the public address that one of the owner's own devices
// reported to the coordinator, on the ports the owner approved, and tells
// which ones answer. It is a TCP connect check: no banner is read and no
// data is sent. Only addresses taken from the owner's own devices'
// reports are ever audited, at a bounded rate.

// Audit limits.
const (
	MaxAuditPorts    = 64
	MaxAuditTargets  = 64
	MinAuditInterval = 6 * time.Hour
	defaultAuditGap  = 200 * time.Millisecond
	defaultAuditDial = 3 * time.Second
	maxAuditDial     = 10 * time.Second
	maxAuditGap      = 5 * time.Second
	minAuditGap      = 50 * time.Millisecond
)

// DefaultAuditPorts is a suggestion the owner confirms: remote login,
// file sharing, databases, web panels and smart home hubs that should
// rarely face the internet.
var DefaultAuditPorts = []uint16{21, 22, 23, 80, 443, 445, 3389, 5900, 8080, 8123, 1883, 3306, 5432, 6379, 9200, 27017}

// AuditTarget is one of the owner's devices and the public address it
// reported.
type AuditTarget struct {
	Device string
	Addr   netip.Addr
}

// AuditFinding is one open port.
type AuditFinding struct {
	Device string     `json:"device"`
	Addr   netip.Addr `json:"addr"`
	Port   uint16     `json:"port"`
}

// AuditConfig configures an audit.
type AuditConfig struct {
	// Ports are the owner-approved ports.
	Ports []uint16
	// Gap is the pause between two connection attempts (rate limit).
	Gap time.Duration
	// DialTimeout bounds one attempt.
	DialTimeout time.Duration
	// allowLoopback lets tests audit 127.0.0.1.
	allowLoopback bool
}

// Errors of the audit.
var (
	ErrAuditAddr  = errors.New("denetlenecek adres cihazın bildirdiği genel bir adres olmalı")
	ErrAuditPorts = fmt.Errorf("denetim için 1-%d onaylı port gerekli", MaxAuditPorts)
)

// Validate checks the configuration.
func (c AuditConfig) Validate() error {
	if len(c.Ports) == 0 || len(c.Ports) > MaxAuditPorts || slices.Contains(c.Ports, 0) {
		return ErrAuditPorts
	}
	if c.Gap != 0 && (c.Gap < minAuditGap || c.Gap > maxAuditGap) {
		return fmt.Errorf("denetim aralığı %s ile %s arasında olmalı", minAuditGap, maxAuditGap)
	}
	if c.DialTimeout < 0 || c.DialTimeout > maxAuditDial {
		return fmt.Errorf("bağlantı zaman aşımı en fazla %s olmalı", maxAuditDial)
	}
	return nil
}

// publicUnicast accepts only global unicast addresses outside private,
// shared (CGNAT), loopback, link-local and documentation ranges.
func publicUnicast(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.Zone() != "" {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// TargetsFromReports builds audit targets from the public addresses that
// devices reported (sysinfo.Info.PublicIP, keyed by device name). Names
// that are not devices of the signed document, and addresses that are not
// public, are left out: the audit can never be pointed at someone else.
func TargetsFromReports(doc *trust.Document, publicIP map[string]string) []AuditTarget {
	if doc == nil {
		return nil
	}
	seen := map[netip.Addr]bool{}
	var out []AuditTarget
	names := make([]string, 0, len(publicIP))
	for n := range publicIP {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, ok := doc.DeviceByName(n); !ok {
			continue
		}
		a, err := netip.ParseAddr(publicIP[n])
		if err != nil || !publicUnicast(a) || seen[a.Unmap()] {
			continue
		}
		seen[a.Unmap()] = true
		out = append(out, AuditTarget{Device: n, Addr: a.Unmap()})
		if len(out) >= MaxAuditTargets {
			break
		}
	}
	return out
}

// Audit connects to every target and approved port, one attempt at a
// time with a pause between them, and returns the open ports.
func Audit(ctx context.Context, cfg AuditConfig, targets []AuditTarget) ([]AuditFinding, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(targets) > MaxAuditTargets {
		return nil, fmt.Errorf("en fazla %d cihaz denetlenebilir", MaxAuditTargets)
	}
	for _, t := range targets {
		if !(cfg.allowLoopback && t.Addr.IsLoopback()) && !publicUnicast(t.Addr) {
			return nil, fmt.Errorf("%s: %w", t.Device, ErrAuditAddr)
		}
	}
	gap := cfg.Gap
	if gap == 0 {
		gap = defaultAuditGap
	}
	dt := cfg.DialTimeout
	if dt == 0 {
		dt = defaultAuditDial
	}
	ports := slices.Clone(cfg.Ports)
	slices.Sort(ports)
	ports = slices.Compact(ports)
	allowLoop := cfg.allowLoopback
	dialer := net.Dialer{
		Timeout: dt,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !(publicUnicast(ap.Addr()) || (allowLoop && ap.Addr().IsLoopback())) {
				return ErrAuditAddr
			}
			return nil
		},
	}
	var out []AuditFinding
	first := true
	for _, t := range targets {
		for _, p := range ports {
			if !first {
				timer := time.NewTimer(gap)
				select {
				case <-ctx.Done():
					timer.Stop()
					return out, ctx.Err()
				case <-timer.C:
				}
			}
			first = false
			c, err := dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(t.Addr, p).String())
			if err != nil {
				if ctx.Err() != nil {
					return out, ctx.Err()
				}
				continue
			}
			_ = c.Close()
			out = append(out, AuditFinding{Device: t.Device, Addr: t.Addr, Port: p})
		}
	}
	return out, nil
}

// AuditDiff compares two audits: ports that opened and ports that closed
// since the previous one. Findings are matched by device and port.
func AuditDiff(prev, cur []AuditFinding) (opened, closed []AuditFinding) {
	key := func(f AuditFinding) string { return fmt.Sprintf("%s|%d", f.Device, f.Port) }
	old := map[string]bool{}
	for _, f := range prev {
		old[key(f)] = true
	}
	now := map[string]bool{}
	for _, f := range cur {
		now[key(f)] = true
		if !old[key(f)] {
			opened = append(opened, f)
		}
	}
	for _, f := range prev {
		if !now[key(f)] {
			closed = append(closed, f)
		}
	}
	return opened, closed
}

// AuditDue reports whether an audit may run at now after the last one;
// the owner cannot schedule audits closer than MinAuditInterval.
func AuditDue(last, now time.Time, every time.Duration) bool {
	if every < MinAuditInterval {
		every = MinAuditInterval
	}
	return last.IsZero() || now.Sub(last) >= every
}
