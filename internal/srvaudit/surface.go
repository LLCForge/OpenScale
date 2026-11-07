package srvaudit

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
)

// External surface check (#479). A member device probes the coordinator's
// public address from outside the tunnel: the WireGuard UDP port must
// answer OpenScale's who-am-I echo (so it is open and it is ours), must
// stay silent to packets it does not recognise, and no other TCP port
// should accept connections. Only the address the owner configured is
// contacted.

// DefaultSurfaceTCP are the TCP ports tried by default: remote login,
// mail, web, databases and remote desktop that are often left open.
var DefaultSurfaceTCP = []uint16{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090}

// SurfaceOptions configures Probe.
type SurfaceOptions struct {
	// Endpoint is host:port of the coordinator's WireGuard UDP port.
	Endpoint string
	// TCPPorts are tried for TCP connections (nil: DefaultSurfaceTCP).
	TCPPorts []uint16
	// AllowTCP are open TCP ports the owner expects (SSH, the TCP
	// transport).
	AllowTCP []uint16
	// Timeout bounds each answer (zero: 2 s).
	Timeout time.Duration
	// Lookup resolves the host; nil uses the system resolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

// SurfaceResult is the outcome of Probe.
type SurfaceResult struct {
	Schema     int       `json:"schema"`
	Endpoint   string    `json:"endpoint"`
	Address    string    `json:"address"`
	SeenAs     string    `json:"seen_as,omitempty"`
	OpenTCP    []uint16  `json:"open_tcp"`
	Unexpected []uint16  `json:"unexpected_tcp"`
	Checks     []Check   `json:"checks"`
	Score      int       `json:"score"`
	At         time.Time `json:"at"`
	Elapsed    float64   `json:"elapsed_s"`
}

const (
	surfaceTries   = 3
	surfaceWorkers = 8
	maxSurfacePort = 64
)

// Probe runs the external surface check.
func Probe(ctx context.Context, o SurfaceOptions) (SurfaceResult, error) {
	start := time.Now()
	host, portText, err := net.SplitHostPort(strings.TrimSpace(o.Endpoint))
	if err != nil || host == "" {
		return SurfaceResult{}, errors.New("adres host:port biçiminde olmalı")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return SurfaceResult{}, errors.New("port 1-65535 olmalı")
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.TCPPorts == nil {
		o.TCPPorts = DefaultSurfaceTCP
	}
	if len(o.TCPPorts) > maxSurfacePort {
		return SurfaceResult{}, fmt.Errorf("en fazla %d TCP portu denenir", maxSurfacePort)
	}
	addr, err := resolve(ctx, host, o.Lookup)
	if err != nil {
		return SurfaceResult{}, err
	}
	target := netip.AddrPortFrom(addr, uint16(port))
	res := SurfaceResult{Schema: 1, Endpoint: o.Endpoint, Address: target.String(), OpenTCP: []uint16{}, Unexpected: []uint16{}}

	open := Check{ID: "udp-open", Title: "WireGuard UDP portu açık", Weight: 40}
	if seen, ok := whoAmI(ctx, target, o.Timeout); ok {
		open.Status, open.Detail = Pass, "Port yanıt veriyor; koordinatör bu cihazı "+seen.String()+" olarak görüyor."
		res.SeenAs = seen.String()
	} else {
		open.Status = Fail
		open.Detail = "Who-am-I yanıtı gelmedi: port kapalı, güvenlik duvarı engelliyor veya adres yanlış."
		open.Fix = "Sunucuda koordinatörün çalıştığını ve güvenlik duvarında UDP " + portText + " portunun açık olduğunu denetleyin."
	}
	silent := Check{ID: "udp-silent", Title: "Tanınmayan paketlere sessizlik", Weight: 30}
	if n := junkReplies(ctx, target, o.Timeout); n == 0 {
		silent.Status, silent.Detail = Pass, "Geçersiz paketlere yanıt verilmedi."
	} else {
		silent.Status = Fail
		silent.Detail = fmt.Sprintf("Geçersiz paketlere %d yanıt geldi; bu portta WireGuard'dan başka bir şey dinliyor olabilir.", n)
		silent.Fix = "Portu başka bir servisin kullanmadığını ve önünde bir yansıtıcı olmadığını denetleyin."
	}
	res.OpenTCP = openTCP(ctx, addr, o.TCPPorts, o.Timeout)
	for _, p := range res.OpenTCP {
		if !slices.Contains(o.AllowTCP, p) {
			res.Unexpected = append(res.Unexpected, p)
		}
	}
	tcp := Check{ID: "tcp", Title: "Beklenmeyen TCP portları", Weight: 30}
	switch {
	case len(res.Unexpected) == 0:
		tcp.Status, tcp.Detail = Pass, fmt.Sprintf("%d TCP portu denendi; beklenmeyen açık port yok.", len(o.TCPPorts))
	default:
		tcp.Status = Warn
		if len(res.Unexpected) > 2 {
			tcp.Status = Fail
		}
		tcp.Detail = "Dışarıdan açık TCP portları: " + joinPorts(res.Unexpected)
		tcp.Fix = "Gerekmeyen servisleri kapatın veya güvenlik duvarında engelleyin; beklenen portları --allow-tcp ile belirtin."
	}
	res.Checks = []Check{open, silent, tcp}
	res.Score = score(res.Checks)
	res.At = time.Now().UTC()
	res.Elapsed = time.Since(start).Seconds()
	return res, nil
}

func joinPorts(ps []uint16) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = strconv.Itoa(int(p))
	}
	return strings.Join(s, ", ")
}

func resolve(ctx context.Context, host string, lookup func(context.Context, string) ([]netip.Addr, error)) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), nil
	}
	if lookup == nil {
		lookup = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		}
	}
	addrs, err := lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("%s çözümlenemedi", host)
	}
	// Prefer IPv4: it is what most devices use to reach the coordinator.
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	return addrs[0], nil
}

// whoAmI sends the who-am-I echo up to surfaceTries times.
func whoAmI(ctx context.Context, target netip.AddrPort, timeout time.Duration) (netip.AddrPort, bool) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return netip.AddrPort{}, false
	}
	defer c.Close()
	var nonce [control.WhoAmINonce]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return netip.AddrPort{}, false
	}
	buf := make([]byte, 512)
	for i := 0; i < surfaceTries && ctx.Err() == nil; i++ {
		if _, err := c.Write(control.NewWhoAmIRequest(nonce)); err != nil {
			return netip.AddrPort{}, false
		}
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		for {
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			if seen, ok := control.ParseWhoAmIReply(buf[:n], nonce); ok {
				return seen, true
			}
		}
	}
	return netip.AddrPort{}, false
}

// junkReplies sends packets WireGuard must ignore (a handshake initiation
// with invalid MACs, random bytes, a text request) and counts replies.
func junkReplies(ctx context.Context, target netip.AddrPort, timeout time.Duration) int {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return 0
	}
	defer c.Close()
	init := make([]byte, 148)
	small := make([]byte, 32)
	if _, err := rand.Read(init); err != nil {
		return 0
	}
	if _, err := rand.Read(small); err != nil {
		return 0
	}
	init[0], init[1], init[2], init[3] = 1, 0, 0, 0
	small[0] = 0xff
	for _, p := range [][]byte{init, small, []byte("GET / HTTP/1.0\r\n\r\n")} {
		if ctx.Err() != nil {
			return 0
		}
		if _, err := c.Write(p); err != nil {
			return 0
		}
	}
	replies := 0
	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	for {
		if _, err := c.Read(buf); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return replies
			}
			// An ICMP "port unreachable" shows up as a read error: no reply.
			return replies
		}
		replies++
	}
}

// openTCP returns the ports that accept a TCP connection, sorted.
func openTCP(ctx context.Context, addr netip.Addr, ports []uint16, timeout time.Duration) []uint16 {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		open = []uint16{}
		jobs = make(chan uint16)
	)
	d := net.Dialer{Timeout: timeout}
	for range surfaceWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, p).String())
				if err != nil {
					continue
				}
				_ = conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}()
	}
	for _, p := range ports {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	slices.Sort(open)
	return slices.Compact(open)
}
