//go:build linux

package osnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"text/template"
)

const torTable = "openscale_tor"

// Members' internet TCP is redirected to Tor's TransPort (a local socket on
// this exit node's OpenScale address); every other member packet bound for
// the internet (UDP, ICMP, all IPv6) is dropped in forward, which also
// catches connections forwarded before the Tor exit was turned on. Only
// redirected connections may reach TransPort: Tor must not become a proxy
// for anyone who can reach this host. The exit node's own traffic never
// matches (only packets arriving on the OpenScale interface do).
var torRules = template.Must(template.New("tor").Parse(`table inet {{.Table}}
delete table inet {{.Table}}
table inet {{.Table}} {
	chain prerouting {
		type nat hook prerouting priority dstnat - 5; policy accept;
		iifname "{{.Overlay}}" ip saddr {{.V4}} ip daddr != { {{.Blocked4}} } meta l4proto tcp redirect to :{{.TransPort}}
	}
	chain forward {
		type filter hook forward priority filter - 15; policy accept;
		iifname "{{.Overlay}}" ip saddr {{.V4}} ip daddr != { {{.Blocked4}} } drop
		iifname "{{.Overlay}}" ip6 saddr {{.V6}} ip6 daddr != { {{.Blocked6}} } drop
	}
	chain input {
		type filter hook input priority filter - 5; policy accept;
		iifname != "lo" tcp dport {{.TransPort}} ct status dnat accept
		iifname != "lo" tcp dport {{.TransPort}} drop
	}
}
`))

// TorRouter installs the packet filter of a Tor exit on a Linux exit node.
type TorRouter struct {
	ops sysOps

	mu        sync.Mutex
	installed bool
}

// NewTorRouter returns the router for this host.
func NewTorRouter() *TorRouter { return &TorRouter{ops: hostOps} }

// TorSupported reports whether this OS can be a Tor exit.
func TorSupported() bool { return true }

// Apply installs or replaces the Tor exit filter in one nft transaction.
func (t *TorRouter) Apply(ctx context.Context, r TorRoute) error {
	if err := r.validate(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ops.has("nft") {
		return errors.New("Tor çıkışı için nft (nftables) gerekli")
	}
	script, err := torScript(r)
	if err != nil {
		return err
	}
	if _, err := t.ops.run(ctx, script, "nft", "-f", "-"); err != nil {
		return err
	}
	t.installed = true
	return nil
}

// Remove deletes the Tor exit filter.
func (t *TorRouter) Remove(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	removeTorTable(ctx, t.ops)
	t.installed = false
	return nil
}

// Probe reads the socket tables; it opens no connection, so it never
// makes Tor build a circuit.
func (t *TorRouter) Probe(r TorRoute) TorHealth {
	var tcp, udp []procSocket
	var errs []error
	for _, f := range []struct {
		path string
		into *[]procSocket
	}{{"/proc/net/tcp", &tcp}, {"/proc/net/tcp6", &tcp}, {"/proc/net/udp", &udp}, {"/proc/net/udp6", &udp}} {
		data, err := t.ops.read(f.path)
		if err != nil {
			// tcp6/udp6 are absent without IPv6.
			if !strings.HasSuffix(f.path, "6") {
				errs = append(errs, err)
			}
			continue
		}
		*f.into = append(*f.into, parseProcNet(data)...)
	}
	h := torHealthFrom(r, tcp, udp)
	h.Err = errors.Join(errs...)
	return h
}

func removeTorTable(ctx context.Context, o sysOps) {
	if o.has("nft") {
		_, _ = o.run(ctx, nil, "nft", "delete", "table", "inet", torTable)
	}
}

func torScript(r TorRoute) ([]byte, error) {
	var b bytes.Buffer
	err := torRules.Execute(&b, map[string]any{
		"Table": torTable, "Overlay": r.Overlay,
		"V4": r.OverlayV4.Masked().String(), "V6": r.OverlayV6.Masked().String(),
		"Blocked4": strings.Join(exitBlocked4, ", "), "Blocked6": strings.Join(exitBlocked6, ", "),
		"TransPort": r.TransPort,
	})
	if err != nil {
		return nil, fmt.Errorf("Tor çıkışı kuralları üretilemedi: %w", err)
	}
	return b.Bytes(), nil
}

func (r TorRoute) validate() error {
	if !validSysctlName(r.Overlay) {
		return errors.New("geçersiz OpenScale arayüz adı")
	}
	if !r.OverlayV4.IsValid() || !r.OverlayV4.Addr().Is4() || !r.OverlayV6.IsValid() || !r.OverlayV6.Addr().Is6() {
		return errors.New("geçersiz ağ aralıkları")
	}
	if r.TransPort == 0 || r.DNSPort == 0 || r.TransPort == r.DNSPort {
		return errors.New("geçersiz Tor portları")
	}
	return nil
}
