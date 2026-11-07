// Package dnsguard holds the pure decision code of the device and exit
// node DNS hardening of ADR-0213:
//
//   - #717 DNS enforcement: the rule set that keeps every DNS query in the
//     tunnel (plain DNS and DNS over TLS/QUIC outside the tunnel and the
//     owner's DoH endpoints are dropped). The rules are data; applying
//     them with nftables or WFP is internal/osnet's job.
//   - #721 .onion names resolve only on a device whose Tor exit is on.
//   - #739 DNS rebinding filter for answers of outside names.
//   - #765 a TTL-respecting, size-bounded answer cache with negative
//     caching and popularity based prefetch candidates.
//
// Nothing here opens a socket or names an address (ADR-0008); the DoH
// endpoint list comes only from the owner's file.
package dnsguard

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// Enforcement limits.
const (
	MaxDoHFileSize  = 1 << 20
	MaxDoHEntries   = 4096
	maxInterfaceLen = 64
)

// Action is what a rule does.
type Action string

// Actions.
const (
	ActionAllow Action = "allow"
	ActionDrop  Action = "drop"
)

// Proto is a transport protocol.
type Proto string

// Protocols.
const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

// Rule is one outbound rule; rules are evaluated in order and the first
// match wins. An empty Interface matches every interface; NotInterface
// inverts it. An invalid Dst matches every destination.
type Rule struct {
	Action       Action       `json:"action"`
	Proto        Proto        `json:"proto"`
	Dst          netip.Prefix `json:"dst,omitzero"`
	Port         uint16       `json:"port"`
	Interface    string       `json:"interface,omitempty"`
	NotInterface bool         `json:"not_interface,omitempty"`
	Comment      string       `json:"comment"`
}

// DoHList is the owner's list of DNS over HTTPS endpoints: addresses are
// dropped on port 443 (TCP and UDP for HTTP/3); names are answered with
// NXDOMAIN by the tunnel resolver so browsers fall back to it.
type DoHList struct {
	Prefixes []netip.Prefix `json:"prefixes"`
	Names    []string       `json:"names"`
}

// ParseDoHList reads the owner's file: one address, prefix or host name
// per line, '#' comments. Unknown lines are an error, not guessed.
func ParseDoHList(r io.Reader) (DoHList, error) {
	var out DoHList
	sc := bufio.NewScanner(io.LimitReader(r, MaxDoHFileSize+1))
	sc.Buffer(make([]byte, 0, 4096), 4096)
	read, line := 0, 0
	seenP, seenN := map[netip.Prefix]bool{}, map[string]bool{}
	for sc.Scan() {
		line++
		read += len(sc.Bytes()) + 1
		if read > MaxDoHFileSize {
			return DoHList{}, errors.New("DoH listesi çok büyük")
		}
		s := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\xef\xbb\xbf"))
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		if s == "" {
			continue
		}
		if len(out.Prefixes)+len(out.Names) >= MaxDoHEntries {
			return DoHList{}, fmt.Errorf("DoH listesinde en fazla %d kayıt olabilir", MaxDoHEntries)
		}
		if p, err := parsePrefix(s); err == nil {
			if p.Bits() < 8 || (p.Addr().Is6() && p.Bits() < 32) {
				return DoHList{}, fmt.Errorf("satır %d: aralık çok geniş: %s", line, s)
			}
			if !seenP[p] {
				seenP[p] = true
				out.Prefixes = append(out.Prefixes, p)
			}
			continue
		}
		n, ok := normalizeName(s)
		if !ok {
			return DoHList{}, fmt.Errorf("satır %d: adres veya ad değil: %q", line, s)
		}
		if !seenN[n] {
			seenN[n] = true
			out.Names = append(out.Names, n)
		}
	}
	if err := sc.Err(); err != nil {
		return DoHList{}, fmt.Errorf("DoH listesi okunamadı: %w", err)
	}
	sort.Slice(out.Prefixes, func(i, j int) bool { return out.Prefixes[i].String() < out.Prefixes[j].String() })
	sort.Strings(out.Names)
	return out, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// BlocksName reports whether a DoH endpoint name covers name; the tunnel
// resolver answers such names with NXDOMAIN.
func (l DoHList) BlocksName(name string) bool {
	n, ok := normalizeName(name)
	if !ok {
		return false
	}
	for _, d := range l.Names {
		if under(n, d) {
			return true
		}
	}
	return false
}

// EnforceConfig describes the device for #717.
type EnforceConfig struct {
	// Tunnel is the tunnel interface name; DNS may leave only through it.
	Tunnel string
	// Resolvers are the in-tunnel resolver addresses (the exit node or
	// the device's tunnel resolver); at least one.
	Resolvers []netip.Addr
	// AllowLoopback keeps a local resolver on loopback reachable.
	AllowLoopback bool
	DoH           DoHList
}

// Validate checks the configuration.
func (c EnforceConfig) Validate() error {
	if c.Tunnel == "" || len(c.Tunnel) > maxInterfaceLen || strings.ContainsAny(c.Tunnel, " \t\r\n\x00\"';/") {
		return errors.New("tünel arayüzü adı geçersiz")
	}
	if len(c.Resolvers) == 0 || len(c.Resolvers) > 8 {
		return errors.New("tünel içinde 1 ile 8 çözücü adresi gerekli")
	}
	for _, a := range c.Resolvers {
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
			return fmt.Errorf("çözücü adresi geçersiz: %s", a)
		}
	}
	return nil
}

// dnsPorts are the ports of DNS (53), DNS over TLS and DNS over QUIC
// (853) and the alternative DoT port some resolvers serve (5353 is mDNS
// and stays on the local link, so it is not listed).
var dnsPorts = []uint16{53, 853}

// EnforceRules builds the ordered rule set of #717:
//
//  1. loopback DNS when AllowLoopback (a local resolver);
//  2. DNS and DoT/DoQ to the in-tunnel resolvers through the tunnel;
//  3. every other DNS and DoT/DoQ outside the tunnel is dropped;
//  4. TCP and UDP 443 to the owner's DoH endpoints is dropped on every
//     interface (also through the tunnel: the exit node would only carry
//     the query past the tunnel resolver).
//
// Port 53 and 853 inside the tunnel to other members are left to the
// packet filter (ADR-0013); this set only keeps DNS from leaving outside.
func EnforceRules(c EnforceConfig) ([]Rule, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var out []Rule
	protos := []Proto{ProtoUDP, ProtoTCP}
	if c.AllowLoopback {
		for _, p := range protos {
			for _, port := range dnsPorts {
				out = append(out,
					Rule{Action: ActionAllow, Proto: p, Dst: netip.MustParsePrefix("127.0.0.0/8"), Port: port, Comment: "yerel çözücü"},
					Rule{Action: ActionAllow, Proto: p, Dst: netip.MustParsePrefix("::1/128"), Port: port, Comment: "yerel çözücü"})
			}
		}
	}
	for _, r := range c.Resolvers {
		r = r.Unmap()
		for _, p := range protos {
			for _, port := range dnsPorts {
				out = append(out, Rule{Action: ActionAllow, Proto: p, Dst: netip.PrefixFrom(r, r.BitLen()), Port: port,
					Interface: c.Tunnel, Comment: "tünel çözücüsü"})
			}
		}
	}
	for _, p := range protos {
		for _, port := range dnsPorts {
			out = append(out, Rule{Action: ActionDrop, Proto: p, Port: port, Interface: c.Tunnel, NotInterface: true,
				Comment: "tünel dışı DNS"})
		}
	}
	for _, d := range c.DoH.Prefixes {
		for _, p := range protos {
			out = append(out, Rule{Action: ActionDrop, Proto: p, Dst: d, Port: 443, Comment: "bilinen DoH uç noktası"})
		}
	}
	return out, nil
}

// Evaluate applies rules to one outbound packet (for tests and for the
// panel's "what would happen" view); ok is false when no rule matched.
func Evaluate(rules []Rule, iface string, proto Proto, dst netip.Addr, port uint16) (Action, bool) {
	dst = dst.Unmap()
	for _, r := range rules {
		if r.Proto != proto || r.Port != port {
			continue
		}
		if r.Dst.IsValid() && !r.Dst.Contains(dst) {
			continue
		}
		if r.Interface != "" && (iface == r.Interface) == r.NotInterface {
			continue
		}
		return r.Action, true
	}
	return "", false
}

// normalizeName returns a lowercase absolute name with at least two
// labels of letters, digits, '-' and '_'.
func normalizeName(h string) (string, bool) {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	if h == "" || len(h) > 253 || !strings.Contains(h, ".") {
		return "", false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return h + ".", true
}

// absName lowercases a queried name and makes it absolute.
func absName(name string) string {
	n := strings.ToLower(name)
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return n
}

func under(n, d string) bool { return n == d || strings.HasSuffix(n, "."+d) }
