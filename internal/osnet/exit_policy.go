package osnet

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Exit node policy (P04): outbound port policy (#402), blocking the
// owner's list of DoH servers (#403), the public source address members
// leave from (#408) and the data quota block list (#401, ADR-0155). Every
// part is optional; an ExitNAT without them installs exactly the rules it
// did before.

// ExitPort is one destination port members may not reach on the internet.
type ExitPort struct {
	// Proto is "tcp" or "udp".
	Proto string
	Port  uint16
}

func (p ExitPort) String() string { return p.Proto + "/" + strconv.Itoa(int(p.Port)) }

// ExitSource maps a member's overlay address to the public address its
// traffic is masqueraded behind. An invalid Member is the default for
// every member of that address family.
type ExitSource struct {
	Member netip.Addr
	Source netip.Addr
}

// Limits of the exit policy.
const (
	MaxExitBlockedPorts = 32
	MaxExitDoHEntries   = 512
	MaxExitSources      = 256
	// maxDoHLine bounds one line of the DoH list file.
	maxDoHLine = 256
	// MaxDoHListSize bounds the DoH list file.
	MaxDoHListSize = 64 << 10
	// Narrowest blocked DoH ranges: a wider one would cut ordinary HTTPS.
	minDoHBits4 = 16
	minDoHBits6 = 32
)

// DefaultExitBlockedPorts is the policy when the owner sets none: SMTP
// submission straight to mail servers (TCP 25), the usual reason a VPS
// provider closes an account after a member is compromised.
var DefaultExitBlockedPorts = []ExitPort{{Proto: "tcp", Port: 25}}

// ParseExitPorts parses "25,465,tcp/587,udp/1900"; a bare number is TCP.
// "none" (or "") is an empty policy. The result is sorted and unique.
func ParseExitPorts(s string) ([]ExitPort, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "none") {
		return nil, nil
	}
	var out []ExitPort
	for _, f := range strings.Split(s, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		proto, num := "tcp", f
		if i := strings.IndexByte(f, '/'); i >= 0 {
			proto, num = f[:i], f[i+1:]
		}
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("port %q: protokol tcp veya udp olmalı", f)
		}
		n, err := strconv.ParseUint(num, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("port %q: 1-65535 arası olmalı", f)
		}
		p := ExitPort{Proto: proto, Port: uint16(n)}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
		if len(out) > MaxExitBlockedPorts {
			return nil, fmt.Errorf("en fazla %d port engellenebilir", MaxExitBlockedPorts)
		}
	}
	slices.SortFunc(out, func(a, b ExitPort) int {
		if c := strings.Compare(a.Proto, b.Proto); c != 0 {
			return c
		}
		return int(a.Port) - int(b.Port)
	})
	return out, nil
}

// ParseDoHList reads the owner's DoH server list: one address or CIDR per
// line, "#" starts a comment. Ranges wider than /16 (IPv4) or /32 (IPv6)
// are refused because they would block ordinary HTTPS.
func ParseDoHList(r io.Reader) ([]netip.Prefix, error) {
	sc := bufio.NewScanner(io.LimitReader(r, MaxDoHListSize+1))
	sc.Buffer(make([]byte, 0, maxDoHLine), maxDoHLine)
	var (
		out   []netip.Prefix
		total int
		line  int
	)
	for sc.Scan() {
		line++
		total += len(sc.Bytes()) + 1
		if total > MaxDoHListSize {
			return nil, errors.New("DoH listesi çok büyük")
		}
		s := sc.Text()
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = s[:i]
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := parseDoHEntry(s)
		if err != nil {
			return nil, fmt.Errorf("DoH listesi satır %d: %w", line, err)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
		if len(out) > MaxExitDoHEntries {
			return nil, fmt.Errorf("DoH listesi en fazla %d kayıt alır", MaxExitDoHEntries)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("DoH listesi okunamadı: %w", err)
	}
	return out, nil
}

func parseDoHEntry(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return netip.Prefix{}, fmt.Errorf("%q geçerli bir CIDR değil", s)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q geçerli bir adres değil", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
	}
	p = p.Masked()
	if err := checkPublicPrefix(p); err != nil {
		return netip.Prefix{}, err
	}
	return p, nil
}

func checkPublicPrefix(p netip.Prefix) error {
	a := p.Addr()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return fmt.Errorf("%s internette bir adres değil", p)
	}
	if (a.Is4() && p.Bits() < minDoHBits4) || (a.Is6() && p.Bits() < minDoHBits6) {
		return fmt.Errorf("%s çok geniş (en geniş IPv4 /%d, IPv6 /%d)", p, minDoHBits4, minDoHBits6)
	}
	return nil
}

// validSourceAddr: an address this host can masquerade behind.
func validSourceAddr(a netip.Addr) bool {
	return a.IsValid() && a.Zone() == "" && !a.Is4In6() && !a.IsLoopback() && !a.IsMulticast() &&
		!a.IsUnspecified() && !a.IsLinkLocalUnicast()
}

// validatePolicy checks the optional policy parts of an ExitNAT.
func (c ExitNAT) validatePolicy() error {
	if len(c.BlockPorts) > MaxExitBlockedPorts {
		return errors.New("too many blocked exit ports")
	}
	for _, p := range c.BlockPorts {
		if (p.Proto != "tcp" && p.Proto != "udp") || p.Port == 0 {
			return fmt.Errorf("invalid blocked exit port %v", p)
		}
	}
	if len(c.BlockDoH) > MaxExitDoHEntries {
		return errors.New("too many DoH entries")
	}
	for _, p := range c.BlockDoH {
		if !p.IsValid() || p != p.Masked() || checkPublicPrefix(p) != nil {
			return fmt.Errorf("invalid DoH entry %v", p)
		}
	}
	if len(c.Sources) > MaxExitSources {
		return errors.New("too many exit sources")
	}
	seen := map[netip.Addr]bool{}
	defaults := map[bool]bool{}
	for _, s := range c.Sources {
		if !validSourceAddr(s.Source) {
			return fmt.Errorf("invalid exit source %v", s.Source)
		}
		if !s.Member.IsValid() {
			if defaults[s.Source.Is4()] {
				return errors.New("two default exit sources for one address family")
			}
			defaults[s.Source.Is4()] = true
			continue
		}
		in := c.IPv4
		if s.Member.Is6() {
			in = c.IPv6
		}
		if s.Member.Is4() != s.Source.Is4() || !in.Contains(s.Member) || seen[s.Member] {
			return fmt.Errorf("invalid exit source for member %v", s.Member)
		}
		seen[s.Member] = true
	}
	return nil
}

// sourcesFor returns the member-specific and default sources of a family.
func (c ExitNAT) sourcesFor(v4 bool) (members []ExitSource, def netip.Addr) {
	for _, s := range c.Sources {
		if s.Source.Is4() != v4 {
			continue
		}
		if s.Member.IsValid() {
			members = append(members, s)
		} else {
			def = s.Source
		}
	}
	slices.SortFunc(members, func(a, b ExitSource) int { return a.Member.Compare(b.Member) })
	return members, def
}
