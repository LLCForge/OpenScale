package osnet

import (
	"bufio"
	"net/netip"
	"strings"
)

// SystemResolver is one DNS server the operating system uses, with the
// link it belongs to ("" for global ones).
type SystemResolver struct {
	Link string
	Addr netip.Addr
}

// parseResolvectlDNS reads "resolvectl dns": "Global: a b" and
// "Link 2 (eth0): a b%2" lines.
func parseResolvectlDNS(out string) []SystemResolver {
	var res []SystemResolver
	for _, line := range strings.Split(out, "\n") {
		head, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		link := ""
		head = strings.TrimSpace(head)
		switch {
		case head == "Global":
		case strings.HasPrefix(head, "Link "):
			open, close := strings.Index(head, "("), strings.LastIndex(head, ")")
			if open < 0 || close < open {
				continue
			}
			link = head[open+1 : close]
		default:
			continue
		}
		for _, f := range strings.Fields(rest) {
			if i := strings.IndexAny(f, "%#"); i >= 0 {
				f = f[:i]
			}
			if a, err := netip.ParseAddr(f); err == nil {
				res = append(res, SystemResolver{Link: link, Addr: a})
			}
		}
	}
	return res
}

// parseResolvConf reads the nameserver lines of resolv.conf.
func parseResolvConf(data string) []SystemResolver {
	var res []SystemResolver
	s := bufio.NewScanner(strings.NewReader(data))
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			v := f[1]
			if i := strings.IndexByte(v, '%'); i >= 0 {
				v = v[:i]
			}
			if a, err := netip.ParseAddr(v); err == nil {
				res = append(res, SystemResolver{Addr: a})
			}
		}
	}
	return res
}
