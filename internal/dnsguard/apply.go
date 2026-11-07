package dnsguard

// Applying the #717 rule set to the operating system. The rule set itself
// is pure (EnforceRules); this file turns it into the two native forms,
// an nftables script for Linux and a WFP filter list for Windows, and
// drives an Applier that installs or removes them. The real appliers
// belong with the other system changes in internal/osnet; tests use a
// fake one so nothing on the test machine is touched.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// NFTTable is the nftables table OpenScale's DNS enforcement owns.
const NFTTable = "openscale_dns"

// Applier installs and removes a rendered rule set.
type Applier interface {
	// Apply replaces the whole enforcement rule set atomically.
	Apply(rules []Rule) error
	// Remove takes the rule set away; removing nothing is not an error.
	Remove() error
}

const badIfaceChars = " \t\r\n\x00\"';/{}"

// RenderNFT renders rules as one nftables script that replaces the
// table in a single transaction ("nft -f"). Rules keep their order.
func RenderNFT(rules []Rule) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", NFTTable, NFTTable, NFTTable)
	b.WriteString("\tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n")
	for i, r := range rules {
		if r.Action != ActionAllow && r.Action != ActionDrop {
			return "", fmt.Errorf("kural %d: bilinmeyen eylem %q", i, r.Action)
		}
		if r.Proto != ProtoTCP && r.Proto != ProtoUDP {
			return "", fmt.Errorf("kural %d: bilinmeyen protokol %q", i, r.Proto)
		}
		if strings.ContainsAny(r.Interface, badIfaceChars) || len(r.Interface) > maxInterfaceLen {
			return "", fmt.Errorf("kural %d: arayüz adı geçersiz", i)
		}
		b.WriteString("\t\t")
		if r.Interface != "" {
			op := ""
			if r.NotInterface {
				op = "!= "
			}
			fmt.Fprintf(&b, "oifname %s\"%s\" ", op, r.Interface)
		}
		if r.Dst.IsValid() {
			fam := "ip"
			if r.Dst.Addr().Is6() {
				fam = "ip6"
			}
			fmt.Fprintf(&b, "%s daddr %s ", fam, r.Dst.Masked())
		}
		verdict := "accept"
		if r.Action == ActionDrop {
			verdict = "drop"
		}
		fmt.Fprintf(&b, "%s dport %d %s comment \"%s\"\n", r.Proto, r.Port, verdict, nftComment(r.Comment))
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

func nftComment(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 {
			return -1
		}
		return r
	}, s)
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// WFPFilter is one Windows Filtering Platform filter at the outbound
// connect layer (ALE_AUTH_CONNECT). Weight preserves the rule order:
// earlier rules get a higher weight, so the first match wins as in
// Evaluate.
type WFPFilter struct {
	Name         string
	Permit       bool
	Proto        uint8 // 6 tcp, 17 udp
	RemotePrefix string
	RemotePort   uint16
	// Interface is the tunnel interface alias; NotInterface inverts it.
	Interface    string
	NotInterface bool
	Weight       uint8
}

// RenderWFP renders rules as WFP filters.
func RenderWFP(rules []Rule) ([]WFPFilter, error) {
	if len(rules) > 250 {
		return nil, errors.New("WFP için en fazla 250 kural")
	}
	out := make([]WFPFilter, 0, len(rules))
	for i, r := range rules {
		if r.Action != ActionAllow && r.Action != ActionDrop {
			return nil, fmt.Errorf("kural %d: bilinmeyen eylem %q", i, r.Action)
		}
		f := WFPFilter{Name: "OpenScale DNS: " + nftComment(r.Comment), Permit: r.Action == ActionAllow,
			RemotePort: r.Port, Interface: r.Interface, NotInterface: r.NotInterface, Weight: uint8(255 - i)}
		switch r.Proto {
		case ProtoTCP:
			f.Proto = 6
		case ProtoUDP:
			f.Proto = 17
		default:
			return nil, fmt.Errorf("kural %d: bilinmeyen protokol %q", i, r.Proto)
		}
		if r.Dst.IsValid() {
			f.RemotePrefix = r.Dst.Masked().String()
		}
		out = append(out, f)
	}
	return out, nil
}

// Enforcer keeps the rule set installed exactly while the tunnel is up
// and enforcement is on: rules that send DNS to a tunnel that does not
// exist would cut the computer off name resolution.
type Enforcer struct {
	Applier Applier

	mu        sync.Mutex
	installed bool
	last      string
}

// Sync installs cfg's rules when on and tunnelUp, and removes them
// otherwise. It re-applies only when the rule set changed.
func (e *Enforcer) Sync(on, tunnelUp bool, cfg EnforceConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !on || !tunnelUp {
		if !e.installed {
			return nil
		}
		if err := e.Applier.Remove(); err != nil {
			return err
		}
		e.installed, e.last = false, ""
		return nil
	}
	rules, err := EnforceRules(cfg)
	if err != nil {
		return err
	}
	key := fmt.Sprint(rules)
	if e.installed && key == e.last {
		return nil
	}
	if err := e.Applier.Apply(rules); err != nil {
		return err
	}
	e.installed, e.last = true, key
	return nil
}

// Installed reports whether the rule set is in place.
func (e *Enforcer) Installed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.installed
}
