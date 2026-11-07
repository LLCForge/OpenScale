package osnet

// Applying the #717 DNS enforcement rule set (ADR-0213, ADR-0224) to the
// operating system. dnsguard.EnforceRules builds the ordered, abstract
// rules; this file turns them into the three native forms and drives
// them through a replaceable command runner or WFP interface, so the
// rule text and the call sequence are tested on every platform with a
// fake. The *_linux, *_windows and *_darwin files only bind the real
// system:
//
//   - Linux: its own nftables table "inet openscale_dns", replaced in one
//     "nft -f" transaction, deleted on Remove;
//   - Windows: filters in OpenScale's own sublayer, opened in a dynamic
//     WFP session: when the service process ends for any reason the
//     kernel drops every filter of the session by itself;
//   - macOS: the pf sub-anchor "com.openscale/dns", which the kill switch
//     anchor evaluates (one "anchor" line in pfKillSwitchRules).
//
// Nothing here decides when the rules are installed: dnsguard.Enforcer
// installs them only while the tunnel is up and removes them otherwise.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/dnsguard"
)

// ErrDNSEnforceUnsupported is returned where no DNS enforcement exists.
var ErrDNSEnforceUnsupported = errors.New("DNS zorlama bu işletim sisteminde yok")

// ErrDNSEnforceInactive says the macOS rules were loaded but pf does not
// evaluate them: the sub-anchor only works inside the kill switch anchor.
var ErrDNSEnforceInactive = errors.New("DNS zorlama kuralları yüklendi ama etkin değil: macOS'ta kill switch açıkken çalışır")

// dnsEnforceTimeout bounds one apply or remove.
const dnsEnforceTimeout = 30 * time.Second

// maxDNSEnforceRules bounds the rule set (the DoH list allows 4096
// entries, two rules each, plus the fixed rules).
const maxDNSEnforceRules = 2*dnsguard.MaxDoHEntries + 64

// cmdRunner runs a program without a shell; stdin may be nil.
type cmdRunner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

// dnsEnforceMissing reports whether a tool error says the table or anchor
// does not exist.
func dnsEnforceMissing(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "No such file or directory") || strings.Contains(s, "does not exist")
}

// dnsEnforceInterface returns the one tunnel interface the rules name;
// EnforceRules uses a single tunnel, more than one is refused.
func dnsEnforceInterface(rules []dnsguard.Rule) (string, error) {
	if len(rules) > maxDNSEnforceRules {
		return "", fmt.Errorf("DNS zorlama için en fazla %d kural", maxDNSEnforceRules)
	}
	iface := ""
	for _, r := range rules {
		if r.Interface == "" {
			continue
		}
		if iface != "" && r.Interface != iface {
			return "", errors.New("DNS zorlama kuralları birden fazla arayüz adlandırıyor")
		}
		iface = r.Interface
	}
	return iface, nil
}

// ---- Linux: nftables ----

// nftDNSEnforceScript renders the table. OpenScale's own marked sockets
// (TunnelBypassMark, the same exception as the kill switch and the leak
// guard) pass first, so the engine's own connections keep working.
func nftDNSEnforceScript(rules []dnsguard.Rule) (string, error) {
	iface, err := dnsEnforceInterface(rules)
	if err != nil {
		return "", err
	}
	if iface != "" && !validNftIfname(iface) {
		return "", fmt.Errorf("geçersiz arayüz adı %q", iface)
	}
	script, err := dnsguard.RenderNFT(rules)
	if err != nil {
		return "", err
	}
	const hook = "policy accept;\n"
	i := strings.Index(script, hook)
	if i < 0 {
		return "", errors.New("nft betiği beklenen biçimde değil")
	}
	i += len(hook)
	mark := "\t\tmeta mark 0x" + strconv.FormatUint(TunnelBypassMark, 16) + " accept comment \"OpenScale\"\n"
	return script[:i] + mark + script[i:], nil
}

// nftDNSEnforcer implements dnsguard.Applier with nft.
type nftDNSEnforcer struct {
	run cmdRunner
	has func(program string) bool
	mu  sync.Mutex
}

func (n *nftDNSEnforcer) Apply(rules []dnsguard.Rule) error {
	script, err := nftDNSEnforceScript(rules)
	if err != nil {
		return err
	}
	if !n.has("nft") {
		return errors.New("DNS zorlama için nft (nftables) gerekli; bulunamadı")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), dnsEnforceTimeout)
	defer cancel()
	if _, err := n.run(ctx, []byte(script), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("DNS zorlama kuralları yüklenemedi: %w", err)
	}
	return nil
}

func (n *nftDNSEnforcer) Remove() error {
	if !n.has("nft") {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), dnsEnforceTimeout)
	defer cancel()
	if _, err := n.run(ctx, nil, "nft", "delete", "table", "inet", dnsguard.NFTTable); err != nil && !dnsEnforceMissing(err) {
		return fmt.Errorf("DNS zorlama tablosu silinemedi: %w", err)
	}
	return nil
}

// ---- macOS: pf sub-anchor ----

const (
	// pfDNSSubAnchor is evaluated inside "com.openscale"; the kill switch
	// rules call it before the tunnel permit, so a DoH endpoint is
	// dropped also through the tunnel.
	pfDNSSubAnchor = "dns"
	pfDNSAnchor    = pfAnchor + "/" + pfDNSSubAnchor
)

// pfDNSEnforceRules renders the rules as quick pf rules: the first match
// decides, like dnsguard.Evaluate.
func pfDNSEnforceRules(rules []dnsguard.Rule) (string, error) {
	iface, err := dnsEnforceInterface(rules)
	if err != nil {
		return "", err
	}
	if iface != "" && !validDarwinIface(iface) {
		return "", fmt.Errorf("geçersiz arayüz adı %q", iface)
	}
	var b strings.Builder
	b.WriteString("# OpenScale DNS zorlama (#717, ADR-0224)\n")
	for i, r := range rules {
		action := "pass out quick"
		switch r.Action {
		case dnsguard.ActionAllow:
		case dnsguard.ActionDrop:
			action = "block drop out quick"
		default:
			return "", fmt.Errorf("kural %d: bilinmeyen eylem %q", i, r.Action)
		}
		if r.Proto != dnsguard.ProtoTCP && r.Proto != dnsguard.ProtoUDP {
			return "", fmt.Errorf("kural %d: bilinmeyen protokol %q", i, r.Proto)
		}
		b.WriteString(action)
		if r.Interface != "" {
			if r.NotInterface {
				b.WriteString(" on ! " + r.Interface)
			} else {
				b.WriteString(" on " + r.Interface)
			}
		}
		to := "any"
		if r.Dst.IsValid() {
			if r.Dst.Addr().Is6() {
				b.WriteString(" inet6")
			} else {
				b.WriteString(" inet")
			}
			to = r.Dst.Masked().String()
		}
		fmt.Fprintf(&b, " proto %s from any to %s port %d\n", r.Proto, to, r.Port)
	}
	return b.String(), nil
}

// pfDNSEnforcer implements dnsguard.Applier with pfctl.
type pfDNSEnforcer struct {
	run    cmdRunner
	exists func(path string) bool
	mu     sync.Mutex
}

// Apply loads the sub-anchor and then checks that pf evaluates it: the
// kill switch anchor calls it and the main ruleset calls the kill switch
// anchor. Loaded but not evaluated rules change nothing, so that is
// reported as ErrDNSEnforceInactive instead of success.
func (p *pfDNSEnforcer) Apply(rules []dnsguard.Rule) error {
	text, err := pfDNSEnforceRules(rules)
	if err != nil {
		return err
	}
	if !p.exists(darwinPfctl) {
		return errors.New("DNS zorlama için pfctl gerekli; bulunamadı")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), dnsEnforceTimeout)
	defer cancel()
	if _, err := p.run(ctx, []byte(text), darwinPfctl, "-a", pfDNSAnchor, "-f", "-"); err != nil {
		return fmt.Errorf("DNS zorlama kuralları yüklenemedi: %w", err)
	}
	inner, err := p.run(ctx, nil, darwinPfctl, "-a", pfAnchor, "-s", "rules")
	if err != nil && !dnsEnforceMissing(err) {
		return fmt.Errorf("pf kuralları okunamadı: %w", err)
	}
	main, err := p.run(ctx, nil, darwinPfctl, "-s", "rules")
	if err != nil {
		return fmt.Errorf("pf kuralları okunamadı: %w", err)
	}
	if !strings.Contains(string(inner), `anchor "`+pfDNSSubAnchor+`"`) || !pfReferencesAnchor(main) {
		return ErrDNSEnforceInactive
	}
	return nil
}

func (p *pfDNSEnforcer) Remove() error {
	if !p.exists(darwinPfctl) {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), dnsEnforceTimeout)
	defer cancel()
	if _, err := p.run(ctx, nil, darwinPfctl, "-a", pfDNSAnchor, "-F", "rules"); err != nil && !dnsEnforceMissing(err) {
		return fmt.Errorf("DNS zorlama kuralları silinemedi: %w", err)
	}
	return nil
}

// ---- Windows: WFP, dynamic session ----

// wfpIfaceMatch says how a WFP filter matches the tunnel interface.
type wfpIfaceMatch uint8

const (
	wfpIfaceAny wfpIfaceMatch = iota
	wfpIfaceEqual
	wfpIfaceNotEqual
)

// dnsWFPFilter is one filter of the plan, independent of the WFP API.
type dnsWFPFilter struct {
	Name   string
	IPv6   bool
	Permit bool
	// App permits OpenScale's own program (no other condition).
	App    bool
	Proto  uint8
	Prefix netip.Prefix
	Port   uint16
	Iface  wfpIfaceMatch
	// Weight orders the filters inside the sublayer: the highest
	// matching weight decides, so earlier rules get higher weights.
	Weight uint64
}

// dnsWFPPlan turns the ordered rules into WFP filters at the outbound
// connect layers. A rule without a destination goes to both the IPv4 and
// the IPv6 layer; one with a destination only to its family. The first
// filter permits OpenScale's own program, like the kill switch does.
func dnsWFPPlan(rules []dnsguard.Rule) ([]dnsWFPFilter, error) {
	if _, err := dnsEnforceInterface(rules); err != nil {
		return nil, err
	}
	top := uint64(len(rules)) + 1
	plan := []dnsWFPFilter{
		{Name: "OpenScale DNS: program izni", Permit: true, App: true, Weight: top},
		{Name: "OpenScale DNS: program izni", IPv6: true, Permit: true, App: true, Weight: top},
	}
	for i, r := range rules {
		f := dnsWFPFilter{Port: r.Port, Weight: top - 1 - uint64(i)}
		switch r.Action {
		case dnsguard.ActionAllow:
			f.Permit = true
		case dnsguard.ActionDrop:
		default:
			return nil, fmt.Errorf("kural %d: bilinmeyen eylem %q", i, r.Action)
		}
		switch r.Proto {
		case dnsguard.ProtoTCP:
			f.Proto = 6
		case dnsguard.ProtoUDP:
			f.Proto = 17
		default:
			return nil, fmt.Errorf("kural %d: bilinmeyen protokol %q", i, r.Proto)
		}
		if r.Interface != "" {
			f.Iface = wfpIfaceEqual
			if r.NotInterface {
				f.Iface = wfpIfaceNotEqual
			}
		}
		f.Name = "OpenScale DNS: " + strings.TrimSpace(r.Comment)
		if r.Dst.IsValid() {
			f.Prefix = r.Dst.Masked()
			f.IPv6 = f.Prefix.Addr().Is6()
			plan = append(plan, f)
			continue
		}
		plan = append(plan, f)
		f.IPv6 = true
		plan = append(plan, f)
	}
	return plan, nil
}

// wfpDNSOps is the WFP surface the enforcer uses; the real one is in
// dnsenforce_windows.go, tests use a recording fake.
type wfpDNSOps interface {
	// open starts a dynamic session: every object added through it is
	// deleted when the session closes or the process ends.
	open() error
	close() error
	begin() error
	commit() error
	abort() error
	addSublayer() error
	addFilter(f dnsWFPFilter, luid uint64) (uint64, error)
	deleteFilter(id uint64) error
}

// wfpDNSEnforcer implements dnsguard.Applier over a dynamic WFP session.
type wfpDNSEnforcer struct {
	ops    wfpDNSOps
	luidOf func(iface string) (uint64, error)

	mu     sync.Mutex
	opened bool
	ids    []uint64
}

// Apply replaces the filters in one transaction: either the whole new set
// is in place or the previous one stays.
func (w *wfpDNSEnforcer) Apply(rules []dnsguard.Rule) error {
	plan, err := dnsWFPPlan(rules)
	if err != nil {
		return err
	}
	iface, _ := dnsEnforceInterface(rules)
	var luid uint64
	if iface != "" {
		if luid, err = w.luidOf(iface); err != nil {
			return err
		}
		if luid == 0 {
			return fmt.Errorf("tünel arayüzü bulunamadı: %s", iface)
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	fresh := !w.opened
	if fresh {
		if err := w.ops.open(); err != nil {
			return err
		}
		w.opened = true
	}
	fail := func(err error) error {
		_ = w.ops.abort()
		if fresh {
			_ = w.ops.close()
			w.opened, w.ids = false, nil
		}
		return err
	}
	if err := w.ops.begin(); err != nil {
		if fresh {
			_ = w.ops.close()
			w.opened = false
		}
		return err
	}
	if fresh {
		if err := w.ops.addSublayer(); err != nil {
			return fail(err)
		}
	}
	for _, id := range w.ids {
		if err := w.ops.deleteFilter(id); err != nil {
			return fail(err)
		}
	}
	ids := make([]uint64, 0, len(plan))
	for _, f := range plan {
		id, err := w.ops.addFilter(f, luid)
		if err != nil {
			return fail(fmt.Errorf("DNS zorlama kuralı eklenemedi (%s): %w", f.Name, err))
		}
		ids = append(ids, id)
	}
	if err := w.ops.commit(); err != nil {
		return fail(err)
	}
	w.ids = ids
	return nil
}

// Remove closes the dynamic session; WFP deletes the sublayer and every
// filter with it.
func (w *wfpDNSEnforcer) Remove() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.opened {
		return nil
	}
	err := w.ops.close()
	w.opened, w.ids = false, nil
	return err
}
