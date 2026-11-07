package fwtemplate

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// IoT and camera isolation over address ranges (#243, ADR-0232).
//
// The iot-isolation subject may be a CIDR or "host:" range. A range inside
// the network prefixes selects the OpenScale devices it holds and works
// like a tag. A range inside an approved subnet route covers devices that
// do not run OpenScale at all, such as cameras behind a router: the
// template then writes explicit range rules, because the wildcard, names,
// tags and groups never reach routed hosts (ADR-0133). Routed hosts never
// reach each other or the internet through OpenScale (the filter refuses
// routed-to-routed traffic and exit nodes do not carry them), so the
// isolation option only adds a warning that traffic staying on their LAN
// must be closed on the router itself.

// ErrRange is returned for a range the template cannot use.
var ErrRange = errors.New("aralık ağ öneklerinin veya onaylı bir alt ağ rotasının içinde olmalı")

func isRangeEntry(e string) bool {
	return strings.HasPrefix(e, trust.HostPrefix) || strings.Contains(e, "/")
}

// iotRange resolves the subject range and reports whether it lies behind a
// subnet router.
func iotRange(doc *trust.Document, e string) (netip.Prefix, bool, error) {
	p, ok := entryPrefix(doc, e)
	if !ok || !p.IsValid() || p != p.Masked() {
		return netip.Prefix{}, false, ErrSubject
	}
	for _, o := range []netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix} {
		if o.IsValid() && o.Addr().Is4() == p.Addr().Is4() && o.Bits() <= p.Bits() && o.Contains(p.Addr()) {
			return p, false, nil
		}
	}
	if _, route, ok := doc.RouteOwner(p.Addr()); ok && route.Bits() <= p.Bits() {
		return p, true, nil
	}
	return netip.Prefix{}, false, ErrRange
}

// devicesIn lists the devices whose tunnel addresses lie in p.
func devicesIn(doc *trust.Document, p netip.Prefix) []string {
	var out []string
	for _, d := range doc.Devices {
		if (d.IPv4.IsValid() && p.Contains(d.IPv4)) || (d.IPv6.IsValid() && p.Contains(d.IPv6)) {
			out = append(out, d.Name)
		}
	}
	return out
}

// buildIoTRouted plans iot-isolation for a range behind a subnet router.
func buildIoTRouted(doc *trust.Document, p Params, pfx netip.Prefix) (Plan, error) {
	if p.Protocol == "" {
		p.Protocol = trust.ProtocolTCP
	}
	if len(p.Targets) == 0 {
		return Plan{}, ErrNoTargets
	}
	if len(p.Targets) > maxTargets {
		return Plan{}, fmt.Errorf("en fazla %d hedef", maxTargets)
	}
	for _, t := range p.Targets {
		if ms, ok := members(doc, t); !ok || len(ms) == 0 {
			return Plan{}, fmt.Errorf("hedef bulunamadı: %q", t)
		}
	}
	if err := validPorts(p.Protocol, p.Ports); err != nil {
		return Plan{}, err
	}
	desc := descPrefix + string(IoTIsolation) + " (" + p.Subject + ")"
	if len(desc) > 256 {
		return Plan{}, ErrSubject
	}
	add := []trust.Rule{
		{From: slices.Clone(p.Targets), To: []string{p.Subject}, Protocol: trust.ProtocolAny, Description: desc},
		{From: []string{p.Subject}, To: slices.Clone(p.Targets), Protocol: p.Protocol, Ports: slices.Clone(p.Ports), Description: desc},
	}
	plan := Plan{Kind: IoTIsolation, Base: baseDigest(doc)}
	rules := slices.Clone(doc.Rules)
	for _, r := range add {
		if !containsRule(rules, r) {
			plan.Added = append(plan.Added, r)
		}
	}
	plan.Disabled, plan.Warnings = rangeConflicts(doc, pfx)
	for _, i := range plan.Disabled {
		rules[i].Disabled = true
	}
	if p.Isolate {
		plan.Warnings = append(plan.Warnings, "Yönlendirici arkasındaki cihazlar birbirine ve internete OpenScale üzerinden ulaşamaz; ancak aynı yerel ağdaki trafik ve yönlendiricinin kendi internet çıkışı OpenScale'den geçmez. Bunları yönlendiricide veya ayrı bir VLAN ile kapatın.")
	}
	rules = append(rules, plan.Added...)
	plan.Rules = rules
	if len(plan.Added) == 0 && len(plan.Disabled) == 0 {
		return plan, ErrNoChange
	}
	plan.Reach, plan.ReachTruncated = rangeReach(doc, plan, pfx, p)
	return plan, nil
}

// entryOverlaps reports whether a rule entry names addresses in pfx: a
// range that overlaps it or a group with such a range member.
func entryOverlaps(doc *trust.Document, e string, pfx netip.Prefix) (overlap, inside bool) {
	if g, ok := strings.CutPrefix(e, trust.GroupPrefix); ok {
		grp, found := doc.GroupByName(g)
		if !found {
			return false, false
		}
		inside = true
		for _, m := range grp.Members {
			o, in := entryOverlaps(doc, m, pfx)
			overlap = overlap || o
			inside = inside && in
		}
		return overlap, overlap && inside
	}
	if !isRangeEntry(e) {
		return false, false
	}
	p, ok := entryPrefix(doc, e)
	if !ok || !p.Overlaps(pfx) {
		return false, false
	}
	return true, pfx.Bits() <= p.Bits() && pfx.Contains(p.Addr())
}

// rangeConflicts finds enabled allow rules through which hosts of pfx can
// open connections. Rules whose sources all lie inside pfx are disabled;
// broader ones become warnings.
func rangeConflicts(doc *trust.Document, pfx netip.Prefix) (disabled []int, warnings []string) {
	for i, r := range doc.Rules {
		if r.Disabled || r.IsDeny() || r.Service != "" {
			continue
		}
		sources := r.From
		if r.Bidirectional {
			sources = append(slices.Clone(r.From), r.To...)
		}
		hit, all := false, true
		for _, e := range sources {
			o, in := entryOverlaps(doc, e, pfx)
			hit = hit || o
			all = all && in
		}
		if !hit {
			continue
		}
		if all {
			disabled = append(disabled, i)
			continue
		}
		warnings = append(warnings, fmt.Sprintf("Kural %d (%s) aralığı da kapsıyor ve başka adreslere de izin veriyor; bu şablondan sonra da geçerli kalır.", i+1, ruleLabel(r)))
	}
	return disabled, warnings
}

// rangeReach compares access between every device and one host of pfx
// (its first address) before and after the plan.
func rangeReach(doc *trust.Document, plan Plan, pfx netip.Prefix, p Params) ([]ReachChange, bool) {
	probes := slices.Clone(defaultProbes)
	if p.Protocol == trust.ProtocolTCP || p.Protocol == trust.ProtocolUDP {
		for _, spec := range p.Ports {
			if lo, _, err := trust.ParsePortRange(spec); err == nil {
				name := fmt.Sprintf("%s/%d", p.Protocol, lo)
				if !slices.ContainsFunc(probes, func(x probe) bool { return x.name == name }) {
					probes = append(probes, probe{name, p.Protocol, lo})
				}
			}
		}
	}
	host := pfx.Addr()
	if pfx.Bits() < host.BitLen() {
		host = host.Next()
	}
	after := *doc
	after.Rules = plan.Rules
	query := func(pr probe) trust.PacketQuery {
		switch pr.proto {
		case trust.ProtocolUDP:
			return trust.PacketQuery{Proto: 17, Port: pr.port, ICMPType: -1}
		case trust.ProtocolICMP:
			return trust.PacketQuery{Proto: 1, ICMPType: 8}
		}
		return trust.PacketQuery{Proto: 6, Port: pr.port, ICMPType: -1}
	}
	var out []ReachChange
	label := pfx.String()
	for _, d := range doc.Devices {
		for _, dir := range []bool{true, false} {
			src, dst := trust.DeviceEnd(d.Name), trust.AddrEnd(host)
			from, to := d.Name, label
			if !dir {
				src, dst, from, to = dst, src, to, from
			}
			for _, pr := range probes {
				b, a := doc.AllowsRoutedPacketAt(src, dst, query(pr)), after.AllowsRoutedPacketAt(src, dst, query(pr))
				if a == b {
					continue
				}
				if len(out) >= maxReach {
					return out, true
				}
				out = append(out, ReachChange{From: from, To: to, Probe: pr.name, Before: b, After: a})
			}
		}
	}
	return out, false
}

// withoutExitUsers returns exit_users without the subject: the entry and
// the subject devices are removed, and when no list exists yet one is made
// of every other device. Devices still allowed through a tag or group are
// named in a warning.
func withoutExitUsers(doc *trust.Document, entry string, subj []string) ([]string, bool, []string) {
	if len(subj) == 0 {
		return nil, false, nil
	}
	users, limited := doc.ExitUsersList()
	var next []string
	var warn []string
	if !limited {
		for _, d := range doc.Devices {
			if !slices.Contains(subj, d.Name) {
				next = append(next, d.Name)
			}
		}
		warn = append(warn, "Çıkış düğümü kullanıcıları listesi yoktu; şablon bütün diğer cihazlarla bir liste oluşturur. Sonradan katılan cihazları bu listeye eklemeniz gerekir.")
	} else {
		next = slices.DeleteFunc(slices.Clone(users), func(u string) bool { return u == entry || slices.Contains(subj, u) })
	}
	if next == nil {
		next = []string{}
	}
	changed := !limited || len(next) != len(users)
	probe := *doc
	probe.ExitUsers = &next
	for _, n := range subj {
		if probe.MayUseExitNode(n) {
			warn = append(warn, n+" bir etiket veya grup üzerinden çıkış düğümünü kullanmaya devam ediyor; o girdiyi çıkış düğümü kullanıcılarından kaldırın.")
		}
	}
	return next, changed, warn
}
