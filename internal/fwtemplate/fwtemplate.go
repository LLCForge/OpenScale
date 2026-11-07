// Package fwtemplate turns ready-made firewall packages (#727, ADR-0215)
// into ordinary rules of the signed network document: "internet only",
// "NAS only", "guest", "IoT isolation", "admin everywhere" and
// "quarantine". A template never invents a rule type; it produces
// trust.Rule values, an exit_users change when needed, and a preview of
// what changes: rules added, narrow rules disabled, broad rules the owner
// must look at, and the device pairs whose reachability changes.
//
// Nothing is signed or applied here. The caller shows the Plan, the owner
// approves it, and the existing edit and signing flow (Plan.Apply on the
// working copy, then the usual sign/publish) makes it effective.
package fwtemplate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/openscale/openscale/internal/trust"
)

// Kind names a template.
type Kind string

// Templates.
const (
	InternetOnly    Kind = "internet-only"
	NASOnly         Kind = "nas-only"
	Guest           Kind = "guest"
	IoTIsolation    Kind = "iot-isolation"
	AdminEverywhere Kind = "admin-everywhere"
	Quarantine      Kind = "quarantine"
)

// Info describes a template for the panel.
type Info struct {
	Kind        Kind   `json:"kind"`
	Title       string `json:"title"`
	Description string `json:"description"`
	// NeedsTargets and NeedsPorts tell the form which fields to show.
	NeedsTargets bool `json:"needsTargets"`
	NeedsPorts   bool `json:"needsPorts"`
	// Ranges: the subject may be a CIDR or "host:" range, also behind a
	// subnet router; Isolate: the template offers the isolation option
	// (#243, ADR-0232).
	Ranges  bool `json:"ranges"`
	Isolate bool `json:"isolate"`
}

// Templates lists the templates in display order.
func Templates() []Info {
	return []Info{
		{Kind: InternetOnly, Title: "Yalnızca internet", Description: "Cihaz yalnızca çıkış düğümü üzerinden internete çıkar; ağdaki hiçbir cihaza bağlanamaz."},
		{Kind: NASOnly, Title: "Yalnızca NAS", Description: "Cihaz yalnızca seçilen NAS'a, seçilen portlardan bağlanır; daha geniş izinler önizlemede gösterilir.", NeedsTargets: true, NeedsPorts: true},
		{Kind: Guest, Title: "Misafir", Description: "Misafir cihaz internete ve seçilen paylaşımlı cihazlara (yazıcı gibi) erişir; ağdaki cihazlar misafire bağlanamaz. İsteğe bağlı bitiş zamanı.", NeedsTargets: true, NeedsPorts: true},
		{Kind: IoTIsolation, Title: "IoT yalıtımı", Description: "Akıllı cihazlar ve kameralar (alt ağ yönlendirici arkasındaki bir aralık da olabilir) yalnızca denetleyiciye (ör. Home Assistant) seçilen portlardan bağlanır; denetleyici onlara her yoldan ulaşır.", NeedsTargets: true, NeedsPorts: true, Ranges: true, Isolate: true},
		{Kind: AdminEverywhere, Title: "Yönetici her yere", Description: "Seçilen yönetim cihazı ağdaki her cihaza bağlanabilir."},
		{Kind: Quarantine, Title: "Karantina", Description: "Cihazın ağdaki bütün bağlantıları iki yönde de kesilir; saldırı algılandığında önerilir."},
	}
}

// Params are the template's inputs. Subject and Targets are rule entries:
// a device name, "tag:x" or "group:x".
type Params struct {
	Subject string
	Targets []string
	// Protocol and Ports are the allowed service of nas-only, guest and
	// iot-isolation (default tcp).
	Protocol trust.Protocol
	Ports    []string
	// Until ends the guest template's rules (zero means no end).
	Until time.Time
	// Isolate closes iot-isolation subjects to each other and to the
	// internet through exit nodes (#243, ADR-0232, iot_routed.go).
	Isolate bool
}

// ReachChange is one device pair whose access changes.
type ReachChange struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Probe  string `json:"probe"`
	Before bool   `json:"before"`
	After  bool   `json:"after"`
}

// Plan is the preview of a template.
type Plan struct {
	Kind  Kind         `json:"kind"`
	Added []trust.Rule `json:"added"`
	// Disabled are indices of existing allow rules that only the subject
	// uses and that the template turns off.
	Disabled []int `json:"disabled"`
	// Warnings name broad rules that still give the subject more access;
	// the owner decides about them.
	Warnings []string `json:"warnings"`
	// ExitUsers is the new exit_users list when ExitUsersChanged.
	ExitUsers        []string      `json:"exitUsers,omitempty"`
	ExitUsersChanged bool          `json:"exitUsersChanged"`
	Reach            []ReachChange `json:"reach"`
	ReachTruncated   bool          `json:"reachTruncated"`
	// Base fingerprints the previewed rules and exit_users; Apply refuses
	// a document that changed since.
	Base string `json:"base"`
	// Rules is the complete rule list after the template.
	Rules []trust.Rule `json:"-"`
}

// Limits.
const (
	maxSubjectDevices = 64
	maxReach          = 2000
	maxTargets        = 16
	maxPorts          = 32
	descPrefix        = "Şablon: "
)

// Errors.
var (
	ErrUnknownKind = errors.New("bilinmeyen şablon")
	ErrSubject     = errors.New("şablonun konusu bir cihaz, tag:x veya group:x olmalı")
	ErrNoTargets   = errors.New("bu şablon en az bir hedef cihaz ister")
	ErrNoChange    = errors.New("şablon belgede bir değişiklik yapmıyor; kurallar zaten var")
)

// members resolves a rule entry to device names. Wildcards and address
// entries are not subjects.
func members(doc *trust.Document, e string) ([]string, bool) {
	if e == "" || e == trust.RuleWildcard || strings.HasPrefix(e, trust.HostPrefix) || strings.Contains(e, "/") {
		return nil, false
	}
	if t, ok := strings.CutPrefix(e, trust.TagPrefix); ok {
		var out []string
		for _, d := range doc.Devices {
			if slices.Contains(d.Tags, t) {
				out = append(out, d.Name)
			}
		}
		return out, true
	}
	if g, ok := strings.CutPrefix(e, trust.GroupPrefix); ok {
		grp, found := doc.GroupByName(g)
		if !found {
			return nil, false
		}
		var out []string
		for _, m := range grp.Members {
			sub, ok := members(doc, m)
			if !ok {
				continue
			}
			for _, n := range sub {
				if !slices.Contains(out, n) {
					out = append(out, n)
				}
			}
		}
		return out, true
	}
	if _, ok := doc.DeviceByName(e); ok {
		return []string{e}, true
	}
	return nil, false
}

// covers reports whether rule entry e matches device d.
func covers(doc *trust.Document, e string, d trust.Device) bool {
	switch {
	case e == trust.RuleWildcard:
		return true
	case strings.HasPrefix(e, trust.HostPrefix) || strings.Contains(e, "/"):
		p, ok := entryPrefix(doc, e)
		return ok && ((d.IPv4.IsValid() && p.Contains(d.IPv4)) || (d.IPv6.IsValid() && p.Contains(d.IPv6)))
	}
	ms, _ := members(doc, e)
	return slices.Contains(ms, d.Name)
}

func entryPrefix(doc *trust.Document, e string) (netip.Prefix, bool) {
	if h, ok := strings.CutPrefix(e, trust.HostPrefix); ok {
		for _, n := range doc.Hosts {
			if n.Name == h {
				return n.Prefix, true
			}
		}
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(e)
	return p, err == nil
}

func validPorts(proto trust.Protocol, ports []string) error {
	switch proto {
	case trust.ProtocolTCP, trust.ProtocolUDP:
		if len(ports) == 0 || len(ports) > maxPorts {
			return fmt.Errorf("1-%d port gerekli", maxPorts)
		}
		for _, p := range ports {
			if _, _, err := trust.ParsePortRange(p); err != nil {
				return fmt.Errorf("port geçersiz: %q", p)
			}
		}
	case trust.ProtocolAny, trust.ProtocolICMP:
		if len(ports) != 0 {
			return errors.New("any ve icmp port almaz")
		}
	default:
		return fmt.Errorf("protokol tcp, udp, icmp veya any olmalı: %q", proto)
	}
	return nil
}

// Build computes the plan of template kind for doc. doc is not changed.
func Build(doc *trust.Document, kind Kind, p Params) (Plan, error) {
	if doc == nil {
		return Plan{}, errors.New("ağ belgesi yok")
	}
	if p.Isolate && kind != IoTIsolation {
		return Plan{}, errors.New("yalıtım seçeneği yalnızca IoT yalıtımı şablonunda kullanılır")
	}
	subj, ok := members(doc, p.Subject)
	if kind == IoTIsolation && isRangeEntry(p.Subject) {
		// A CIDR or "host:" range of smart devices (#243, iot_routed.go).
		pfx, routed, err := iotRange(doc, p.Subject)
		if err != nil {
			return Plan{}, err
		}
		if routed {
			return buildIoTRouted(doc, p, pfx)
		}
		subj, ok = devicesIn(doc, pfx), true
	}
	if !ok || len(subj) == 0 {
		return Plan{}, ErrSubject
	}
	if len(subj) > maxSubjectDevices {
		return Plan{}, fmt.Errorf("şablon en fazla %d cihaza uygulanabilir", maxSubjectDevices)
	}
	if p.Protocol == "" {
		p.Protocol = trust.ProtocolTCP
	}
	needsTargets := kind == NASOnly || kind == Guest || kind == IoTIsolation
	if needsTargets {
		if len(p.Targets) == 0 {
			return Plan{}, ErrNoTargets
		}
		if len(p.Targets) > maxTargets {
			return Plan{}, fmt.Errorf("en fazla %d hedef", maxTargets)
		}
		for _, t := range p.Targets {
			ms, ok := members(doc, t)
			if !ok || len(ms) == 0 {
				return Plan{}, fmt.Errorf("hedef bulunamadı: %q", t)
			}
			for _, m := range ms {
				if slices.Contains(subj, m) {
					return Plan{}, fmt.Errorf("hedef %q konunun kendisi", m)
				}
			}
		}
		if err := validPorts(p.Protocol, p.Ports); err != nil {
			return Plan{}, err
		}
	}
	if !p.Until.IsZero() && kind != Guest {
		return Plan{}, errors.New("bitiş zamanı yalnızca misafir şablonunda kullanılır")
	}
	desc := descPrefix + string(kind) + " (" + p.Subject + ")"
	if len(desc) > 256 || strings.IndexFunc(desc, unicode.IsControl) >= 0 {
		return Plan{}, ErrSubject
	}
	service := func(from, to []string) trust.Rule {
		return trust.Rule{From: from, To: to, Protocol: p.Protocol, Ports: slices.Clone(p.Ports), Description: desc}
	}
	var add []trust.Rule
	narrowOutbound := false
	needExit := false
	switch kind {
	case InternetOnly:
		add = append(add, trust.Rule{From: []string{p.Subject}, To: []string{trust.RuleWildcard}, Protocol: trust.ProtocolAny, Action: trust.RuleDeny, Description: desc})
		needExit = true
	case NASOnly:
		add = append(add, service([]string{p.Subject}, slices.Clone(p.Targets)))
		narrowOutbound = true
	case Guest:
		r := service([]string{p.Subject}, slices.Clone(p.Targets))
		deny := trust.Rule{From: []string{trust.RuleWildcard}, To: []string{p.Subject}, Protocol: trust.ProtocolAny, Action: trust.RuleDeny, Description: desc}
		if !p.Until.IsZero() {
			r.NotAfter, deny.NotAfter = p.Until.UTC(), p.Until.UTC()
		}
		add = append(add, r, deny)
		narrowOutbound, needExit = true, true
	case IoTIsolation:
		add = append(add,
			trust.Rule{From: slices.Clone(p.Targets), To: []string{p.Subject}, Protocol: trust.ProtocolAny, Description: desc},
			service([]string{p.Subject}, slices.Clone(p.Targets)))
		if p.Isolate && len(subj) > 1 {
			// The subject devices may not reach each other (#243).
			add = append(add, trust.Rule{From: []string{p.Subject}, To: []string{p.Subject}, Protocol: trust.ProtocolAny, Action: trust.RuleDeny, Description: desc})
		}
		narrowOutbound = true
	case AdminEverywhere:
		add = append(add, trust.Rule{From: []string{p.Subject}, To: []string{trust.RuleWildcard}, Protocol: trust.ProtocolAny, Description: desc})
	case Quarantine:
		add = append(add,
			trust.Rule{From: []string{p.Subject}, To: []string{trust.RuleWildcard}, Protocol: trust.ProtocolAny, Action: trust.RuleDeny, Description: desc},
			trust.Rule{From: []string{trust.RuleWildcard}, To: []string{p.Subject}, Protocol: trust.ProtocolAny, Action: trust.RuleDeny, Description: desc})
	default:
		return Plan{}, ErrUnknownKind
	}

	plan := Plan{Kind: kind, Base: baseDigest(doc)}
	rules := slices.Clone(doc.Rules)
	for _, r := range add {
		if !containsRule(rules, r) {
			plan.Added = append(plan.Added, r)
		}
	}
	if narrowOutbound {
		plan.Disabled, plan.Warnings = conflicts(doc, subj)
		for _, i := range plan.Disabled {
			rules[i].Disabled = true
		}
	}
	if kind == AdminEverywhere && !strings.Contains(p.Subject, ":") {
		if d, _ := doc.DeviceByName(p.Subject); !d.HasRole(trust.RoleAdmin) {
			plan.Warnings = append(plan.Warnings, p.Subject+" yönetici rolünde değil; her yere erişim yalnızca güvendiğiniz bir cihaza verilmeli.")
		}
	}
	rules = append(rules, plan.Added...)
	plan.Rules = rules
	if needExit {
		if users, changed := withExitUsers(doc, p.Subject, subj); changed {
			plan.ExitUsers, plan.ExitUsersChanged = users, true
		}
	}
	if kind == IoTIsolation && p.Isolate {
		// No internet through exit nodes for the subject (#243).
		users, changed, warn := withoutExitUsers(doc, p.Subject, subj)
		if changed {
			plan.ExitUsers, plan.ExitUsersChanged = users, true
		}
		plan.Warnings = append(plan.Warnings, warn...)
	}
	if len(plan.Added) == 0 && len(plan.Disabled) == 0 && !plan.ExitUsersChanged {
		return plan, ErrNoChange
	}
	plan.Reach, plan.ReachTruncated = reach(doc, plan, subj, p)
	return plan, nil
}

func containsRule(rules []trust.Rule, r trust.Rule) bool {
	for _, x := range rules {
		if !x.Disabled && x.Action == r.Action && x.Protocol == r.Protocol && x.Service == r.Service &&
			slices.Equal(x.From, r.From) && slices.Equal(x.To, r.To) && slices.Equal(x.Ports, r.Ports) &&
			x.NotAfter.Equal(r.NotAfter) && x.NotBefore.Equal(r.NotBefore) && x.Schedule == nil && !x.Bidirectional {
			return true
		}
	}
	return false
}

// conflicts finds the enabled allow rules through which a subject device
// can open connections. Rules whose sources are all subject devices are
// disabled; broader ones become warnings.
func conflicts(doc *trust.Document, subj []string) (disabled []int, warnings []string) {
	devs := make([]trust.Device, 0, len(subj))
	for _, n := range subj {
		if d, ok := doc.DeviceByName(n); ok {
			devs = append(devs, d)
		}
	}
	for i, r := range doc.Rules {
		if r.Disabled || r.IsDeny() {
			continue
		}
		sources := r.From
		if r.Bidirectional {
			sources = append(slices.Clone(r.From), r.To...)
		}
		hit := false
		for _, d := range devs {
			for _, e := range sources {
				if covers(doc, e, d) {
					hit = true
					break
				}
			}
			if hit {
				break
			}
		}
		if !hit {
			continue
		}
		if onlySubject(doc, sources, subj) {
			disabled = append(disabled, i)
			continue
		}
		warnings = append(warnings, fmt.Sprintf("Kural %d (%s) konuyu da kapsıyor ve başka cihazlara da izin veriyor; bu şablondan sonra da geçerli kalır.", i+1, ruleLabel(r)))
	}
	return disabled, warnings
}

func onlySubject(doc *trust.Document, entries []string, subj []string) bool {
	for _, e := range entries {
		ms, ok := members(doc, e)
		if !ok {
			return false
		}
		for _, m := range ms {
			if !slices.Contains(subj, m) {
				return false
			}
		}
	}
	return true
}

func ruleLabel(r trust.Rule) string {
	if r.Description != "" {
		return r.Description
	}
	what := string(r.Protocol)
	if r.Service != "" {
		what = string(r.Service)
	}
	return strings.Join(r.From, ",") + " -> " + strings.Join(r.To, ",") + " " + what
}

// withExitUsers returns exit_users with the subject added when the list
// exists and does not cover every subject device yet.
func withExitUsers(doc *trust.Document, entry string, subj []string) ([]string, bool) {
	users, limited := doc.ExitUsersList()
	if !limited {
		return nil, false
	}
	for _, n := range subj {
		if !doc.MayUseExitNode(n) {
			if slices.Contains(users, entry) {
				return nil, false
			}
			return append(slices.Clone(users), entry), true
		}
	}
	return nil, false
}

type probe struct {
	name  string
	proto trust.Protocol
	port  uint16
}

var defaultProbes = []probe{
	{"tcp/22", trust.ProtocolTCP, 22},
	{"tcp/80", trust.ProtocolTCP, 80},
	{"tcp/443", trust.ProtocolTCP, 443},
	{"tcp/445", trust.ProtocolTCP, 445},
	{"tcp/3389", trust.ProtocolTCP, 3389},
	{"icmp", trust.ProtocolICMP, 0},
}

func reach(doc *trust.Document, plan Plan, subj []string, p Params) ([]ReachChange, bool) {
	probes := slices.Clone(defaultProbes)
	if p.Protocol == trust.ProtocolTCP || p.Protocol == trust.ProtocolUDP {
		for _, spec := range p.Ports {
			lo, _, err := trust.ParsePortRange(spec)
			if err != nil {
				continue
			}
			name := fmt.Sprintf("%s/%d", p.Protocol, lo)
			if !slices.ContainsFunc(probes, func(x probe) bool { return x.name == name }) {
				probes = append(probes, probe{name, p.Protocol, lo})
			}
		}
	}
	after := *doc
	after.Rules = plan.Rules
	var out []ReachChange
	add := func(from, to string) bool {
		for _, pr := range probes {
			b, a := doc.Allows(from, to, pr.proto, pr.port), after.Allows(from, to, pr.proto, pr.port)
			if a == b {
				continue
			}
			if len(out) >= maxReach {
				return false
			}
			out = append(out, ReachChange{From: from, To: to, Probe: pr.name, Before: b, After: a})
		}
		return true
	}
	for _, s := range subj {
		for _, d := range doc.Devices {
			if d.Name == s {
				continue
			}
			if !add(s, d.Name) || (!slices.Contains(subj, d.Name) && !add(d.Name, s)) {
				return out, true
			}
		}
	}
	return out, false
}

// ErrStale is returned when the document changed after the preview.
var ErrStale = errors.New("kurallar önizlemeden sonra değişmiş; şablonu yeniden önizleyin")

// baseDigest fingerprints the parts of the document a plan replaces.
func baseDigest(doc *trust.Document) string {
	data, err := json.Marshal(struct {
		Rules     []trust.Rule `json:"r"`
		ExitUsers *[]string    `json:"e"`
	}{doc.Rules, doc.ExitUsers})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Apply writes the plan into doc (the owner's working copy before
// signing) through the document's own validating edit functions:
// disabling rules, adding rules and changing exit_users. It refuses a plan
// previewed against different rules and restores doc when any step fails.
func (p Plan) Apply(doc *trust.Document) error {
	if doc == nil {
		return errors.New("ağ belgesi yok")
	}
	if p.Base == "" || baseDigest(doc) != p.Base {
		return ErrStale
	}
	rules := slices.Clone(doc.Rules)
	var exit *[]string
	if doc.ExitUsers != nil {
		cp := slices.Clone(*doc.ExitUsers)
		exit = &cp
	}
	restore := func(err error) error {
		doc.Rules, doc.ExitUsers = rules, exit
		return err
	}
	if p.ExitUsersChanged {
		if err := doc.SetExitUsers(p.ExitUsers); err != nil {
			return restore(err)
		}
	}
	for _, i := range p.Disabled {
		if err := doc.SetRuleDisabled(i, true); err != nil {
			return restore(err)
		}
	}
	for _, r := range p.Added {
		if err := doc.AddRule(r); err != nil {
			return restore(fmt.Errorf("şablon kuralı eklenemedi: %w", err))
		}
	}
	return nil
}
