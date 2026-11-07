package trust

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// MagicDNS zone extensions (ADR-0034, F-053, F-054, F-055, #39, #97):
// search domains, extra records under the network domain, extra names for
// devices and device subdomains. Every field is optional and omitted when
// empty, so documents without them encode exactly as before.

// Limits of the MagicDNS zone extensions.
const (
	MaxSearchDomains = 8
	MaxDNSRecords    = 256
	MaxDeviceAliases = 8
	maxTXTLength     = 255
	// maxCNAMEChain bounds a chain of in-zone CNAME records; longer chains
	// are rejected by Validate and never followed further by MagicDNS.
	maxCNAMEChain = 8
)

// DNS record types that may appear in the zone.
const (
	RecordA     = "A"
	RecordAAAA  = "AAAA"
	RecordCNAME = "CNAME"
	RecordSRV   = "SRV"
	RecordTXT   = "TXT"
)

// MagicDNSSettings is the optional magic_dns section of the document.
type MagicDNSSettings struct {
	// Search lists domains appended to short names ("ssh masaustu"):
	// the network domain or a split DNS domain, so a short name is never
	// sent to a resolver outside the network's own settings.
	Search []string `json:"search,omitempty"`
	// Records are extra names under the network domain.
	Records []DNSRecord `json:"records,omitempty"`
	// DeviceSubdomains makes every name below a device ("web.nas.<alan>")
	// resolve to that device (F-055).
	DeviceSubdomains bool `json:"device_subdomains,omitempty"`
}

// DNSRecord is one record under the network domain. Name is relative to
// the domain ("nas", "_rdp._tcp.masaustu", "*.lab"); a leading "*" label
// is a wildcard for every name below the rest.
type DNSRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Value is the address (A, AAAA), the target name (CNAME, SRV; absolute,
	// without the trailing dot) or the text (TXT).
	Value    string `json:"value"`
	Priority uint16 `json:"priority,omitempty"`
	Weight   uint16 `json:"weight,omitempty"`
	Port     uint16 `json:"port,omitempty"`
}

// SetMagicDNS replaces the magic_dns section; nil removes it. The
// settings are copied.
func (doc *Document) SetMagicDNS(s *MagicDNSSettings) error {
	var next *MagicDNSSettings
	if s != nil {
		next = &MagicDNSSettings{
			Search:           slices.Clone(s.Search),
			Records:          slices.Clone(s.Records),
			DeviceSubdomains: s.DeviceSubdomains,
		}
	}
	return doc.transact(func() error {
		doc.MagicDNS = next
		return nil
	})
}

// SetDeviceAliases replaces the extra MagicDNS names of a device (#39,
// F-055); an empty list removes them.
func (doc *Document) SetDeviceAliases(name string, aliases []string) error {
	idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.Name == name })
	if idx < 0 {
		return ErrUnknownDevice
	}
	var next []string
	if len(aliases) > 0 {
		next = slices.Clone(aliases)
	}
	return doc.transact(func() error {
		doc.Devices[idx].Aliases = next
		return nil
	})
}

// zoneNames returns every owner name of the zone that is not a record:
// the coordinator, device names and aliases, relative to the domain.
func (doc *Document) zoneNames() map[string]bool {
	names := make(map[string]bool, 2*len(doc.Devices)+1)
	if doc.Coordinator != nil {
		names[CoordinatorName] = true
	}
	for _, d := range doc.Devices {
		names[d.Name] = true
		for _, a := range d.Aliases {
			names[a] = true
		}
	}
	return names
}

// validateAliases checks device aliases: lowercase labels, unique across
// every device name and alias, never the coordinator's name.
func (doc *Document) validateAliases() error {
	owner := make(map[string]string, 2*len(doc.Devices))
	for _, d := range doc.Devices {
		owner[d.Name] = d.Name
	}
	for _, d := range doc.Devices {
		if len(d.Aliases) > MaxDeviceAliases {
			return fmt.Errorf("device %s: at most %d aliases are allowed", d.Name, MaxDeviceAliases)
		}
		for _, a := range d.Aliases {
			switch {
			case !isValidLabel(a):
				return fmt.Errorf("device %s: alias %q must be a lowercase DNS label", d.Name, a)
			case a == CoordinatorName:
				return fmt.Errorf("device %s: alias %q is reserved", d.Name, a)
			}
			if prev, taken := owner[a]; taken {
				return fmt.Errorf("device %s: alias %q is already used by %s", d.Name, a, prev)
			}
			owner[a] = d.Name
		}
	}
	return nil
}

// validateMagicDNS checks the magic_dns section against the devices and
// the dns section.
func (doc *Document) validateMagicDNS() error {
	if err := doc.validateAliases(); err != nil {
		return err
	}
	s := doc.MagicDNS
	if s == nil {
		return nil
	}
	if len(s.Search) == 0 && len(s.Records) == 0 && !s.DeviceSubdomains {
		return errors.New("magic_dns section is empty; remove it instead")
	}
	if err := doc.validateSearch(s.Search); err != nil {
		return err
	}
	return doc.validateRecords(s.Records)
}

// validateSearch allows only the network domain and split DNS domains:
// a search domain makes the OS try every short name under it, and those
// names must go only to resolvers the network chose.
func (doc *Document) validateSearch(search []string) error {
	if len(search) > MaxSearchDomains {
		return fmt.Errorf("magic_dns search allows at most %d domains", MaxSearchDomains)
	}
	allowed := map[string]bool{doc.DNSDomain: true}
	if doc.DNS != nil {
		for _, e := range doc.DNS.Split {
			allowed[e.Domain] = true
		}
	}
	seen := make(map[string]bool, len(search))
	for _, d := range search {
		if !allowed[d] {
			return fmt.Errorf("magic_dns search domain %q must be the network domain or a split DNS domain", d)
		}
		if seen[d] {
			return fmt.Errorf("magic_dns search domain %q is listed twice", d)
		}
		seen[d] = true
	}
	return nil
}

func (doc *Document) validateRecords(records []DNSRecord) error {
	if len(records) > MaxDNSRecords {
		return fmt.Errorf("magic_dns allows at most %d records", MaxDNSRecords)
	}
	owners := doc.zoneNames()
	seen := make(map[DNSRecord]bool, len(records))
	byName := make(map[string][]string, len(records)) // name -> types
	for i, r := range records {
		if err := doc.validateRecord(r, owners); err != nil {
			return fmt.Errorf("magic_dns record %d (%s %s): %w", i, r.Name, r.Type, err)
		}
		if seen[r] {
			return fmt.Errorf("magic_dns record %d (%s %s) is listed twice", i, r.Name, r.Type)
		}
		seen[r] = true
		byName[r.Name] = append(byName[r.Name], r.Type)
	}
	for name, types := range byName {
		if slices.Contains(types, RecordCNAME) && len(types) > 1 {
			return fmt.Errorf("magic_dns name %q has a CNAME and other records", name)
		}
	}
	// In-zone targets must exist, so a name never silently points at a
	// device that takes a revoked or renamed device's name later.
	exists := func(rel string) bool {
		if owners[rel] {
			return true
		}
		_, ok := byName[rel]
		return ok
	}
	for i, r := range records {
		if r.Type != RecordCNAME && r.Type != RecordSRV {
			continue
		}
		rel, inZone := doc.relativeName(r.Value)
		if !inZone {
			continue
		}
		if rel == "" || !exists(rel) {
			return fmt.Errorf("magic_dns record %d (%s %s): target %q does not exist in the network domain", i, r.Name, r.Type, r.Value)
		}
	}
	return doc.checkCNAMEChains(records)
}

func (doc *Document) validateRecord(r DNSRecord, owners map[string]bool) error {
	wildcard, err := checkRecordName(r.Name)
	if err != nil {
		return err
	}
	if len(r.Name)+1+len(doc.DNSDomain) > maxDomainLength {
		return errors.New("name is too long")
	}
	if !wildcard && (owners[r.Name] || r.Name == CoordinatorName) {
		return errors.New("name belongs to a device or the coordinator")
	}
	if r.Type != RecordSRV && (r.Priority != 0 || r.Weight != 0 || r.Port != 0) {
		return errors.New("priority, weight and port are only for SRV records")
	}
	switch r.Type {
	case RecordA, RecordAAAA:
		a, err := netip.ParseAddr(r.Value)
		if err != nil || a.String() != r.Value || a.Zone() != "" || a.Is4In6() {
			return errors.New("value must be an address in canonical form")
		}
		if (r.Type == RecordA) != a.Is4() {
			return errors.New("A needs an IPv4 and AAAA an IPv6 address")
		}
		if a.IsUnspecified() || a.IsMulticast() {
			return errors.New("value must be a unicast address")
		}
		if doc.IPv4Prefix.Contains(a) || doc.IPv6Prefix.Contains(a) {
			// Inside the network only a current address: a record must
			// not follow an address to whichever device gets it next.
			if !doc.isMemberAddr(a) {
				return errors.New("an address inside the network must belong to a device or the coordinator")
			}
		}
	case RecordCNAME, RecordSRV:
		if !isValidHostname(r.Value) {
			return errors.New("target must be a lowercase domain name without the trailing dot")
		}
		if rel, inZone := doc.relativeName(r.Value); inZone && rel == r.Name {
			return errors.New("record points at itself")
		}
		if r.Type == RecordSRV && r.Port == 0 {
			return errors.New("SRV needs a port")
		}
		if r.Type == RecordCNAME && wildcard {
			return errors.New("wildcard CNAME records are not supported")
		}
	case RecordTXT:
		if r.Value == "" || len(r.Value) > maxTXTLength {
			return fmt.Errorf("text must be 1-%d characters", maxTXTLength)
		}
		for i := 0; i < len(r.Value); i++ {
			if c := r.Value[i]; c < 0x20 || c > 0x7e {
				return errors.New("text must be printable ASCII")
			}
		}
	default:
		return fmt.Errorf("unsupported record type %q", r.Type)
	}
	return nil
}

// checkCNAMEChains rejects in-zone CNAME loops and chains longer than
// MagicDNS follows.
func (doc *Document) checkCNAMEChains(records []DNSRecord) error {
	next := make(map[string]string)
	for _, r := range records {
		if r.Type != RecordCNAME {
			continue
		}
		if rel, inZone := doc.relativeName(r.Value); inZone {
			next[r.Name] = rel
		}
	}
	for start := range next {
		cur, steps := start, 0
		for {
			n, ok := next[cur]
			if !ok {
				break
			}
			steps++
			if steps > maxCNAMEChain {
				return fmt.Errorf("magic_dns CNAME chain from %q loops or is longer than %d", start, maxCNAMEChain)
			}
			cur = n
		}
	}
	return nil
}

// isMemberAddr reports whether a is a device's or the coordinator's
// tunnel address.
func (doc *Document) isMemberAddr(a netip.Addr) bool {
	if c := doc.Coordinator; c != nil && (c.IPv4 == a || c.IPv6 == a) {
		return true
	}
	for _, d := range doc.Devices {
		if d.IPv4 == a || d.IPv6 == a {
			return true
		}
	}
	return false
}

// relativeName returns name relative to the network domain ("" for the
// apex) and whether it is inside the domain.
func (doc *Document) relativeName(name string) (string, bool) {
	if name == doc.DNSDomain {
		return "", true
	}
	rel, ok := strings.CutSuffix(name, "."+doc.DNSDomain)
	return rel, ok
}

// checkRecordName accepts lowercase labels, labels starting with "_" for
// service names ("_rdp._tcp") and a leading "*" wildcard label followed by
// at least one more label.
func checkRecordName(name string) (wildcard bool, err error) {
	if name == "" || len(name) > maxDomainLength {
		return false, errors.New("name is empty or too long")
	}
	labels := strings.Split(name, ".")
	for i, l := range labels {
		if i == 0 && l == "*" {
			if len(labels) == 1 {
				return false, errors.New("a wildcard needs a name after \"*.\"")
			}
			wildcard = true
			continue
		}
		if !isValidLabel(strings.TrimPrefix(l, "_")) {
			return false, fmt.Errorf("name %q is not a lowercase DNS name", name)
		}
	}
	return wildcard, nil
}

// isValidHostname reports whether s is a lowercase domain name of one or
// more labels (service labels starting with "_" allowed).
func isValidHostname(s string) bool {
	if s == "" || len(s) > maxDomainLength {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !isValidLabel(strings.TrimPrefix(l, "_")) {
			return false
		}
	}
	return true
}

// renameDNSRefs follows a device rename in the zone: records below the old
// name and targets naming it move to the new name.
func (doc *Document) renameDNSRefs(oldName, newName string) {
	s := doc.MagicDNS
	if s == nil {
		return
	}
	oldFQDN, newFQDN := oldName+"."+doc.DNSDomain, newName+"."+doc.DNSDomain
	for i := range s.Records {
		r := &s.Records[i]
		if base, ok := strings.CutSuffix(r.Name, "."+oldName); ok {
			r.Name = base + "." + newName
		}
		if r.Type == RecordCNAME || r.Type == RecordSRV {
			if r.Value == oldFQDN {
				r.Value = newFQDN
			} else if base, ok := strings.CutSuffix(r.Value, "."+oldFQDN); ok {
				r.Value = base + "." + newFQDN
			}
		}
	}
}

// dropDNSRefs removes the records that depend on a revoked device: those
// with its addresses, those below its name or aliases, and then every
// record whose in-zone target no longer exists. An empty section is
// removed.
func (doc *Document) dropDNSRefs(d Device) {
	s := doc.MagicDNS
	if s == nil {
		return
	}
	gone := append([]string{d.Name}, d.Aliases...)
	below := func(name string) bool {
		for _, g := range gone {
			if name == g || strings.HasSuffix(name, "."+g) {
				return true
			}
		}
		return false
	}
	s.Records = slices.DeleteFunc(s.Records, func(r DNSRecord) bool {
		if r.Type == RecordA || r.Type == RecordAAAA {
			if a, err := netip.ParseAddr(r.Value); err == nil && (a == d.IPv4 || a == d.IPv6) {
				return true
			}
		}
		return below(r.Name)
	})
	// Drop dangling targets until nothing changes (chains of records).
	owners := doc.zoneNames()
	for {
		names := make(map[string]bool, len(s.Records))
		for _, r := range s.Records {
			names[r.Name] = true
		}
		before := len(s.Records)
		s.Records = slices.DeleteFunc(s.Records, func(r DNSRecord) bool {
			if r.Type != RecordCNAME && r.Type != RecordSRV {
				return false
			}
			rel, inZone := doc.relativeName(r.Value)
			return inZone && !owners[rel] && !names[rel]
		})
		if len(s.Records) == before {
			break
		}
	}
	if len(s.Records) == 0 {
		s.Records = nil
	}
	if len(s.Search) == 0 && len(s.Records) == 0 && !s.DeviceSubdomains {
		doc.MagicDNS = nil
	}
}

// pruneSearch removes search domains that are no longer the network
// domain or a split DNS domain, so removing a split domain never fails
// because of the search list.
func (doc *Document) pruneSearch() {
	s := doc.MagicDNS
	if s == nil || len(s.Search) == 0 {
		return
	}
	if doc.validateSearch(s.Search) == nil {
		return
	}
	allowed := map[string]bool{doc.DNSDomain: true}
	if doc.DNS != nil {
		for _, e := range doc.DNS.Split {
			allowed[e.Domain] = true
		}
	}
	s.Search = slices.DeleteFunc(s.Search, func(d string) bool { return !allowed[d] })
	if len(s.Search) == 0 {
		s.Search = nil
	}
	if len(s.Search) == 0 && len(s.Records) == 0 && !s.DeviceSubdomains {
		doc.MagicDNS = nil
	}
}
