package trust

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Document schema additions of ADR-0232: device icons (#233), address
// ranges in groups, exit_users and via (#277) and support rules (#852).
//
// Every addition is optional and omitted when unset, so a document that
// uses none of them encodes byte for byte as before. Older clients decode
// the signed payload strictly and reject an unknown field, a range where
// they expect a device name or an unknown service; a document that uses an
// addition is therefore only valid with min_client_version at least
// SchemaV2MinClientVersion, and the owner's tooling raises it by itself
// when it signs such a document (admin.Network.Prepare).

// SchemaV2MinClientVersion is the first client that understands every
// ADR-0232 addition.
const SchemaV2MinClientVersion = "1.0.0-beta.2"

// Errors of the ADR-0232 additions.
var (
	ErrUnknownIcon        = errors.New("unknown device icon")
	ErrSchemaNeedsClients = errors.New("document uses fields older clients reject")
)

// SchemaV2Features lists the ADR-0232 additions doc uses, in a fixed order.
func (doc *Document) SchemaV2Features() []string {
	var out []string
	for _, d := range doc.Devices {
		if d.Icon != "" {
			out = append(out, "device icons")
			break
		}
	}
	for _, g := range doc.Groups {
		if len(addrMembers(g.Members)) > 0 {
			out = append(out, "address ranges in groups")
			break
		}
	}
	if doc.ExitUsers != nil && len(addrMembers(*doc.ExitUsers)) > 0 {
		out = append(out, "address ranges in exit_users")
	}
	via, support := false, false
	for _, r := range doc.Rules {
		via = via || len(addrMembers(r.Via)) > 0
		support = support || r.Service == ServiceSupport || r.AllowKill
	}
	for _, t := range doc.PolicyTests {
		support = support || t.Service == ServiceSupport
	}
	if via {
		out = append(out, "address ranges in via")
	}
	if support {
		out = append(out, "support rules")
	}
	return out
}

// RaiseMinClientForSchema raises min_client_version to
// SchemaV2MinClientVersion when doc uses an ADR-0232 addition and the
// current minimum is lower or unset. It never lowers a minimum and reports
// whether it changed doc.
func RaiseMinClientForSchema(doc *Document) bool {
	if doc == nil || len(doc.SchemaV2Features()) == 0 || MinVersionAtLeast(doc.MinClientVersion, SchemaV2MinClientVersion) {
		return false
	}
	doc.MinClientVersion = SchemaV2MinClientVersion
	return true
}

// validateF4A checks the ADR-0232 additions. Validate calls it last, after
// the named addresses are known to be valid.
func (doc *Document) validateF4A() error {
	if err := doc.validateIcons(); err != nil {
		return err
	}
	if err := doc.validateRanges(); err != nil {
		return err
	}
	if f := doc.SchemaV2Features(); len(f) > 0 && !MinVersionAtLeast(doc.MinClientVersion, SchemaV2MinClientVersion) {
		return fmt.Errorf("%w (%s): min_client_version must be at least %s", ErrSchemaNeedsClients, strings.Join(f, ", "), SchemaV2MinClientVersion)
	}
	return nil
}

// addrMembers returns the CIDR and "host:" entries of a list.
func addrMembers(entries []string) []string {
	var out []string
	for _, e := range entries {
		if isAddrEntry(e) {
			out = append(out, e)
		}
	}
	return out
}

// validateRanges checks the range entries of groups, exit_users and via.
// Group ranges may lie inside the network prefixes or an approved subnet
// route (cameras behind a router); exit_users and via name OpenScale
// devices, so their ranges must lie inside the network prefixes.
func (doc *Document) validateRanges() error {
	for _, g := range doc.Groups {
		for _, m := range addrMembers(g.Members) {
			if err := doc.checkRangeEntry("group "+g.Name, m, false); err != nil {
				return err
			}
		}
	}
	if doc.ExitUsers != nil {
		for _, e := range addrMembers(*doc.ExitUsers) {
			if err := doc.checkRangeEntry("exit_users", e, true); err != nil {
				return err
			}
		}
	}
	for i, r := range doc.Rules {
		for _, e := range addrMembers(r.Via) {
			if err := doc.checkRangeEntry(fmt.Sprintf("rule %d via", i), e, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func (doc *Document) checkRangeEntry(field, e string, overlayOnly bool) error {
	var p netip.Prefix
	if h, ok := strings.CutPrefix(e, HostPrefix); ok {
		found := false
		for _, n := range doc.Hosts {
			if n.Name == h {
				p, found = n.Prefix, true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s references unknown named address %q", field, h)
		}
	} else {
		parsed, err := netip.ParsePrefix(e)
		if err != nil {
			return fmt.Errorf("%s: %q is not a CIDR range", field, e)
		}
		if err := doc.validateOverlayPrefix(field, parsed, e); err != nil {
			return err
		}
		p = parsed
	}
	if overlayOnly && !doc.insideOverlay(p) {
		return fmt.Errorf("%s: %s must lie inside the network prefixes; it names OpenScale devices", field, e)
	}
	return nil
}

// NormalizeAddrEntry turns a bare IP address typed by the owner into its
// single-address CIDR ("100.80.0.5" -> "100.80.0.5/32"). Every other entry
// is returned trimmed and unchanged; validation decides about it. The
// document itself only ever holds CIDR or "host:" entries.
func NormalizeAddrEntry(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") || strings.HasPrefix(s, HostPrefix) {
		return s
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	return s
}

// --- client versions with a beta suffix ---

// parseMinVersion parses a minimum client version: "1.2.3" or
// "1.2.3-beta.N" (N >= 1, no leading zeros). beta is 0 for a release.
func parseMinVersion(s string) (base [3]int, beta int, ok bool) {
	core, pre, hasPre := strings.Cut(s, "-")
	base, ok = parseStrictVersion(core)
	if !ok || !hasPre {
		return base, 0, ok
	}
	n, ok := betaNumber(pre)
	if !ok {
		return base, 0, false
	}
	return base, n, true
}

// betaNumber parses "beta.N".
func betaNumber(pre string) (int, bool) {
	num, ok := strings.CutPrefix(pre, "beta.")
	if !ok || num == "" || len(num) > 5 || num[0] == '0' {
		return 0, false
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

// reportedBeta returns N of a reported version's "-beta.N" suffix, or 0
// for a release or any other suffix (which counts as the release itself,
// as before ADR-0232).
func reportedBeta(have string) int {
	s := strings.TrimPrefix(strings.TrimSpace(have), "v")
	i := strings.Index(s, "-beta.")
	if i < 0 {
		return 0
	}
	rest := s[i+len("-beta."):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	n, ok := betaNumber("beta." + rest[:end])
	if !ok {
		return 0
	}
	return n
}

// compareMin orders two parsed minimum versions; a release is newer than
// every beta of the same numbers.
func compareMin(a [3]int, ab int, b [3]int, bb int) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case ab == bb:
		return 0
	case ab == 0:
		return 1
	case bb == 0:
		return -1
	case ab < bb:
		return -1
	}
	return 1
}

// MinVersionAtLeast reports whether the minimum client version min is at
// least need. An empty or invalid min is never enough.
func MinVersionAtLeast(min, need string) bool {
	a, ab, ok := parseMinVersion(min)
	if !ok || min == "" {
		return false
	}
	b, bb, ok := parseMinVersion(need)
	if !ok {
		return false
	}
	return compareMin(a, ab, b, bb) >= 0
}
