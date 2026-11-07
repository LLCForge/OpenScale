package netprofile

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/openscale/openscale/internal/member"
)

// Several networks at the same time (#500, ADR-0164). Each network keeps
// its own state directory (ADR-0135); running two of them at once needs a
// tunnel interface per network and address ranges that do not overlap,
// otherwise routes, the firewall filter and the MagicDNS resolver address
// (derived from the range) of one network would capture the other's
// traffic. CheckConcurrent decides whether a set of profiles can be up
// together and names an interface for each; it changes nothing.

// MaxConcurrent bounds the networks open at the same time.
const MaxConcurrent = 4

// PrimaryInterface is the interface name of the first network; it is the
// default of "openscale up".
const PrimaryInterface = "OpenScale"

// ConcurrentProfile is one network of a concurrent plan.
type ConcurrentProfile struct {
	Name      string       `json:"name"`
	Dir       string       `json:"dir"`
	NetworkID string       `json:"network_id"`
	Interface string       `json:"interface"`
	IPv4      netip.Prefix `json:"ipv4"`
	IPv6      netip.Prefix `json:"ipv6,omitempty"`
	DNSDomain string       `json:"dns_domain"`
	// Primary is the one network that may use an exit node and the kill
	// switch; both are system wide.
	Primary bool `json:"primary,omitempty"`
}

// ConcurrentPlan is the result of CheckConcurrent.
type ConcurrentPlan struct {
	Profiles []ConcurrentProfile `json:"profiles"`
	// Conflicts make the set unusable together; empty means it can run.
	Conflicts []string `json:"conflicts,omitempty"`
}

// OK reports whether the profiles can be up together.
func (p ConcurrentPlan) OK() bool { return len(p.Conflicts) == 0 }

// ConcurrentInterface names the tunnel interface of a non-primary
// network: "os-<name>", at most 15 bytes (the Linux IFNAMSIZ limit).
func ConcurrentInterface(name string) string {
	n := "os-" + name
	if len(n) > 15 {
		n = n[:15]
	}
	return strings.TrimRight(n, "-")
}

// CheckConcurrent loads the named profiles (the first is the primary) and
// reports every conflict between them.
func CheckConcurrent(base string, names []string) (ConcurrentPlan, error) {
	if len(names) < 2 {
		return ConcurrentPlan{}, errors.New("at least two network profiles are needed")
	}
	if len(names) > MaxConcurrent {
		return ConcurrentPlan{}, fmt.Errorf("at most %d networks can be open together", MaxConcurrent)
	}
	var plan ConcurrentPlan
	seen := map[string]bool{}
	ifaces := map[string]string{}
	for i, name := range names {
		if seen[name] {
			return ConcurrentPlan{}, fmt.Errorf("network profile %q is listed twice", name)
		}
		seen[name] = true
		dir, err := Resolve(base, name, false)
		if err != nil {
			return ConcurrentPlan{}, err
		}
		s, err := member.Open(dir)
		if err != nil {
			if errors.Is(err, member.ErrNotJoined) {
				return ConcurrentPlan{}, fmt.Errorf("%w: %q", ErrNotJoined, name)
			}
			return ConcurrentPlan{}, fmt.Errorf("network profile %q: %w", name, err)
		}
		doc := s.Document()
		if doc == nil {
			return ConcurrentPlan{}, fmt.Errorf("network profile %q has no document", name)
		}
		cp := ConcurrentProfile{Name: name, Dir: dir, NetworkID: s.Anchor().NetworkID, IPv4: doc.IPv4Prefix,
			IPv6: doc.IPv6Prefix, DNSDomain: strings.ToLower(doc.DNSDomain), Primary: i == 0}
		if cp.Primary {
			cp.Interface = PrimaryInterface
		} else {
			cp.Interface = ConcurrentInterface(name)
		}
		if other, ok := ifaces[strings.ToLower(cp.Interface)]; ok {
			plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("%q ve %q aynı arayüz adını alıyor (%s); profillerden birini yeniden adlandırın", other, name, cp.Interface))
		}
		ifaces[strings.ToLower(cp.Interface)] = name
		plan.Profiles = append(plan.Profiles, cp)
	}
	ps := plan.Profiles
	for i := range ps {
		for j := i + 1; j < len(ps); j++ {
			a, b := ps[i], ps[j]
			if a.NetworkID == b.NetworkID {
				plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("%q ve %q aynı ağa üye; aynı ağ iki kez açılamaz", a.Name, b.Name))
				continue
			}
			if a.IPv4.IsValid() && b.IPv4.IsValid() && a.IPv4.Overlaps(b.IPv4) {
				plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("%q (%s) ve %q (%s) IPv4 aralıkları çakışıyor; ağlardan birinin sahibi aralığı değiştirmeli", a.Name, a.IPv4, b.Name, b.IPv4))
			}
			if a.IPv6.IsValid() && b.IPv6.IsValid() && a.IPv6.Overlaps(b.IPv6) {
				plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("%q (%s) ve %q (%s) IPv6 aralıkları çakışıyor", a.Name, a.IPv6, b.Name, b.IPv6))
			}
			if domainsOverlap(a.DNSDomain, b.DNSDomain) {
				plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("%q ve %q aynı DNS alanını kullanıyor (%s, %s); adlar yanlış ağa gider", a.Name, b.Name, a.DNSDomain, b.DNSDomain))
			}
		}
	}
	return plan, nil
}

// domainsOverlap reports equal domains or one under the other.
func domainsOverlap(a, b string) bool {
	a, b = strings.TrimSuffix(a, "."), strings.TrimSuffix(b, ".")
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}
