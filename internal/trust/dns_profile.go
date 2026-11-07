package trust

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// DNS filter profiles (#416, #417, ADR-0150). A profile names the devices
// whose exit node DNS queries get a stricter or looser treatment than the
// exit node's default: a block list chosen on the exit node by profile
// name, no block list at all, or enforced safe search. The exit node
// decides by the tunnel address the query came from, which the signed
// document binds to one device. Block lists themselves never travel in
// the document (ADR-0102: lists are local files on the exit node).

// Limits of dns_profiles.
const (
	MaxDNSProfiles       = 32
	maxDNSProfileMembers = 256
)

// DNSProfile assigns devices, tags or groups to a named DNS filter
// profile. The first profile that covers a device applies to it.
type DNSProfile struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
	// SafeSearch maps the search engines' names to their safe search
	// names on the exit node (#417).
	SafeSearch bool `json:"safe_search,omitempty"`
	// NoBlocklist turns the exit node's block lists off for the members,
	// e.g. for servers.
	NoBlocklist bool `json:"no_blocklist,omitempty"`
}

// ValidDNSProfileName reports whether s can name a profile: a lowercase
// DNS label, so it also works as a file name part on the exit node.
func ValidDNSProfileName(s string) bool { return isValidLabel(s) }

// SetDNSProfile adds the profile or replaces the one with the same name;
// its position in the list is kept on replace.
func (doc *Document) SetDNSProfile(p DNSProfile) error {
	p.Members = slices.Clone(p.Members)
	return doc.transact(func() error {
		if i := slices.IndexFunc(doc.DNSProfiles, func(x DNSProfile) bool { return x.Name == p.Name }); i >= 0 {
			doc.DNSProfiles[i] = p
			return nil
		}
		doc.DNSProfiles = append(doc.DNSProfiles, p)
		return nil
	})
}

// RemoveDNSProfile deletes the named profile.
func (doc *Document) RemoveDNSProfile(name string) error {
	i := slices.IndexFunc(doc.DNSProfiles, func(x DNSProfile) bool { return x.Name == name })
	if i < 0 {
		return errors.New("dns profile not found")
	}
	return doc.transact(func() error {
		doc.DNSProfiles = slices.Delete(doc.DNSProfiles, i, i+1)
		if len(doc.DNSProfiles) == 0 {
			// Encode exactly as a document that never had profiles.
			doc.DNSProfiles = nil
		}
		return nil
	})
}

// DNSProfileFor returns the first profile covering the named device.
func (doc *Document) DNSProfileFor(name string) (DNSProfile, bool) {
	if len(doc.DNSProfiles) == 0 {
		return DNSProfile{}, false
	}
	s := doc.subject(name)
	for _, p := range doc.DNSProfiles {
		if doc.matchesAny(p.Members, s) {
			return p, true
		}
	}
	return DNSProfile{}, false
}

func (doc *Document) validateDNSProfiles(names, groups map[string]bool) error {
	if doc.DNSProfiles == nil {
		return nil
	}
	if len(doc.DNSProfiles) == 0 {
		return errors.New("dns_profiles is empty; omit it instead")
	}
	if len(doc.DNSProfiles) > MaxDNSProfiles {
		return fmt.Errorf("dns_profiles allows at most %d profiles", MaxDNSProfiles)
	}
	seen := make(map[string]bool, len(doc.DNSProfiles))
	for i, p := range doc.DNSProfiles {
		if !isValidLabel(p.Name) {
			return fmt.Errorf("dns profile %d: name must be a lowercase DNS label", i)
		}
		if seen[p.Name] {
			return fmt.Errorf("dns profile %d (%s): duplicate name", i, p.Name)
		}
		seen[p.Name] = true
		if len(p.Members) == 0 {
			return fmt.Errorf("dns profile %s: needs at least one member", p.Name)
		}
		if len(p.Members) > maxDNSProfileMembers {
			return fmt.Errorf("dns profile %s: at most %d members are allowed", p.Name, maxDNSProfileMembers)
		}
		field := "dns profile " + p.Name
		members := make(map[string]bool, len(p.Members))
		for _, m := range p.Members {
			if m == RuleWildcard || isAddrEntry(m) {
				return fmt.Errorf("%s: members must be devices, tags or groups", field)
			}
			if err := validateReference(field, m, names, groups); err != nil {
				return err
			}
			if members[m] {
				return fmt.Errorf("%s lists %q twice", field, m)
			}
			members[m] = true
		}
	}
	return nil
}

// dropDNSProfileRefs removes a revoked device from the profiles; a profile
// left without members goes too, so a revocation never fails on it.
func (doc *Document) dropDNSProfileRefs(name string) {
	if doc.DNSProfiles == nil {
		return
	}
	kept := doc.DNSProfiles[:0]
	for _, p := range doc.DNSProfiles {
		p.Members = slices.DeleteFunc(p.Members, func(s string) bool { return s == name })
		if len(p.Members) > 0 {
			kept = append(kept, p)
		}
	}
	doc.DNSProfiles = kept
	if len(doc.DNSProfiles) == 0 {
		doc.DNSProfiles = nil
	}
}

// renameDNSProfileRefs follows a device rename.
func (doc *Document) renameDNSProfileRefs(oldName, newName string) {
	for i := range doc.DNSProfiles {
		for j, m := range doc.DNSProfiles[i].Members {
			if m == oldName && !strings.Contains(m, ":") {
				doc.DNSProfiles[i].Members[j] = newName
			}
		}
	}
}
