package osnet

import (
	"fmt"
	"slices"
	"strings"
)

// Group Policy NRPT details (#272, F-063). Windows keeps the Name
// Resolution Policy Table in two places: rules added locally (as OpenScale
// does with Add-DnsClientNrptRule) and rules pushed by Group Policy. As
// soon as Group Policy defines any rule, the DNS client uses only the Group
// Policy rules and ignores every local one, OpenScale's included. The
// local rules stay in place (nrptScript is unchanged), so they work again
// the moment the policy is gone; NRPTGroupPolicyConflict explains what the
// policy means for the network's names so the owner can be warned.

// maxGPORules bounds the Group Policy rules kept in a status.
const maxGPORules = 64

// NRPTRuleInfo is one NRPT rule: its namespaces (".corp.example" is a
// suffix, "host.corp.example" one name, "." every name) and DNS servers.
type NRPTRuleInfo struct {
	Namespaces []string `json:"namespaces"`
	Servers    []string `json:"servers"`
}

// NRPTConflict is what Group Policy NRPT rules mean for one domain.
type NRPTConflict struct {
	// Active: Group Policy has NRPT rules, so local rules are ignored.
	Active bool `json:"active"`
	// Rules is the number of Group Policy rules.
	Rules int `json:"rules"`
	// Covered: a Group Policy rule names the domain (itself, a parent or
	// "."); its servers then answer for the network's names.
	Covered bool `json:"covered"`
	// Namespace is the most specific Group Policy namespace that covers
	// the domain.
	Namespace string `json:"namespace,omitempty"`
	// ToResolver: that rule sends the names to OpenScale's resolver, so
	// MagicDNS still works under the policy.
	ToResolver bool `json:"to_resolver"`
	// Sample lists a few Group Policy namespaces for the message.
	Sample []string `json:"sample,omitempty"`
}

// nrptCovers reports whether NRPT namespace ns applies to domain and how
// specific it is (higher is more specific; 0 does not apply).
func nrptCovers(ns, domain string) int {
	ns = strings.ToLower(strings.TrimSpace(ns))
	domain = strings.ToLower(strings.Trim(domain, "."))
	switch {
	case ns == ".":
		return 1
	case strings.HasPrefix(ns, "."):
		suffix := ns[1:]
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return 1 + strings.Count(suffix, ".") + 1
		}
	case ns == domain:
		return 1000
	}
	return 0
}

// NRPTGroupPolicyConflict explains the Group Policy rules of status for
// the network domain and the MagicDNS resolver address.
func NRPTGroupPolicyConflict(status DNSSystemStatus, domain, resolver string) NRPTConflict {
	c := NRPTConflict{Active: status.GroupPolicyNRPT || len(status.GroupPolicyRules) > 0, Rules: len(status.GroupPolicyRules)}
	if !c.Active {
		return c
	}
	best := 0
	for _, r := range status.GroupPolicyRules {
		for _, ns := range r.Namespaces {
			if len(c.Sample) < 3 && !slices.Contains(c.Sample, ns) {
				c.Sample = append(c.Sample, ns)
			}
			if n := nrptCovers(ns, domain); n > best {
				best = n
				c.Covered, c.Namespace = true, ns
				c.ToResolver = resolver != "" && slices.Contains(r.Servers, resolver)
			}
		}
	}
	return c
}

// Message is the owner's warning for domain; empty without Group Policy
// rules.
func (c NRPTConflict) Message(domain string) string {
	if !c.Active {
		return ""
	}
	head := "Grup İlkesi ile tanımlı NRPT kuralları var"
	if c.Rules > 0 {
		head = fmt.Sprintf("Grup İlkesi ile tanımlı %d NRPT kuralı var", c.Rules)
		if len(c.Sample) > 0 {
			head += " (" + strings.Join(c.Sample, ", ") + ")"
		}
	}
	head += "; Windows bu durumda yerel NRPT kurallarını, OpenScale'inkiler dahil, yok sayar."
	switch {
	case c.Covered && c.ToResolver:
		return head + fmt.Sprintf(" Grup İlkesi'ndeki %q kuralı .%s adlarını zaten OpenScale çözücüsüne gönderiyor; cihaz adları çözülmeye devam eder.", c.Namespace, domain)
	case c.Covered:
		return head + fmt.Sprintf(" Grup İlkesi'ndeki %q kuralı .%s adlarını başka DNS sunucularına gönderiyor; cihaz adları çözülmez ve ad sorguları kurum DNS'ine gider. BT yöneticinizden .%s için OpenScale çözücüsüne giden bir NRPT kuralı isteyin.", c.Namespace, domain, domain)
	default:
		return head + fmt.Sprintf(" .%s için Grup İlkesi'nde kural yok; cihaz adları çözülmeyebilir. BT yöneticinizden ağ alan adı için Grup İlkesi'ne OpenScale çözücüsüne giden bir NRPT kuralı eklemesini isteyin.", domain)
	}
}
