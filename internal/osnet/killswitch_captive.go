package osnet

import "net/netip"

// ksWeightCaptive orders the captive portal permits (#85) inside the
// OpenScale sublayer: above the default block, below every other rule.
const ksWeightCaptive = 9

const protoTCP = 6

// captivePorts are the only ports a captive portal exception opens.
var captivePorts = []uint16{80, 443}

// captivePlan returns the WFP permits of a captive portal exception: TCP
// to ports 80 and 443 of each local gateway address, outbound IPv4 only.
// The addresses must have passed validCaptive.
func captivePlan(addrs []netip.Addr) []ksRule {
	var plan []ksRule
	for _, a := range addrs {
		for _, port := range captivePorts {
			plan = append(plan, ksRule{
				Name:       "giriş sayfası istisnası",
				Permit:     true,
				Weight:     ksWeightCaptive,
				Kind:       ksMatchRemotePrefixPort,
				Protocol:   protoTCP,
				RemotePort: port,
				Prefix:     netip.PrefixFrom(a.Unmap(), 32),
			})
		}
	}
	return plan
}

// CaptiveAddressAllowed reports whether a captive portal exception may
// name a: a local IPv4 address (private, link-local or shared address
// space), never a public one.
func CaptiveAddressAllowed(a netip.Addr) bool { return captiveAllowed(a) }
