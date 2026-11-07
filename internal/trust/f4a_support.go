package trust

// Remote support toolbox rules (#852, ADR-0232).
//
// A support rule lets the source read the destination's running
// processes, services, recent system events, disk usage and startup
// programs. Reading is all a plain support rule grants; ending a process
// ("support.kill") is a separate permission that needs allow_kill on an
// allow rule. Like every service rule it opens only the service's fixed TCP
// port and the destination's service decides with AllowsSupport, so a
// coordinator that forges or withholds messages can never grant it: the
// decision rests on the root-signed rules alone. Every session also needs
// the approval of the person at the destination and shows the "remotely
// connected" indicator there (internal/support).

// ServiceSupport is the remote support toolbox (TCP 4053).
const ServiceSupport RuleService = "support"

// SupportPort is the support service's port on each tunnel address.
const SupportPort uint16 = 4053

// SupportMode is what a support request needs.
type SupportMode string

// Support modes.
const (
	// SupportRead reads processes, services, events, disks and startup
	// programs.
	SupportRead SupportMode = "read"
	// SupportKill ends a process.
	SupportKill SupportMode = "kill"
)

// Valid reports whether m is a known mode.
func (m SupportMode) Valid() bool { return m == SupportRead || m == SupportKill }

// AllowsSupport reports whether device from may use the support toolbox on
// device to in the given mode. Read needs any enabled support allow rule;
// kill needs one with allow_kill. A matching support deny rule, or a packet
// deny rule over the service port, wins.
func (doc *Document) AllowsSupport(from, to string, mode SupportMode) bool {
	if !mode.Valid() {
		return false
	}
	return doc.serviceAllowed(ServiceSupport, from, to, func(r Rule) bool {
		return mode == SupportRead || r.AllowKill
	})
}
