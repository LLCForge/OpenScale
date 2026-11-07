package trust

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
)

// Application service rules (ADR-0030, ADR-0031).
//
// A rule with a service grants one OpenScale service instead of raw
// traffic. It opens the service's fixed TCP port between the devices it
// matches (so the packet filter admits the connection) and the service
// itself decides with the policy functions below. Only explicit service
// rules grant a service: a broad "any" rule opens the port but never lets
// the service accept the peer. Deny rules, disabled rules and the usual
// evaluation order (ADR-0021) apply unchanged, and a deny rule that covers
// the service port (for example "deny tcp 4000-4100") also denies the
// service.

// RuleService names an application service.
type RuleService string

// Services a rule may grant.
const (
	// ServiceSSH is the embedded SSH server (ADR-0030).
	ServiceSSH RuleService = "ssh"
	// ServiceFiles lets the source send files to the destination.
	ServiceFiles RuleService = "files"
	// ServiceWake lets the source ask a relay device (Via) to wake the
	// destination with a Wake-on-LAN packet on the relay's LAN.
	ServiceWake RuleService = "wake"
	// ServiceSpeedtest lets the source run a throughput test against the
	// destination.
	ServiceSpeedtest RuleService = "speedtest"
	// ServiceRemoteDesktop is the embedded remote desktop (ADR-0055):
	// watching the destination's screen and, with allow_control, sending
	// it keyboard, mouse and clipboard input.
	ServiceRemoteDesktop RuleService = "rdesk"
	// ServicePanel lets the source open the destination's management
	// panel over the tunnel, read-only (ADR-0107). It is not in Services():
	// the panel serves it itself, only on a device holding the root key
	// and only after the owner turned remote access on locally.
	ServicePanel RuleService = "panel"
)

// Fixed TCP ports of the services on each device's tunnel addresses. They
// sit next to the control ports (4040-4043) and away from ports the
// operating system's own servers use, so the embedded SSH server never
// competes with an installed OpenSSH on port 22.
const (
	SSHPort       uint16 = 4022
	FilesPort     uint16 = 4044
	SpeedtestPort uint16 = 4045
	WakePort      uint16 = 4046
	// RemoteDesktopPort is the embedded remote desktop (ADR-0055).
	RemoteDesktopPort uint16 = 4047
	// PanelPort is the read-only management panel over the tunnel
	// (ADR-0107). 4048 is messaging (ADR-0109), 4050 folder sync
	// (SyncPort, ADR-0110).
	PanelPort uint16 = 4049
)

// SSH account names with a special meaning in ssh rules.
const (
	// SSHRootUser is never listed in Users; AllowRoot grants it.
	SSHRootUser = "root"
	// SSHWindowsUser is the account the Windows service runs as
	// (LocalSystem). A Windows device accepts SSH only from rules that
	// list it explicitly; it is as powerful as root.
	SSHWindowsUser = "system"
)

const (
	maxSSHUsers   = 32
	maxSSHUserLen = 32
)

// Services returns every service a rule may grant.
func Services() []RuleService {
	return []RuleService{ServiceSSH, ServiceFiles, ServiceWake, ServiceSpeedtest, ServiceRemoteDesktop, ServiceSync, ServiceSupport}
}

// Port returns the service's TCP port inside the tunnel, or 0 for an
// unknown service.
func (s RuleService) Port() uint16 {
	switch s {
	case ServiceSSH:
		return SSHPort
	case ServiceFiles:
		return FilesPort
	case ServiceSpeedtest:
		return SpeedtestPort
	case ServiceWake:
		return WakePort
	case ServiceRemoteDesktop:
		return RemoteDesktopPort
	case ServicePanel:
		return PanelPort
	case ServiceSync:
		return SyncPort
	case ServiceServe: // ADR-0139
		return ServePort
	case ServiceCert: // ADR-0138
		return CertPort
	case ServiceSupport: // ADR-0232
		return SupportPort
	}
	return 0
}

// hasServiceFields reports whether r sets any field that only service
// rules may set.
func (r Rule) hasServiceFields() bool {
	return len(r.Users) != 0 || r.AllowRoot || r.AllowForward || len(r.Via) != 0 || r.hasRemoteDesktopFields() || r.hasSyncFields() || r.AllowKill
}

// hasRemoteDesktopFields reports whether r sets a field only rdesk rules
// may set (ADR-0055).
func (r Rule) hasRemoteDesktopFields() bool {
	return r.AllowControl || r.AllowUnattended
}

// trafficTo returns the entries the destination of the rule's packets must
// match. A wake rule's traffic goes to the relay (Via), not to the
// sleeping target; a deny wake rule has no Via and so only affects the
// service decision, never the packet filter.
func (r Rule) trafficTo() []string {
	if r.Service == ServiceWake {
		return r.Via
	}
	return r.To
}

func validateServiceRule(r Rule, names, groups map[string]bool) error {
	if r.Service == "" {
		if r.hasServiceFields() {
			return errors.New("users, allow_root, allow_forward, via, allow_control and allow_unattended need a service")
		}
		return nil
	}
	if r.Service.Port() == 0 {
		return fmt.Errorf("unknown service %q", r.Service)
	}
	if r.Protocol != "" || len(r.Ports) != 0 {
		return errors.New("service rules must not set protocol or ports")
	}
	if r.IsDeny() {
		if r.hasServiceFields() {
			return errors.New("deny service rules must not list users, allow_root, allow_forward, via, allow_control or allow_unattended")
		}
		return nil
	}
	if r.Service != ServiceRemoteDesktop && r.hasRemoteDesktopFields() {
		return errors.New("only rdesk rules may set allow_control or allow_unattended")
	}
	if r.Service != ServiceSync && r.hasSyncFields() {
		return errors.New("only sync rules may set folders, backup, quota or allow_prune")
	}
	if r.Service != ServiceSupport && r.AllowKill {
		return errors.New("only support rules may set allow_kill")
	}
	switch r.Service {
	case ServiceSync:
		if len(r.Users) != 0 || r.AllowRoot || r.AllowForward || len(r.Via) != 0 {
			return errors.New("sync rules must not list users, allow_root, allow_forward or via")
		}
		return validateSyncRule(r)
	case ServiceSSH:
		if len(r.Via) != 0 {
			return errors.New("only wake rules may list via")
		}
		return validateSSHUsers(r.Users, r.AllowRoot)
	case ServiceWake:
		if len(r.Users) != 0 || r.AllowRoot || r.AllowForward {
			return errors.New("only ssh rules may list users, allow_root or allow_forward")
		}
		if slices.Contains(r.Via, RuleWildcard) {
			return errors.New("via must name devices, tags, groups or ranges, not *")
		}
		// Ranges in via (#277) must hold relay devices; validateF4A checks
		// that they lie inside the network prefixes.
		return validateTrafficEntries("via", r.Via, names, groups)
	case ServiceSupport: // #852, f4a_support.go
		if len(r.Users) != 0 || r.AllowRoot || r.AllowForward || len(r.Via) != 0 {
			return errors.New("support rules must not list users, allow_root, allow_forward or via")
		}
		return nil
	case ServiceRemoteDesktop:
		if len(r.Users) != 0 || r.AllowRoot || r.AllowForward || len(r.Via) != 0 {
			return errors.New("rdesk rules must not list users, allow_root, allow_forward or via")
		}
		return nil
	default:
		if r.hasServiceFields() {
			return fmt.Errorf("%s rules must not list users, allow_root, allow_forward or via", r.Service)
		}
		return nil
	}
}

func validateSSHUsers(users []string, allowRoot bool) error {
	if len(users) == 0 && !allowRoot {
		return errors.New("ssh rules need users or allow_root")
	}
	if len(users) > maxSSHUsers {
		return fmt.Errorf("ssh rules allow at most %d users", maxSSHUsers)
	}
	seen := make(map[string]bool, len(users))
	for _, u := range users {
		if u == SSHRootUser {
			return errors.New("root is granted with allow_root, not listed in users")
		}
		if !ValidSSHUser(u) {
			return fmt.Errorf("invalid ssh user %q", u)
		}
		if seen[u] {
			return fmt.Errorf("users lists %q twice", u)
		}
		seen[u] = true
	}
	return nil
}

// ValidSSHUser reports whether u is an account name an ssh rule may list:
// lowercase letters, digits, '_', '.' and '-', starting with a letter or
// '_', at most 32 characters. There is no wildcard.
func ValidSSHUser(u string) bool {
	if u == "" || len(u) > maxSSHUserLen {
		return false
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		switch {
		case c >= 'a' && c <= 'z', c == '_':
		case (c >= '0' && c <= '9') || c == '.' || c == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validateDescription(d string) error {
	if len(d) > maxDescriptionLen || strings.IndexFunc(d, unicode.IsControl) >= 0 {
		return errors.New("description is too long or contains control characters")
	}
	return nil
}

// serviceDecision evaluates the service rules of svc from src to dst. It
// returns false when any enabled deny rule of the service matches, and
// otherwise true when an enabled allow rule matches and permits(rule).
func (doc *Document) serviceDecision(svc RuleService, src, dst subject, permits func(Rule) bool) bool {
	return doc.serviceDecisionAt(svc, src, dst, permits, timeNow())
}

// serviceDecisionAt is serviceDecision at time at; the zero time ignores
// time-limited rules' conditions (ADR-0120).
func (doc *Document) serviceDecisionAt(svc RuleService, src, dst subject, permits func(Rule) bool, at time.Time) bool {
	allowed := false
	for _, r := range doc.Rules {
		if doc.ruleOff(r) || r.Service != svc || !r.ActiveAt(at) || !doc.matchesAny(r.From, src) || !doc.matchesAny(r.To, dst) {
			continue
		}
		if r.IsDeny() {
			return false
		}
		if permits == nil || permits(r) {
			allowed = true
		}
	}
	return allowed
}

// serviceAllowed combines the packet decision for the service port with
// the service rules.
func (doc *Document) serviceAllowed(svc RuleService, from, to string, permits func(Rule) bool) bool {
	if from == to || from == "" || to == "" {
		return false
	}
	if !doc.allows(from, to, ipProtoTCP, svc.Port()) {
		return false
	}
	return doc.serviceDecision(svc, doc.subject(from), doc.subject(to), permits)
}

func sshUserPermitted(r Rule, user string) bool {
	if user == SSHRootUser {
		return r.AllowRoot
	}
	return slices.Contains(r.Users, user)
}

// AllowsSSH reports whether device from may log in to device to as the
// local account user over the embedded SSH server. "root" needs a rule
// with allow_root; any other account must be listed in the rule's users.
// Account names are compared exactly; the Windows service passes "system".
func (doc *Document) AllowsSSH(from, to, user string) bool {
	if user == "" {
		return false
	}
	return doc.serviceAllowed(ServiceSSH, from, to, func(r Rule) bool { return sshUserPermitted(r, user) })
}

// AllowsSSHForward reports whether an SSH session of from on to as user
// may open local port forwards: a rule must permit the user and set
// allow_forward.
func (doc *Document) AllowsSSHForward(from, to, user string) bool {
	if user == "" {
		return false
	}
	return doc.serviceAllowed(ServiceSSH, from, to, func(r Rule) bool {
		return r.AllowForward && sshUserPermitted(r, user)
	})
}

// AllowsFileSend reports whether device from may send files to device to.
func (doc *Document) AllowsFileSend(from, to string) bool {
	return doc.serviceAllowed(ServiceFiles, from, to, nil)
}

// AllowsSpeedtest reports whether device from may run a speed test
// against device to.
func (doc *Document) AllowsSpeedtest(from, to string) bool {
	return doc.serviceAllowed(ServiceSpeedtest, from, to, nil)
}

// AllowsWake reports whether device from may have device relay send a
// Wake-on-LAN packet for device target. An allow rule must match from and
// target and list relay in via; a deny wake rule for from and target wins.
// When relay is from itself the request never crosses the tunnel, so no
// packet decision is needed.
func (doc *Document) AllowsWake(from, target, relay string) bool {
	if from == "" || target == "" || relay == "" || from == target || relay == target {
		return false
	}
	if relay != from && !doc.allows(from, relay, ipProtoTCP, WakePort) {
		return false
	}
	rs := doc.subject(relay)
	return doc.serviceDecision(ServiceWake, doc.subject(from), doc.subject(target), func(r Rule) bool {
		return doc.matchesAny(r.Via, rs)
	})
}

// WakeRelays returns the devices that may relay a wake request from
// device from for device target, in document order.
func (doc *Document) WakeRelays(from, target string) []string {
	var out []string
	for _, d := range doc.Devices {
		if doc.AllowsWake(from, target, d.Name) {
			out = append(out, d.Name)
		}
	}
	return out
}

// HostsService reports whether the named device should run the service:
// some enabled allow rule of the service names it as destination (as relay
// for wake). Without one the device does not listen at all.
func (doc *Document) HostsService(name string, svc RuleService) bool {
	if _, ok := doc.DeviceByName(name); !ok {
		return false
	}
	self := doc.subject(name)
	for _, r := range doc.Rules {
		if doc.ruleOff(r) || r.IsDeny() || r.Service != svc {
			continue
		}
		if doc.matchesAny(r.trafficTo(), self) {
			return true
		}
	}
	return false
}

// DeviceByAddr returns the device that owns the tunnel address a.
func (doc *Document) DeviceByAddr(a netip.Addr) (Device, bool) {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" {
		return Device{}, false
	}
	for _, d := range doc.Devices {
		if d.IPv4 == a || d.IPv6 == a {
			return d, true
		}
	}
	return Device{}, false
}
