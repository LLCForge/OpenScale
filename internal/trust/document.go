package trust

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// DocumentContext is the signature context of network documents.
const DocumentContext = "openscale/network-document/v1"

// Limits on document contents. They bound memory and CPU spent on a
// document received from an untrusted coordinator.
const (
	MaxDocumentSize    = 1 << 20
	MaxDevices         = 1024
	MaxRevoked         = 4096
	MaxRules           = 1024
	maxRuleEntries     = 64
	maxRulePorts       = 32
	maxDescriptionLen  = 256
	MaxValidity        = 400 * 24 * time.Hour
	DefaultValidity    = 90 * 24 * time.Hour
	DefaultDeviceLife  = 365 * 24 * time.Hour
	MaxDeviceLife      = 3650 * 24 * time.Hour
	DefaultDNSDomain   = "openscale.internal"
	maxDomainLength    = 253
	maxEndpointHostLen = 253
)

// DefaultIPv4Prefix is the default overlay IPv4 range, inside the RFC 6598
// shared address space.
var DefaultIPv4Prefix = netip.MustParsePrefix("100.80.0.0/16")

var allowedIPv4Ranges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

var ulaRange = netip.MustParsePrefix("fc00::/7")

// Role grants a device an additional capability.
type Role string

// RoleExitNode allows a device to forward other devices' internet traffic.
const RoleExitNode Role = "exit_node"

// RoleAdmin marks the owner's management device: the coordinator shows it
// pending invite enrollments (ADR-0014).
const RoleAdmin Role = "admin"

// Protocol is a rule's transport protocol.
type Protocol string

// Supported rule protocols.
const (
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolICMP Protocol = "icmp"
	ProtocolAny  Protocol = "any"
)

// RuleAction says whether a rule allows or denies matching traffic
// (ADR-0021). The empty value means allow, so rules written before deny
// rules existed keep their meaning and their exact encoding.
type RuleAction string

// Rule actions.
const (
	RuleAllow RuleAction = "allow"
	RuleDeny  RuleAction = "deny"
)

// Prefixes of tag and group references in rule entries, group members and
// exit_users (ADR-0021). Device names cannot contain ':', so a reference
// can never be mistaken for a device.
const (
	TagPrefix   = "tag:"
	GroupPrefix = "group:"
)

// RuleWildcard matches every device in a rule.
const RuleWildcard = "*"

// CoordinatorName is the MagicDNS name of the coordinator; no device may
// use it.
const CoordinatorName = "coordinator"

// Document is the owner-signed description of the network.
type Document struct {
	NetworkID   string       `json:"network_id"`
	Version     uint64       `json:"version"`
	IssuedAt    time.Time    `json:"issued_at"`
	ExpiresAt   time.Time    `json:"expires_at"`
	DNSDomain   string       `json:"dns_domain"`
	IPv4Prefix  netip.Prefix `json:"ipv4_prefix"`
	IPv6Prefix  netip.Prefix `json:"ipv6_prefix"`
	Coordinator *Coordinator `json:"coordinator,omitempty"`
	Devices     []Device     `json:"devices"`
	Revoked     []Revocation `json:"revoked"`
	Rules       []Rule       `json:"rules"`
	Invites     []Invite     `json:"invites,omitempty"`
	// Groups name sets of devices and tags for rules (ADR-0021).
	Groups []Group `json:"groups,omitempty"`
	// ExitUsers limits which devices may use exit nodes (ADR-0021). nil
	// means every device, as before; a present but empty list means none.
	ExitUsers *[]string `json:"exit_users,omitempty"`
	// DNS holds network-wide resolvers and split DNS (ADR-0024).
	DNS *DNSSettings `json:"dns,omitempty"`
	// DNSProfiles assign devices to exit node DNS filter profiles (#416,
	// dns_profile.go). Optional; documents without them encode as before.
	DNSProfiles []DNSProfile `json:"dns_profiles,omitempty"`
	// MagicDNS holds search domains, extra records and device subdomains
	// (ADR-0034).
	MagicDNS *MagicDNSSettings `json:"magic_dns,omitempty"`
	// RetiredKeys lists keys replaced by a key rotation (ADR-0020). Like
	// revoked keys they can never be used again.
	RetiredKeys []RetiredKey `json:"retired_keys,omitempty"`
	// DisplayName is the network's name shown to people (F-160), for
	// example in the tray and the panel header. Optional; documents
	// without it encode exactly as before.
	DisplayName string `json:"display_name,omitempty"`
	// RecoveryKeys are the public halves of the offline recovery keys
	// (ADR-0027, #7). Devices pin them on first sight; afterwards only a
	// recovery-signed root transition can change them. Optional; documents
	// without them encode exactly as before.
	RecoveryKeys []Key `json:"recovery_keys,omitempty"`
	// RootEpoch counts root key changes (ADR-0027). Documents are ordered by
	// (root_epoch, version); 0 is omitted so older documents keep their bytes.
	RootEpoch uint64 `json:"root_epoch,omitempty"`
	// MinClientVersion is the oldest OpenScale version the coordinator keeps
	// serving (F-027, #257), as "major.minor.patch". Empty: no minimum.
	MinClientVersion string `json:"min_client_version,omitempty"`
	// Hosts name address ranges inside the network for rules ("host:x")
	// and PolicyTests are checked before every signature (ADR-0120).
	// Optional; documents without them encode exactly as before.
	Hosts       []NamedAddress `json:"hosts,omitempty"`
	PolicyTests []PolicyTest   `json:"policy_tests,omitempty"`
	// Coordinators are additional coordinators next to Coordinator
	// (ADR-0111, #153, #152, #57): devices connect to all of them, fail
	// over between them and use each as a relay. Optional; documents
	// without them encode exactly as before.
	Coordinators []Coordinator `json:"coordinators,omitempty"`
	// Approval requires k-of-n approver signatures next to the root
	// signature (ADR-0121, #5). Optional; documents without it encode
	// exactly as before.
	Approval *ApprovalPolicy `json:"approval,omitempty"`
	// ExternalExits are the owner's plain WireGuard servers usable as exit
	// nodes, and Addressing the address assignment strategy (ADR-0133,
	// F-045, F-050). Optional; documents without them encode as before.
	ExternalExits []ExternalExit `json:"external_exits,omitempty"`
	Addressing    *Addressing    `json:"addressing,omitempty"`
	// InternalCA pins the internal certificate authority for TLS inside
	// the tunnel (ADR-0138). Optional; documents without it encode as
	// before.
	InternalCA *InternalCA `json:"internal_ca,omitempty"`
	// PrevDigest is the hex SHA-256 of the signed payload of the previous
	// version (version chain, #343, ADR-0144, chain.go). Opt-in; documents
	// without it encode exactly as before.
	PrevDigest string `json:"prev_digest,omitempty"`
	// RevokedKeyDigests are compacted revocations, MaxKeyAgeDays the device
	// key age policy and Lockdown the network-wide emergency lock (#346,
	// #347, #361, p01_*.go). All opt-in; documents without them encode
	// exactly as before.
	RevokedKeyDigests []string  `json:"revoked_key_digests,omitempty"`
	MaxKeyAgeDays     uint32    `json:"max_key_age_days,omitempty"`
	Lockdown          *Lockdown `json:"lockdown,omitempty"`
	// RevokedAdmins lists revoked administrator grants and Sensitive the
	// two-person rule for sensitive devices (ADR-0172, ADR-0174, g1_*.go).
	// Opt-in; documents without them encode exactly as before.
	RevokedAdmins []string         `json:"revoked_admins,omitempty"`
	Sensitive     *SensitivePolicy `json:"sensitive,omitempty"`
	// Blocking and Plugins: signed extension settings (ADR-0220, g7_*.go).
	Blocking *BlockingSettings `json:"blocking,omitempty"`
	Plugins  []PluginPin       `json:"plugins,omitempty"`
	// JoinPolicy: TPM requirement for new devices (#611, w3_join_policy.go).
	JoinPolicy *JoinPolicy `json:"join_policy,omitempty"`
	// MembersOnly seals names, tags, rules and DNS for the members (#629, ADR-0178, members_only.go). Opt-in; documents without it encode as before.
	MembersOnly *MembersOnly `json:"members_only,omitempty"`
	ExitChains  []ExitChain  `json:"exit_chains,omitempty"` // #618, g8_exit_chain.go
}

// Coordinator pins the coordinator's endpoint, WireGuard key and overlay
// addresses. Control messages go to IPv4 inside the tunnel (ADR-0013).
type Coordinator struct {
	Endpoint     string     `json:"endpoint"`
	WireGuardKey Key        `json:"wireguard_key"`
	IPv4         netip.Addr `json:"ipv4"`
	IPv6         netip.Addr `json:"ipv6"`
	// Name and Region label a coordinator in diagnostics (ADR-0111);
	// Until ends an additional coordinator's use, e.g. the old key of a
	// coordinator key rotation (#152). All optional and omitted when empty.
	Name   string    `json:"name,omitempty"`
	Region string    `json:"region,omitempty"`
	Until  time.Time `json:"until,omitzero"`
}

// CoordinatorFingerprint is the short digest shown by `coordinator keygen`
// and typed by the owner when registering the coordinator.
func CoordinatorFingerprint(wireguardKey Key) string {
	return fingerprint([]byte("coordinator"), wireguardKey[:])
}

// Device is a member of the network.
type Device struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	SigningKey   Key        `json:"signing_key"`
	WireGuardKey Key        `json:"wireguard_key"`
	IPv4         netip.Addr `json:"ipv4"`
	IPv6         netip.Addr `json:"ipv6"`
	Roles        []Role     `json:"roles"`
	AddedAt      time.Time  `json:"added_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	// Tags group devices in rules as "tag:<name>" (ADR-0021).
	Tags []string `json:"tags,omitempty"`
	// Aliases are extra MagicDNS names of the device (ADR-0034, #39).
	Aliases []string `json:"aliases,omitempty"`
	// Ephemeral marks a temporary device (ADR-0028, #22): a short
	// membership that the next signed version drops once it has expired.
	Ephemeral bool `json:"ephemeral,omitempty"`
	// Preauthorized marks a device the owner enrolled in advance with an
	// enrollment key (ADR-0028, F-098). It can never hold the admin role.
	Preauthorized bool `json:"preauthorized,omitempty"`
	// Routes are the subnets this device forwards for members, approved by
	// the owner's signature (ADR-0133, F-032, F-033). Omitted when empty.
	Routes []netip.Prefix `json:"routes,omitempty"`
	// Icon is the device type shown in the panel and the tray (#233,
	// ADR-0232, f4a_icon.go). Optional; a document without icons encodes
	// exactly as before.
	Icon DeviceIcon `json:"icon,omitempty"`
}

// Revocation records a removed device. Its keys stay listed so they can
// never be enrolled again.
type Revocation struct {
	DeviceID     string    `json:"device_id"`
	Name         string    `json:"name"`
	SigningKey   Key       `json:"signing_key"`
	WireGuardKey Key       `json:"wireguard_key"`
	RevokedAt    time.Time `json:"revoked_at"`
}

// Rule allows (or, with Action deny, forbids) traffic from devices in From
// to devices in To. Everything not allowed by a rule is denied, and a deny
// rule always wins over allow rules (ADR-0021).
type Rule struct {
	From        []string   `json:"from"`
	To          []string   `json:"to"`
	Protocol    Protocol   `json:"protocol"`
	Ports       []string   `json:"ports"`
	Description string     `json:"description"`
	Action      RuleAction `json:"action,omitempty"`
	// Disabled keeps a rule in the document without applying it.
	Disabled bool `json:"disabled,omitempty"`
	// Service makes this an application service rule (ADR-0030,
	// ADR-0031): ssh, files, wake or speedtest. Such a rule has no
	// protocol or ports of its own; it opens the service's fixed TCP port
	// and the service decides with the fields below. Rules without a
	// service encode exactly as before.
	Service RuleService `json:"service,omitempty"`
	// Users lists the local accounts an ssh rule allows (never "root").
	Users []string `json:"users,omitempty"`
	// AllowRoot lets an ssh rule log in as root (uid 0).
	AllowRoot bool `json:"allow_root,omitempty"`
	// AllowForward lets an ssh rule open local port forwards (ssh -L).
	AllowForward bool `json:"allow_forward,omitempty"`
	// Via lists the devices that may relay a wake request to the target's
	// LAN (wake rules only).
	Via []string `json:"via,omitempty"`
	// AllowControl lets an rdesk rule send keyboard, mouse and clipboard
	// input; without it the rule only allows watching (ADR-0055).
	AllowControl bool `json:"allow_control,omitempty"`
	// AllowUnattended lets an rdesk rule connect without the on-screen
	// approval of the person at the destination (ADR-0055).
	AllowUnattended bool `json:"allow_unattended,omitempty"`
	// Folders lists the folder IDs a sync rule lets the source read from
	// the destination (ADR-0104, ADR-0110).
	Folders []string `json:"folders,omitempty"`
	// Backup lets a sync rule's source keep encrypted backups on the
	// destination; Quota (bytes, 0 = DefaultBackupQuota) bounds them and
	// AllowPrune lets the source delete its own old backups.
	Backup     bool  `json:"backup,omitempty"`
	Quota      int64 `json:"quota,omitempty"`
	AllowPrune bool  `json:"allow_prune,omitempty"`
	// Rule language extensions (ADR-0120, policy_ext.go); all optional and
	// omitted when unset, so older rules keep their exact encoding.
	// Bidirectional also allows traffic from To to From (F-079).
	Bidirectional bool `json:"bidirectional,omitempty"`
	// ICMPTypes limits an icmp rule to some types: echo, v4:<n>, v6:<n>.
	ICMPTypes []string `json:"icmp_types,omitempty"`
	// NotBefore and NotAfter limit the rule to a time window (UTC); a
	// one-time access window is a rule with NotAfter (#104).
	NotBefore time.Time `json:"not_before,omitzero"`
	NotAfter  time.Time `json:"not_after,omitzero"`
	// Schedule limits the rule to some hours of some days (#103).
	Schedule *RuleSchedule `json:"schedule,omitempty"`
	// AllowKill lets a support rule end processes on the destination
	// ("support.kill", #852, ADR-0232, f4a_support.go); without it the
	// rule only reads.
	AllowKill bool `json:"allow_kill,omitempty"`
}

// IsDeny reports whether the rule forbids matching traffic.
func (r Rule) IsDeny() bool { return r.Action == RuleDeny }

// HasRole reports whether the device has role r.
func (d Device) HasRole(r Role) bool {
	for _, have := range d.Roles {
		if have == r {
			return true
		}
	}
	return false
}

// DeviceByName returns the device with the given name.
func (doc *Document) DeviceByName(name string) (Device, bool) {
	for _, d := range doc.Devices {
		if d.Name == name {
			return d, true
		}
	}
	return Device{}, false
}

// Validate checks every structural and semantic invariant. It is called
// before signing and after verifying, so an invalid document is never
// produced or accepted.
func (doc *Document) Validate() error {
	if !isValidID(doc.NetworkID) {
		return errors.New("network_id must be 32 lowercase hex characters")
	}
	if doc.Version == 0 {
		return errors.New("version must be at least 1")
	}
	if doc.IssuedAt.IsZero() || !doc.ExpiresAt.After(doc.IssuedAt) {
		return errors.New("expires_at must be after issued_at")
	}
	if doc.ExpiresAt.Sub(doc.IssuedAt) > MaxValidity {
		return fmt.Errorf("validity must not exceed %d days", int(MaxValidity.Hours()/24))
	}
	if !isValidDomain(doc.DNSDomain) {
		return errors.New("dns_domain is not a valid domain name")
	}
	if doc.DisplayName != "" {
		if err := ValidateDisplayName(doc.DisplayName); err != nil {
			return err
		}
	}
	if err := validateIPv4Prefix(doc.IPv4Prefix); err != nil {
		return err
	}
	if err := validateIPv6Prefix(doc.IPv6Prefix); err != nil {
		return err
	}
	if err := doc.validateCoordinator(); err != nil {
		return err
	}
	if err := doc.validateCoordinators(); err != nil { // ADR-0111
		return err
	}
	names, err := doc.validateDevices()
	if err != nil {
		return err
	}
	if err := doc.validateRevoked(); err != nil {
		return err
	}
	if err := doc.validateRetired(); err != nil {
		return err
	}
	if err := doc.validateInvites(); err != nil {
		return err
	}
	groups, err := doc.validateGroups(names)
	if err != nil {
		return err
	}
	if err := doc.validateExitUsers(names, groups); err != nil {
		return err
	}
	if err := doc.validateDNS(); err != nil {
		return err
	}
	if err := doc.validateDNSProfiles(names, groups); err != nil { // #416
		return err
	}
	if err := doc.validateMagicDNS(); err != nil {
		return err
	}
	// Recovery keys, root epoch, minimum client version, ephemeral and
	// preauthorized devices, multi-use invites (ADR-0027, ADR-0028).
	if err := doc.validateMembership(); err != nil {
		return err
	}
	if err := doc.validateApproval(); err != nil { // ADR-0121
		return err
	}
	// Subnet routes, plain WireGuard exits, address strategy (ADR-0133).
	if err := doc.validateRouting(names); err != nil {
		return err
	}
	if err := doc.validateRules(names, groups); err != nil {
		return err
	}
	if err := doc.validateInternalCA(); err != nil { // ADR-0138
		return err
	}
	if err := doc.validatePrevDigest(); err != nil { // ADR-0144
		return err
	}
	if err := doc.validateP01(); err != nil { // #346, #347, #361
		return err
	}
	if err := doc.validateG1(); err != nil { // ADR-0172, ADR-0174
		return err
	}
	if err := doc.validateG7(); err != nil { // ADR-0220
		return err
	}
	if err := doc.JoinPolicy.Validate(); err != nil { // #611
		return err
	}
	if err := doc.validateMembersOnly(); err != nil { // #629, ADR-0178
		return err
	}
	if err := validateExitChains(doc.ExitChains); err != nil { // #618
		return err
	}
	// Named addresses, CIDR entries, bidirectional, ICMP type and time
	// fields, policy tests (ADR-0120).
	if err := doc.validatePolicyExt(names); err != nil {
		return err
	}
	// Device icons, ranges in groups, exit_users and via, support rules
	// and the client minimum they need (ADR-0232, f4a_schema.go).
	return doc.validateF4A()
}

func validateIPv4Prefix(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 8 || p.Bits() > 30 {
		return errors.New("ipv4_prefix must be a masked IPv4 prefix between /8 and /30")
	}
	for _, allowed := range allowedIPv4Ranges {
		if allowed.Bits() <= p.Bits() && allowed.Contains(p.Addr()) {
			return nil
		}
	}
	return errors.New("ipv4_prefix must be inside 10/8, 172.16/12, 192.168/16 or 100.64/10")
}

func validateIPv6Prefix(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() || p != p.Masked() || p.Bits() < 32 || p.Bits() > 120 {
		return errors.New("ipv6_prefix must be a masked IPv6 prefix between /32 and /120")
	}
	if !ulaRange.Contains(p.Addr()) {
		return errors.New("ipv6_prefix must be inside the fc00::/7 unique local range")
	}
	return nil
}

func (doc *Document) validateCoordinator() error {
	c := doc.Coordinator
	if c == nil {
		return nil
	}
	if c.WireGuardKey.IsZero() {
		return errors.New("coordinator wireguard_key is missing")
	}
	host, port, err := net.SplitHostPort(c.Endpoint)
	if err != nil || host == "" || len(host) > maxEndpointHostLen {
		return errors.New("coordinator endpoint must be host:port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("coordinator endpoint port must be 1-65535")
	}
	if _, err := netip.ParseAddr(host); err != nil && !isValidDomain(host) {
		return errors.New("coordinator endpoint host must be an IP address or domain name")
	}
	if !isHostAddr(doc.IPv4Prefix, c.IPv4) || !isHostAddr(doc.IPv6Prefix, c.IPv6) {
		return errors.New("coordinator addresses must be host addresses inside the network prefixes")
	}
	if c.IPv4 == doc.DNSResolverIPv4() || c.IPv6 == doc.DNSResolverIPv6() {
		return errors.New("coordinator address is reserved for MagicDNS")
	}
	return nil
}

func (doc *Document) validateDevices() (map[string]bool, error) {
	if len(doc.Devices) > MaxDevices {
		return nil, fmt.Errorf("at most %d devices are allowed", MaxDevices)
	}
	ids := make(map[string]bool, len(doc.Devices))
	names := make(map[string]bool, len(doc.Devices))
	keys := make(map[Key]bool, 2*len(doc.Devices)+1)
	addrs := make(map[netip.Addr]bool, 2*len(doc.Devices))
	if doc.Coordinator != nil {
		keys[doc.Coordinator.WireGuardKey] = true
		addrs[doc.Coordinator.IPv4], addrs[doc.Coordinator.IPv6] = true, true
	}
	doc.reserveExtraCoordinators(keys, addrs) // ADR-0111
	addrs[doc.DNSResolverIPv4()], addrs[doc.DNSResolverIPv6()] = true, true
	for i, d := range doc.Devices {
		if err := doc.validateDevice(d); err != nil {
			return nil, fmt.Errorf("device %d (%s): %w", i, d.Name, err)
		}
		if ids[d.ID] || names[d.Name] {
			return nil, fmt.Errorf("device %d (%s): duplicate id or name", i, d.Name)
		}
		if keys[d.SigningKey] || keys[d.WireGuardKey] || d.SigningKey == d.WireGuardKey {
			return nil, fmt.Errorf("device %d (%s): key is already used", i, d.Name)
		}
		if addrs[d.IPv4] || addrs[d.IPv6] {
			return nil, fmt.Errorf("device %d (%s): address is already used", i, d.Name)
		}
		ids[d.ID], names[d.Name] = true, true
		keys[d.SigningKey], keys[d.WireGuardKey] = true, true
		addrs[d.IPv4], addrs[d.IPv6] = true, true
	}
	return names, nil
}

func (doc *Document) validateDevice(d Device) error {
	switch {
	case !isValidID(d.ID):
		return errors.New("id must be 32 lowercase hex characters")
	case !isValidLabel(d.Name):
		return errors.New("name must be a lowercase DNS label")
	case d.Name == CoordinatorName:
		return errors.New("name is reserved for the coordinator")
	case d.SigningKey.IsZero() || d.WireGuardKey.IsZero():
		return errors.New("keys must not be zero")
	case !isHostAddr(doc.IPv4Prefix, d.IPv4):
		return errors.New("ipv4 must be a host address inside ipv4_prefix")
	case !isHostAddr(doc.IPv6Prefix, d.IPv6):
		return errors.New("ipv6 must be a host address inside ipv6_prefix")
	case d.AddedAt.IsZero() || !d.ExpiresAt.After(d.AddedAt):
		return errors.New("expires_at must be after added_at")
	}
	seen := make(map[Role]bool, len(d.Roles))
	for _, r := range d.Roles {
		if r != RoleExitNode && r != RoleAdmin {
			return fmt.Errorf("unknown role %q", r)
		}
		if seen[r] {
			return fmt.Errorf("duplicate role %q", r)
		}
		seen[r] = true
	}
	return validateTags(d.Tags)
}

func (doc *Document) validateRevoked() error {
	if len(doc.Revoked) > MaxRevoked {
		return fmt.Errorf("at most %d revocations are allowed", MaxRevoked)
	}
	revokedIDs := make(map[string]bool, len(doc.Revoked))
	revokedKeys := make(map[Key]bool, 2*len(doc.Revoked))
	for i, r := range doc.Revoked {
		if !isValidID(r.DeviceID) || r.SigningKey.IsZero() || r.WireGuardKey.IsZero() || r.RevokedAt.IsZero() {
			return fmt.Errorf("revocation %d is incomplete", i)
		}
		if revokedIDs[r.DeviceID] {
			return fmt.Errorf("revocation %d: duplicate device id", i)
		}
		revokedIDs[r.DeviceID] = true
		revokedKeys[r.SigningKey], revokedKeys[r.WireGuardKey] = true, true
	}
	for _, d := range doc.Devices {
		if revokedIDs[d.ID] || revokedKeys[d.SigningKey] || revokedKeys[d.WireGuardKey] {
			return fmt.Errorf("device %s uses a revoked id or key", d.Name)
		}
	}
	return nil
}

func (doc *Document) validateRules(names, groups map[string]bool) error {
	if len(doc.Rules) > MaxRules {
		return fmt.Errorf("at most %d rules are allowed", MaxRules)
	}
	for i, r := range doc.Rules {
		if err := validateRule(r, names, groups); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return nil
}

func validateRule(r Rule, names, groups map[string]bool) error {
	if err := validateTrafficEntries("from", r.From, names, groups); err != nil {
		return err
	}
	if err := validateTrafficEntries("to", r.To, names, groups); err != nil {
		return err
	}
	switch r.Action {
	case "", RuleAllow, RuleDeny:
	default:
		return fmt.Errorf("unknown action %q", r.Action)
	}
	if err := validateServiceRule(r, names, groups); err != nil {
		return err
	}
	if r.Service != "" {
		return validateDescription(r.Description)
	}
	switch r.Protocol {
	case ProtocolTCP, ProtocolUDP:
		if len(r.Ports) == 0 || len(r.Ports) > maxRulePorts {
			return fmt.Errorf("%s rules need 1-%d port entries", r.Protocol, maxRulePorts)
		}
		for _, p := range r.Ports {
			if _, _, err := ParsePortRange(p); err != nil {
				return err
			}
		}
	case ProtocolICMP, ProtocolAny:
		if len(r.Ports) != 0 {
			return fmt.Errorf("%s rules must not list ports", r.Protocol)
		}
	default:
		n, ok := ProtocolNumber(r.Protocol)
		if !ok {
			return fmt.Errorf("unknown protocol %q", r.Protocol)
		}
		if namedProtocol(n) {
			return fmt.Errorf("protocol %d must be written as tcp, udp or icmp", n)
		}
		if len(r.Ports) != 0 {
			return errors.New("only tcp and udp rules may list ports")
		}
	}
	if len(r.Description) > maxDescriptionLen || strings.IndexFunc(r.Description, unicode.IsControl) >= 0 {
		return errors.New("description is too long or contains control characters")
	}
	return nil
}

func validateRuleEntries(field string, entries []string, names, groups map[string]bool) error {
	if len(entries) == 0 || len(entries) > maxRuleEntries {
		return fmt.Errorf("%s needs 1-%d entries", field, maxRuleEntries)
	}
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e != RuleWildcard {
			if err := validateReference(field, e, names, groups); err != nil {
				return err
			}
		}
		if seen[e] {
			return fmt.Errorf("%s lists %q twice", field, e)
		}
		seen[e] = true
	}
	return nil
}

// ParsePortRange parses "443" or "5900-5910".
func ParsePortRange(s string) (uint16, uint16, error) {
	lo, hi, isRange := strings.Cut(s, "-")
	start, err := parsePort(lo)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q", s)
	}
	if !isRange {
		return start, start, nil
	}
	end, err := parsePort(hi)
	if err != nil || end < start {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	return start, end, nil
}

func parsePort(s string) (uint16, error) {
	if s == "" || len(s) > 5 || s[0] == '0' {
		return 0, errors.New("invalid port")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("invalid port")
	}
	return uint16(n), nil
}

// DNSResolverIPv4 is the overlay address the operating system sends
// MagicDNS queries to (ADR-0016). It is the highest host address of the
// IPv4 prefix and is never given to a device, invite or coordinator.
func (doc *Document) DNSResolverIPv4() netip.Addr {
	return lastAddr(doc.IPv4Prefix).Prev()
}

// DNSResolverIPv6 is the IPv6 counterpart of DNSResolverIPv4 (F-068): the
// address just below the highest address of the IPv6 prefix. Like the IPv4
// resolver it is never given to a device or the coordinator. The highest
// address itself is left alone because RFC 2526 reserves the top of a
// subnet for anycast.
func (doc *Document) DNSResolverIPv6() netip.Addr {
	if !doc.IPv6Prefix.IsValid() {
		return netip.Addr{}
	}
	return lastAddr(doc.IPv6Prefix).Prev()
}

// ProtocolNumber parses a numeric rule protocol: an IANA protocol number
// "0"-"255" in decimal without leading zeros.
func ProtocolNumber(p Protocol) (uint8, bool) {
	s := string(p)
	if s == "" || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	if n > 255 {
		return 0, false
	}
	return uint8(n), true
}

// IANA numbers of the protocols that have names in rules.
const (
	ipProtoICMP   = 1
	ipProtoTCP    = 6
	ipProtoUDP    = 17
	ipProtoICMPv6 = 58
)

// namedProtocol reports whether protocol n must be written by name: tcp
// and udp need ports, and icmp covers both ICMP versions.
func namedProtocol(n uint8) bool {
	return n == ipProtoICMP || n == ipProtoTCP || n == ipProtoUDP || n == ipProtoICMPv6
}

// isHostAddr reports whether a is inside p and is neither the network
// address nor (for IPv4) the broadcast address.
func isHostAddr(p netip.Prefix, a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() || !p.Contains(a) || a == p.Addr() {
		return false
	}
	return !(a.Is4() && a == lastAddr(p))
}

// lastAddr returns the highest address inside p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		for bit := 0; bit < 8; bit++ {
			if i*8+bit >= bits {
				b[i] |= 0x80 >> bit
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// isValidLabel reports whether s is a lowercase DNS label (RFC 1123).
func isValidLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// isValidDomain reports whether s is a lowercase domain with at least two
// labels.
func isValidDomain(s string) bool {
	if len(s) == 0 || len(s) > maxDomainLength {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !isValidLabel(l) {
			return false
		}
	}
	return true
}
