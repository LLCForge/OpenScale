package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"
)

// ErrNameTaken is returned when a device name is already used.
var ErrNameTaken = errors.New("device name is already used")

// ErrRevokedKey is returned when enrolling an id or key that was revoked.
var ErrRevokedKey = errors.New("device id or key was revoked earlier and cannot be enrolled again")

// ErrUnknownDevice is returned when a named device does not exist.
var ErrUnknownDevice = errors.New("device not found")

// ErrAddressSpaceFull is returned when no overlay address is free.
var ErrAddressSpaceFull = errors.New("no free overlay address in prefix")

// NewDocument returns version 1 of a new network.
func NewDocument(networkID, dnsDomain string, ipv4, ipv6 netip.Prefix, now time.Time, validity time.Duration) (*Document, error) {
	now = roundTimestamp(now)
	doc := &Document{
		NetworkID:  networkID,
		Version:    1,
		IssuedAt:   now,
		ExpiresAt:  now.Add(validity),
		DNSDomain:  dnsDomain,
		IPv4Prefix: ipv4,
		IPv6Prefix: ipv6,
	}
	normalizeSlices(doc)
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return doc, nil
}

// NewNetworkID returns a random network identifier.
func NewNetworkID(random io.Reader) (string, error) {
	return newRandomID(random)
}

// RandomULAPrefix returns a random /48 unique local prefix (RFC 4193).
func RandomULAPrefix(random io.Reader) (netip.Prefix, error) {
	var b [16]byte
	b[0] = 0xfd
	if _, err := io.ReadFull(random, b[1:6]); err != nil {
		return netip.Prefix{}, fmt.Errorf("read random prefix: %w", err)
	}
	return netip.PrefixFrom(netip.AddrFrom16(b), 48), nil
}

// Next returns a deep copy with the version bumped and a new validity
// window. Every edit goes through Next so the original stays untouched if
// the edit fails.
func (doc *Document) Next(now time.Time, validity time.Duration) (*Document, error) {
	if validity <= 0 || validity > MaxValidity {
		return nil, fmt.Errorf("validity must be between 1s and %d days", int(MaxValidity.Hours()/24))
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("copy document: %w", err)
	}
	var next Document
	if err := json.Unmarshal(data, &next); err != nil {
		return nil, fmt.Errorf("copy document: %w", err)
	}
	now = roundTimestamp(now)
	next.Version = doc.Version + 1
	next.IssuedAt = now
	next.ExpiresAt = now.Add(validity)
	normalizeSlices(&next)
	return &next, nil
}

// AddDevice enrolls a verified enrollment request under name.
func (doc *Document) AddDevice(req *EnrollmentRequest, name string, roles []Role, now time.Time, lifetime time.Duration) (Device, error) {
	if !isValidLabel(name) {
		return Device{}, ErrInvalidName
	}
	if _, exists := doc.DeviceByName(name); exists {
		return Device{}, ErrNameTaken
	}
	for _, r := range doc.Revoked {
		if r.DeviceID == req.DeviceID || r.SigningKey == req.SigningKey || r.WireGuardKey == req.WireGuardKey ||
			r.SigningKey == req.WireGuardKey || r.WireGuardKey == req.SigningKey {
			return Device{}, ErrRevokedKey
		}
	}
	if doc.keyRetired(req.SigningKey) || doc.keyRetired(req.WireGuardKey) {
		return Device{}, ErrRevokedKey
	}
	if lifetime <= 0 {
		return Device{}, errors.New("device lifetime must be positive")
	}
	if lifetime > MaxDeviceLife {
		return Device{}, ErrInvalidLifetime
	}
	ipv4, err := doc.freeAddr(doc.IPv4Prefix)
	if err != nil {
		return Device{}, err
	}
	ipv6, err := doc.freeAddr(doc.IPv6Prefix)
	if err != nil {
		return Device{}, err
	}
	now = roundTimestamp(now)
	d := Device{
		ID:           req.DeviceID,
		Name:         name,
		SigningKey:   req.SigningKey,
		WireGuardKey: req.WireGuardKey,
		IPv4:         ipv4,
		IPv6:         ipv6,
		Roles:        append([]Role{}, roles...),
		AddedAt:      now,
		ExpiresAt:    now.Add(lifetime),
	}
	doc.Devices = append(doc.Devices, d)
	if err := doc.Validate(); err != nil {
		doc.Devices = doc.Devices[:len(doc.Devices)-1]
		return Device{}, err
	}
	return d, nil
}

// RevokeDevice removes the named device, records its keys as revoked, and
// removes it from rules, groups, exit_users and DNS settings. Rules left
// with no source or destination are dropped; their count is returned. An
// exit_users list left empty stays present, so it then allows no device
// instead of falling back to every device.
func (doc *Document) RevokeDevice(name string, now time.Time) (int, error) {
	idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.Name == name })
	if idx < 0 {
		return 0, ErrUnknownDevice
	}
	d := doc.Devices[idx]
	doc.Devices = slices.Delete(doc.Devices, idx, idx+1)
	doc.Revoked = append(doc.Revoked, Revocation{
		DeviceID:     d.ID,
		Name:         d.Name,
		SigningKey:   d.SigningKey,
		WireGuardKey: d.WireGuardKey,
		RevokedAt:    now.UTC().Truncate(time.Second),
	})

	dropped := 0
	kept := doc.Rules[:0]
	for _, r := range doc.Rules {
		r.From = slices.DeleteFunc(r.From, func(s string) bool { return s == name })
		r.To = slices.DeleteFunc(r.To, func(s string) bool { return s == name })
		viaBefore := len(r.Via)
		r.Via = slices.DeleteFunc(r.Via, func(s string) bool { return s == name })
		// A wake rule left without a relay is dropped like one without a
		// source or destination (ADR-0031).
		if len(r.From) == 0 || len(r.To) == 0 || (viaBefore > 0 && len(r.Via) == 0) {
			dropped++
			continue
		}
		kept = append(kept, r)
	}
	doc.Rules = kept
	for i := range doc.Groups {
		doc.Groups[i].Members = slices.DeleteFunc(doc.Groups[i].Members, func(s string) bool { return s == name })
	}
	if doc.ExitUsers != nil {
		users := slices.DeleteFunc(*doc.ExitUsers, func(s string) bool { return s == name })
		doc.ExitUsers = &users
	}
	doc.dropDNSAddrs(d.IPv4, d.IPv6)
	doc.dropDNSRefs(d)
	doc.dropDNSProfileRefs(name) // #416
	// Tests naming the device go too, so a revocation never fails on a
	// test (ADR-0120).
	doc.dropPolicyTestsFor(name)
	// The internal CA's key is on its issuer; revoking the issuer unpins
	// the CA (ADR-0138).
	doc.dropInternalCAFor(name)
	// Rule entries and named addresses inside the revoked device's routes
	// go too (ADR-0133), so revoking a router never fails.
	dropped += doc.dropUnroutedRefs()
	return dropped, doc.Validate()
}

// AddRule appends a rule after validating it against the current devices.
func (doc *Document) AddRule(r Rule) error {
	if r.Ports == nil {
		r.Ports = []string{}
	}
	// "allow" is the default; storing it empty keeps allow rules encoded
	// exactly as before deny rules existed.
	if r.Action == RuleAllow {
		r.Action = ""
	}
	doc.Rules = append(doc.Rules, r)
	minBefore := doc.MinClientVersion
	RaiseMinClientForSchema(doc) // support rules and ranges in via (ADR-0232)
	if err := doc.Validate(); err != nil {
		doc.Rules = doc.Rules[:len(doc.Rules)-1]
		doc.MinClientVersion = minBefore
		return err
	}
	return nil
}

// RemoveRule deletes the rule at index (0-based).
func (doc *Document) RemoveRule(index int) (Rule, error) {
	if index < 0 || index >= len(doc.Rules) {
		return Rule{}, errors.New("rule not found")
	}
	r := doc.Rules[index]
	doc.Rules = slices.Delete(doc.Rules, index, index+1)
	return r, doc.Validate()
}

// SetCoordinator pins the coordinator. Its overlay addresses are kept when
// only the endpoint or key changes, so devices keep reaching it.
func (doc *Document) SetCoordinator(endpoint string, wireguardKey Key) error {
	c := &Coordinator{Endpoint: endpoint, WireGuardKey: wireguardKey}
	if doc.Coordinator != nil {
		c.IPv4, c.IPv6 = doc.Coordinator.IPv4, doc.Coordinator.IPv6
	} else {
		var err error
		if c.IPv4, err = doc.freeAddr(doc.IPv4Prefix); err != nil {
			return err
		}
		if c.IPv6, err = doc.freeAddr(doc.IPv6Prefix); err != nil {
			return err
		}
	}
	for _, r := range doc.Revoked {
		if r.WireGuardKey == wireguardKey || r.SigningKey == wireguardKey {
			return ErrRevokedKey
		}
	}
	prev := doc.Coordinator
	doc.Coordinator = c
	if err := doc.Validate(); err != nil {
		doc.Coordinator = prev
		return err
	}
	return nil
}

// freeAddr returns the lowest unused host address in p.
func (doc *Document) freeAddr(p netip.Prefix) (netip.Addr, error) {
	used := make(map[netip.Addr]bool, len(doc.Devices)+1)
	for _, d := range doc.Devices {
		used[d.IPv4], used[d.IPv6] = true, true
	}
	if doc.Coordinator != nil {
		used[doc.Coordinator.IPv4], used[doc.Coordinator.IPv6] = true, true
	}
	doc.reserveExtraCoordinators(nil, used) // ADR-0111
	for _, inv := range doc.Invites {
		used[inv.IPv4] = true
	}
	used[doc.DNSResolverIPv4()], used[doc.DNSResolverIPv6()] = true, true
	if doc.customAddressing() { // ADR-0133 (F-050)
		return doc.pickAddr(p, used)
	}
	for a := p.Addr().Next(); a.IsValid() && p.Contains(a); a = a.Next() {
		if !isHostAddr(p, a) {
			break
		}
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, ErrAddressSpaceFull
}

// SetExitNode grants or removes the exit node role of the named device.
// Other roles are kept.
func (doc *Document) SetExitNode(name string, on bool) error {
	idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.Name == name })
	if idx < 0 {
		return ErrUnknownDevice
	}
	d := &doc.Devices[idx]
	has := d.HasRole(RoleExitNode)
	switch {
	case on && !has:
		d.Roles = append(d.Roles, RoleExitNode)
	case !on && has:
		d.Roles = slices.DeleteFunc(d.Roles, func(r Role) bool { return r == RoleExitNode })
	default:
		return nil
	}
	return doc.Validate()
}
