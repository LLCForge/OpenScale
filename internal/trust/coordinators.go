package trust

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// Several coordinators and coordinator key rotation (ADR-0111; #153, #152,
// #57). The primary coordinator stays in Document.Coordinator, unchanged,
// so documents with a single coordinator keep their exact bytes; the
// optional Document.Coordinators list adds more. Every coordinator is as
// untrusted as the primary: it only stores and serves the root-signed
// document and relays end-to-end encrypted WireGuard packets.

// MaxExtraCoordinators bounds Document.Coordinators. Each one is a
// WireGuard peer with a persistent keepalive on every device.
const MaxExtraCoordinators = 8

// maxCoordinatorLabel bounds Coordinator.Name and Coordinator.Region.
const maxCoordinatorLabel = 32

// MaxCoordinatorTransition bounds how far after the document's issue time an
// additional coordinator's Until may lie when set by RotateCoordinator.
const MaxCoordinatorTransition = MaxValidity

// DefaultCoordinatorTransition is how long the old key of a coordinator key
// rotation stays usable (like the 30-day coordinator handoff, OS-019).
const DefaultCoordinatorTransition = 30 * 24 * time.Hour

// Errors of the coordinator list edits.
var (
	ErrUnknownCoordinator = errors.New("no coordinator with this key in the document")
	ErrNoPrimary          = errors.New("the network has no coordinator yet; run 'openscale network set-coordinator' first")
)

// AllCoordinators returns the primary coordinator followed by the
// additional ones, in document order. Expired additional coordinators are
// included; see UsableCoordinators.
func (doc *Document) AllCoordinators() []Coordinator {
	if doc.Coordinator == nil {
		return nil
	}
	out := make([]Coordinator, 0, 1+len(doc.Coordinators))
	out = append(out, *doc.Coordinator)
	return append(out, doc.Coordinators...)
}

// UsableCoordinators is AllCoordinators without the additional coordinators
// whose Until has passed at now. The primary is always first.
func (doc *Document) UsableCoordinators(now time.Time) []Coordinator {
	all := doc.AllCoordinators()
	return slices.DeleteFunc(all, func(c Coordinator) bool { return c.Expired(now) })
}

// Expired reports whether an additional coordinator's transition ended.
func (c Coordinator) Expired(now time.Time) bool {
	return !c.Until.IsZero() && !now.Before(c.Until)
}

// CoordinatorByKey returns the coordinator (primary or additional) with
// this WireGuard key.
func (doc *Document) CoordinatorByKey(k Key) (Coordinator, bool) {
	for _, c := range doc.AllCoordinators() {
		if c.WireGuardKey == k {
			return c, true
		}
	}
	return Coordinator{}, false
}

// CoordinatorLabel is a short human label: the name when set, otherwise the
// fingerprint of the key.
func (c Coordinator) CoordinatorLabel() string {
	if c.Name != "" {
		return c.Name
	}
	return CoordinatorFingerprint(c.WireGuardKey)
}

// reserveExtraCoordinators marks the additional coordinators' keys and
// addresses as used; keys may be nil.
func (doc *Document) reserveExtraCoordinators(keys map[Key]bool, addrs map[netip.Addr]bool) {
	for _, c := range doc.Coordinators {
		if keys != nil {
			keys[c.WireGuardKey] = true
		}
		if addrs != nil {
			addrs[c.IPv4], addrs[c.IPv6] = true, true
		}
	}
}

// validateCoordinators checks the labels of the primary and every
// additional coordinator. validateCoordinator has already checked the
// primary's endpoint, key and addresses.
func (doc *Document) validateCoordinators() error {
	if c := doc.Coordinator; c != nil {
		if err := validCoordinatorLabels(*c); err != nil {
			return fmt.Errorf("coordinator: %w", err)
		}
		if !c.Until.IsZero() {
			return errors.New("the primary coordinator cannot have an end time")
		}
	}
	if len(doc.Coordinators) == 0 {
		if doc.Coordinators != nil {
			return errors.New("coordinators must be omitted when empty")
		}
		return nil
	}
	if doc.Coordinator == nil {
		return errors.New("additional coordinators need a primary coordinator")
	}
	if len(doc.Coordinators) > MaxExtraCoordinators {
		return fmt.Errorf("at most %d additional coordinators are allowed", MaxExtraCoordinators)
	}
	keys := map[Key]bool{doc.Coordinator.WireGuardKey: true}
	addrs := map[netip.Addr]bool{doc.Coordinator.IPv4: true, doc.Coordinator.IPv6: true}
	names := map[string]bool{}
	if doc.Coordinator.Name != "" {
		names[doc.Coordinator.Name] = true
	}
	revoked := doc.unusableKeys()
	for i, c := range doc.Coordinators {
		if err := doc.validCoordinatorEntry(c); err != nil {
			return fmt.Errorf("coordinator %d: %w", i+1, err)
		}
		if err := validCoordinatorLabels(c); err != nil {
			return fmt.Errorf("coordinator %d: %w", i+1, err)
		}
		// An Until in the past is allowed: renewing a document must not
		// fail because a transition ended; the coordinator is just unused.
		if keys[c.WireGuardKey] || revoked[c.WireGuardKey] {
			return fmt.Errorf("coordinator %d: key is already used or revoked", i+1)
		}
		if addrs[c.IPv4] || addrs[c.IPv6] {
			return fmt.Errorf("coordinator %d: address is already used", i+1)
		}
		if c.Name != "" {
			if names[c.Name] {
				return fmt.Errorf("coordinator %d: duplicate name", i+1)
			}
			names[c.Name] = true
		}
		keys[c.WireGuardKey] = true
		addrs[c.IPv4], addrs[c.IPv6] = true, true
	}
	return nil
}

// validCoordinatorEntry applies validateCoordinator's checks to c.
func (doc *Document) validCoordinatorEntry(c Coordinator) error {
	if c.WireGuardKey.IsZero() {
		return errors.New("wireguard_key is missing")
	}
	host, port, err := net.SplitHostPort(c.Endpoint)
	if err != nil || host == "" || len(host) > maxEndpointHostLen {
		return errors.New("endpoint must be host:port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("endpoint port must be 1-65535")
	}
	if _, err := netip.ParseAddr(host); err != nil && !isValidDomain(host) {
		return errors.New("endpoint host must be an IP address or domain name")
	}
	if !isHostAddr(doc.IPv4Prefix, c.IPv4) || !isHostAddr(doc.IPv6Prefix, c.IPv6) {
		return errors.New("addresses must be host addresses inside the network prefixes")
	}
	if c.IPv4 == doc.DNSResolverIPv4() || c.IPv6 == doc.DNSResolverIPv6() {
		return errors.New("address is reserved for MagicDNS")
	}
	return nil
}

func validCoordinatorLabels(c Coordinator) error {
	if c.Name != "" && (len(c.Name) > maxCoordinatorLabel || !isValidLabel(c.Name)) {
		return errors.New("name must be a lowercase DNS label of at most 32 characters")
	}
	if c.Region != "" && (len(c.Region) > maxCoordinatorLabel || !isValidLabel(c.Region)) {
		return errors.New("region must be a lowercase label of at most 32 characters")
	}
	return nil
}

// unusableKeys are the revoked and retired keys; no coordinator may use one.
func (doc *Document) unusableKeys() map[Key]bool {
	out := make(map[Key]bool, 2*(len(doc.Revoked)+len(doc.RetiredKeys)))
	for _, r := range doc.Revoked {
		out[r.SigningKey], out[r.WireGuardKey] = true, true
	}
	for _, r := range doc.RetiredKeys {
		out[r.SigningKey], out[r.WireGuardKey] = true, true
	}
	return out
}

// AddCoordinator adds an additional coordinator with fresh overlay
// addresses. The owner checks its key fingerprint first, as for
// SetCoordinator.
func (doc *Document) AddCoordinator(endpoint string, wireguardKey Key, name, region string) error {
	if doc.Coordinator == nil {
		return ErrNoPrimary
	}
	if _, exists := doc.CoordinatorByKey(wireguardKey); exists {
		return errors.New("this coordinator is already in the document")
	}
	c := Coordinator{Endpoint: endpoint, WireGuardKey: wireguardKey, Name: name, Region: region}
	var err error
	if c.IPv4, err = doc.freeAddr(doc.IPv4Prefix); err != nil {
		return err
	}
	if c.IPv6, err = doc.freeAddr(doc.IPv6Prefix); err != nil {
		return err
	}
	prev := doc.Coordinators
	doc.Coordinators = append(slices.Clone(doc.Coordinators), c)
	if err := doc.Validate(); err != nil {
		doc.Coordinators = prev
		return err
	}
	return nil
}

// RemoveCoordinator removes an additional coordinator. The primary is
// replaced with PromoteCoordinator or SetCoordinator, never removed here.
func (doc *Document) RemoveCoordinator(wireguardKey Key) error {
	i := slices.IndexFunc(doc.Coordinators, func(c Coordinator) bool { return c.WireGuardKey == wireguardKey })
	if i < 0 {
		if doc.Coordinator != nil && doc.Coordinator.WireGuardKey == wireguardKey {
			return errors.New("the primary coordinator cannot be removed; promote another one first")
		}
		return ErrUnknownCoordinator
	}
	prev := doc.Coordinators
	doc.Coordinators = slices.Delete(slices.Clone(doc.Coordinators), i, i+1)
	if len(doc.Coordinators) == 0 {
		doc.Coordinators = nil
	}
	if err := doc.Validate(); err != nil {
		doc.Coordinators = prev
		return err
	}
	return nil
}

// PromoteCoordinator makes an additional coordinator the primary one. The
// old primary becomes an additional coordinator, usable until until (zero:
// with no end), so devices that still have an older document reach it.
// Overlay addresses move with their coordinator.
func (doc *Document) PromoteCoordinator(wireguardKey Key, until time.Time) error {
	if doc.Coordinator == nil {
		return ErrNoPrimary
	}
	i := slices.IndexFunc(doc.Coordinators, func(c Coordinator) bool { return c.WireGuardKey == wireguardKey })
	if i < 0 {
		return ErrUnknownCoordinator
	}
	prevPrimary, prevList := doc.Coordinator, doc.Coordinators
	next := doc.Coordinators[i]
	next.Until = time.Time{}
	old := *doc.Coordinator
	old.Until = until
	list := slices.Clone(doc.Coordinators)
	list[i] = old
	doc.Coordinator, doc.Coordinators = &next, list
	if err := doc.Validate(); err != nil {
		doc.Coordinator, doc.Coordinators = prevPrimary, prevList
		return err
	}
	return nil
}

// RotateCoordinator replaces the primary coordinator's key in one document
// version while keeping the old key valid for transition (#152): the new
// key becomes the primary coordinator at fresh overlay addresses and the
// old primary stays as an additional coordinator until now+transition.
// Devices that already have the new document talk to both; devices that
// do not yet have it keep reaching the old key and learn the new one from
// it. transition zero uses DefaultCoordinatorTransition.
func (doc *Document) RotateCoordinator(endpoint string, newKey Key, name, region string, transition time.Duration, now time.Time) error {
	if transition == 0 {
		transition = DefaultCoordinatorTransition
	}
	if transition < time.Hour || transition > MaxCoordinatorTransition {
		return fmt.Errorf("transition must be between 1 hour and %d days", int(MaxCoordinatorTransition.Hours()/24))
	}
	if doc.Coordinator == nil {
		return ErrNoPrimary
	}
	if len(doc.Coordinators) >= MaxExtraCoordinators {
		return fmt.Errorf("at most %d additional coordinators are allowed; remove one first", MaxExtraCoordinators)
	}
	prevPrimary, prevList := doc.Coordinator, doc.Coordinators
	if err := doc.AddCoordinator(endpoint, newKey, name, region); err != nil {
		return err
	}
	if err := doc.PromoteCoordinator(newKey, now.Add(transition)); err != nil {
		doc.Coordinator, doc.Coordinators = prevPrimary, prevList
		return err
	}
	return nil
}

// PruneCoordinators removes additional coordinators whose Until passed and
// returns how many were removed.
func (doc *Document) PruneCoordinators(now time.Time) int {
	before := len(doc.Coordinators)
	doc.Coordinators = slices.DeleteFunc(slices.Clone(doc.Coordinators), func(c Coordinator) bool { return c.Expired(now) })
	if len(doc.Coordinators) == 0 {
		doc.Coordinators = nil
	}
	return before - len(doc.Coordinators)
}
