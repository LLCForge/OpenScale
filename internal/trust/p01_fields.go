package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Document fields of package P01 (ADR-0151): compacted revocations (#346),
// the device key age policy (#347) and the network-wide emergency lock
// (#361). Each is optional; a document that does not use them encodes
// exactly as before, and members older than ADR-0151 reject a document
// that does (the accepted closed failure, see the ADR).

// Limits of the P01 fields.
const (
	// MaxRevokedKeyDigests bounds compacted revocation entries (two per
	// revoked device: signing and WireGuard key).
	MaxRevokedKeyDigests = 16384
	// revokedDigestLen is the length of a compacted key digest: 128 bits of
	// SHA-256 in lowercase hex.
	revokedDigestLen = 32
	// MaxKeyAgeDays bounds the key age policy.
	MaxKeyAgeDays = 3650
	// maxLockdownReason bounds the lock's note.
	maxLockdownReason = 256
)

// ReasonLockdown is the decision reason while the network is locked.
const ReasonLockdown = "lockdown"

// Lockdown suspends every rule (#361). Only admin devices may open
// connections to other devices; document distribution through the
// coordinator and gossip is not rule-governed and keeps working. Removing
// the lock restores the rules unchanged, because they never left the
// document.
type Lockdown struct {
	Since  time.Time `json:"since"`
	Reason string    `json:"reason,omitempty"`
}

// --- compacted revocations (#346) ---

// RevokedKeyDigest is the compacted form of a revoked key.
func RevokedKeyDigest(k Key) string {
	h := sha256.New()
	h.Write([]byte("openscale/revoked-key/v1\x00"))
	h.Write(k[:])
	return hex.EncodeToString(h.Sum(nil))[:revokedDigestLen]
}

// KeyRevoked reports whether k is revoked, listed in full or compacted.
func (doc *Document) KeyRevoked(k Key) bool {
	for _, r := range doc.Revoked {
		if r.SigningKey == k || r.WireGuardKey == k {
			return true
		}
	}
	if len(doc.RevokedKeyDigests) == 0 {
		return false
	}
	_, found := slices.BinarySearch(doc.RevokedKeyDigests, RevokedKeyDigest(k))
	return found
}

// CompactRevocations keeps the newest keep revocations in full and moves
// the older ones into revoked_key_digests. It returns how many were
// compacted. A compacted key can still never be enrolled again; only the
// device id, name and time are forgotten.
func (doc *Document) CompactRevocations(keep int) (int, error) {
	if keep < 0 || keep > MaxRevoked {
		return 0, fmt.Errorf("keep must be between 0 and %d", MaxRevoked)
	}
	if len(doc.Revoked) <= keep {
		return 0, nil
	}
	sorted := slices.Clone(doc.Revoked)
	slices.SortStableFunc(sorted, func(a, b Revocation) int { return a.RevokedAt.Compare(b.RevokedAt) })
	n := len(sorted) - keep
	old, kept := sorted[:n], sorted[n:]
	digests := slices.Clone(doc.RevokedKeyDigests)
	for _, r := range old {
		digests = append(digests, RevokedKeyDigest(r.SigningKey), RevokedKeyDigest(r.WireGuardKey))
	}
	slices.Sort(digests)
	digests = slices.Compact(digests)
	if len(digests) > MaxRevokedKeyDigests {
		return 0, fmt.Errorf("at most %d compacted revoked keys are allowed", MaxRevokedKeyDigests)
	}
	// Keep the remaining revocations in their original order.
	keepSet := make(map[string]bool, len(kept))
	for _, r := range kept {
		keepSet[r.DeviceID] = true
	}
	out := doc.Revoked[:0:0]
	for _, r := range doc.Revoked {
		if keepSet[r.DeviceID] {
			out = append(out, r)
		}
	}
	doc.Revoked = out
	doc.RevokedKeyDigests = digests
	return n, nil
}

func (doc *Document) validateRevokedDigests() error {
	ds := doc.RevokedKeyDigests
	if len(ds) > MaxRevokedKeyDigests {
		return fmt.Errorf("at most %d revoked_key_digests are allowed", MaxRevokedKeyDigests)
	}
	for i, d := range ds {
		if !isHexOfLen(d, revokedDigestLen) {
			return fmt.Errorf("revoked_key_digests %d must be %d lowercase hex characters", i, revokedDigestLen)
		}
		// Strictly ascending: one canonical encoding, no duplicates, and
		// KeyRevoked can search it.
		if i > 0 && ds[i-1] >= d {
			return errors.New("revoked_key_digests must be sorted and unique")
		}
	}
	if len(ds) == 0 {
		return nil
	}
	revoked := func(k Key) bool {
		_, found := slices.BinarySearch(ds, RevokedKeyDigest(k))
		return found
	}
	for _, d := range doc.Devices {
		if revoked(d.SigningKey) || revoked(d.WireGuardKey) {
			return fmt.Errorf("device %s uses a revoked key", d.Name)
		}
	}
	if c := doc.Coordinator; c != nil && revoked(c.WireGuardKey) {
		return errors.New("coordinator uses a revoked key")
	}
	for _, c := range doc.Coordinators {
		if revoked(c.WireGuardKey) {
			return errors.New("coordinator uses a revoked key")
		}
	}
	return nil
}

func isHexOfLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// --- device key age policy (#347) ---

// SetMaxKeyAge sets the key age policy in days; 0 removes it.
func (doc *Document) SetMaxKeyAge(days int) error {
	if days < 0 || days > MaxKeyAgeDays {
		return fmt.Errorf("max key age must be between 0 and %d days", MaxKeyAgeDays)
	}
	doc.MaxKeyAgeDays = uint32(days)
	return nil
}

// KeyIssuedAt is when the device's current keys entered the document: its
// enrollment, or its last key rotation (the newest retired key of the same
// device).
func (doc *Document) KeyIssuedAt(d Device) time.Time {
	at := d.AddedAt
	for _, r := range doc.RetiredKeys {
		if r.DeviceID == d.ID && r.RetiredAt.After(at) {
			at = r.RetiredAt
		}
	}
	return at
}

// KeyAgeStatus is one device's key age under the policy.
type KeyAgeStatus struct {
	Name     string    `json:"name"`
	IssuedAt time.Time `json:"issuedAt"`
	AgeDays  int       `json:"ageDays"`
	Overdue  bool      `json:"overdue"`
}

// KeyAges lists every device's key age; Overdue is set only when a policy
// exists and the key is older than it.
func (doc *Document) KeyAges(now time.Time) []KeyAgeStatus {
	out := make([]KeyAgeStatus, 0, len(doc.Devices))
	limit := time.Duration(doc.MaxKeyAgeDays) * 24 * time.Hour
	for _, d := range doc.Devices {
		at := doc.KeyIssuedAt(d)
		age := max(now.Sub(at), 0)
		out = append(out, KeyAgeStatus{Name: d.Name, IssuedAt: at, AgeDays: int(age.Hours() / 24),
			Overdue: doc.MaxKeyAgeDays > 0 && age > limit})
	}
	return out
}

// KeyOverdue reports whether the named device's key is older than the
// policy allows.
func (doc *Document) KeyOverdue(name string, now time.Time) (KeyAgeStatus, bool) {
	for _, s := range doc.KeyAges(now) {
		if s.Name == name {
			return s, s.Overdue
		}
	}
	return KeyAgeStatus{}, false
}

// --- network-wide emergency lock (#361) ---

// SetLockdown turns the lock on (keeping an earlier Since) or off.
func (doc *Document) SetLockdown(on bool, reason string, now time.Time) error {
	if !on {
		doc.Lockdown = nil
		return nil
	}
	if err := validateLockdownReason(reason); err != nil {
		return err
	}
	since := roundTimestamp(now)
	if doc.Lockdown != nil {
		since = doc.Lockdown.Since
	}
	doc.Lockdown = &Lockdown{Since: since, Reason: reason}
	return nil
}

// Locked reports whether the network is under the emergency lock.
func (doc *Document) Locked() bool { return doc.Lockdown != nil }

func validateLockdownReason(s string) error {
	if len(s) > maxLockdownReason || strings.IndexFunc(s, unicode.IsControl) >= 0 || !utf8.ValidString(s) {
		return fmt.Errorf("lockdown reason must be at most %d characters without control characters", maxLockdownReason)
	}
	return nil
}

func (doc *Document) validateLockdown() error {
	l := doc.Lockdown
	if l == nil {
		return nil
	}
	if l.Since.IsZero() || l.Since.After(doc.IssuedAt) {
		return errors.New("lockdown since must be set and not after issued_at")
	}
	return validateLockdownReason(l.Reason)
}

// ruleOff reports whether r takes no part in decisions: disabled, or every
// rule while the network is locked.
func (doc *Document) ruleOff(r Rule) bool { return r.Disabled || doc.Lockdown != nil }

// lockdownAllows: while locked only an admin device reaches devices.
func (doc *Document) lockdownAllows(src, dst string) bool {
	s, ok := doc.DeviceByName(src)
	if !ok || !s.HasRole(RoleAdmin) {
		return false
	}
	_, ok = doc.DeviceByName(dst)
	return ok
}

func (doc *Document) lockdownDecision(src, dst string) Decision {
	d := Decision{Rule: -1, Reason: ReasonLockdown}
	d.Allowed = doc.lockdownAllows(src, dst)
	return d
}

func (doc *Document) validateP01() error {
	if err := doc.validateRevokedDigests(); err != nil {
		return err
	}
	if doc.MaxKeyAgeDays > MaxKeyAgeDays {
		return fmt.Errorf("max_key_age_days must be at most %d", MaxKeyAgeDays)
	}
	return doc.validateLockdown()
}

// --- limits (#345) ---

// LimitUsage is how much of one document limit is used.
type LimitUsage struct {
	Code string `json:"code"`
	Name string `json:"name"`
	Used int    `json:"used"`
	Max  int    `json:"max"`
}

// Percent is the used share in whole percent.
func (u LimitUsage) Percent() int {
	if u.Max <= 0 {
		return 0
	}
	return u.Used * 100 / u.Max
}

// LimitWarnPercent is when a limit starts to warn.
const LimitWarnPercent = 80

// LimitUsages reports the document's use of its hard limits.
func (doc *Document) LimitUsages() []LimitUsage {
	size := 0
	if data, err := json.Marshal(doc); err == nil {
		size = len(data)
	}
	return []LimitUsage{
		{Code: "size", Name: "belge boyutu (bayt)", Used: size, Max: MaxDocumentSize},
		{Code: "devices", Name: "cihaz", Used: len(doc.Devices), Max: MaxDevices},
		{Code: "revoked", Name: "iptal kaydı", Used: len(doc.Revoked), Max: MaxRevoked},
		{Code: "revoked_digests", Name: "sıkıştırılmış iptal", Used: len(doc.RevokedKeyDigests), Max: MaxRevokedKeyDigests},
		{Code: "rules", Name: "kural", Used: len(doc.Rules), Max: MaxRules},
		{Code: "invites", Name: "davet", Used: len(doc.Invites), Max: MaxInvites},
	}
}

// NearLimits returns the limits used at or above LimitWarnPercent.
func (doc *Document) NearLimits() []LimitUsage {
	var out []LimitUsage
	for _, u := range doc.LimitUsages() {
		if u.Percent() >= LimitWarnPercent {
			out = append(out, u)
		}
	}
	return out
}

// LimitWarning is the Turkish warning line for a limit near its end.
func LimitWarning(u LimitUsage) string {
	msg := fmt.Sprintf("Belge sınırına yaklaşıldı: %s %d/%d (%%%d).", u.Name, u.Used, u.Max, u.Percent())
	if u.Code == "revoked" {
		msg += " Eski iptalleri sıkıştırmak için: openscale network revoked-compact."
	}
	return msg
}
