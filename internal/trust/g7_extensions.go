package trust

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/openscale/openscale/internal/adblock"
)

// Signed settings of the blocking and plugin extensions (ADR-0220, G7):
// the approved block list subscriptions with their SHA-256 digests, the
// category policy, the keep list, the .onion and DoH resolver rules and
// the pinned exit node plugins. All opt-in: documents without them encode
// exactly as before, and clients older than the release that added them
// reject a document that uses them (min_client_version, ADR-0220).

// Limits of the extension fields.
const (
	MaxBlockingKeep    = 256
	MaxBlockingDoH     = 256
	MaxPluginPins      = 32
	maxPluginPinName   = 64
	maxBlockingNameLen = 253
)

// BlockingSettings is the owner's signed blocking configuration.
type BlockingSettings struct {
	// Subscriptions are the block lists the exit node may download; a list
	// is used only while its content matches the digest signed here.
	Subscriptions []adblock.Subscription `json:"subscriptions,omitempty"`
	// Policy chooses the categories per device, tag and default.
	Policy *adblock.Policy `json:"policy,omitempty"`
	// Keep lists names never blocked (operating system update domains);
	// it is required when os-telemetry is enabled anywhere (#697).
	Keep []string `json:"keep,omitempty"`
	// Blocking also answers every .onion query with NXDOMAIN on the exit
	// node (#721, RFC 7686): the exit has no Tor resolver, so the name
	// must never reach an ordinary upstream.
	// BlockDoH are DoH resolver names answered with NXDOMAIN so members
	// keep using the network's resolver (#717).
	BlockDoH []string `json:"block_doh,omitempty"`
}

// PluginPin pins one exit node plugin: the SHA-256 digests of its module
// and its manifest, which must match the files byte for byte (#788).
type PluginPin struct {
	Name           string `json:"name"`
	ModuleSHA256   string `json:"module_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// validateG7 checks the extension fields strictly.
func (d *Document) validateG7() error {
	if b := d.Blocking; b != nil {
		if err := b.Validate(); err != nil {
			return fmt.Errorf("engelleme ayarı: %w", err)
		}
	}
	return ValidatePluginPins(d.Plugins)
}

// Validate checks the blocking settings.
func (b *BlockingSettings) Validate() error {
	if err := adblock.ValidateSubscriptions(b.Subscriptions); err != nil {
		return err
	}
	if len(b.Keep) > MaxBlockingKeep {
		return fmt.Errorf("koruma listesi en çok %d ad olabilir", MaxBlockingKeep)
	}
	if err := validNameList(b.Keep); err != nil {
		return fmt.Errorf("koruma listesi: %w", err)
	}
	if len(b.BlockDoH) > MaxBlockingDoH {
		return fmt.Errorf("DoH engel listesi en çok %d ad olabilir", MaxBlockingDoH)
	}
	if err := validNameList(b.BlockDoH); err != nil {
		return fmt.Errorf("DoH engel listesi: %w", err)
	}
	if b.Policy != nil {
		if err := b.Policy.Validate(); err != nil {
			return err
		}
		if len(b.Keep) == 0 && policyUsesTelemetry(b.Policy) {
			return adblock.ErrKeepListRequired
		}
	}
	return nil
}

// Empty reports whether nothing is configured.
func (b *BlockingSettings) Empty() bool {
	return b == nil || len(b.Subscriptions) == 0 && b.Policy == nil && len(b.Keep) == 0 && len(b.BlockDoH) == 0
}

func policyUsesTelemetry(p *adblock.Policy) bool {
	if p.Default.Has(adblock.CategoryOSTelemetry) {
		return true
	}
	for _, s := range p.Tags {
		if s.Has(adblock.CategoryOSTelemetry) {
			return true
		}
	}
	for _, s := range p.Devices {
		if s.Has(adblock.CategoryOSTelemetry) {
			return true
		}
	}
	return false
}

func validNameList(names []string) error {
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || len(n) > maxBlockingNameLen || strings.ContainsAny(n, " \t\r\n\x00/*") {
			return fmt.Errorf("geçersiz ad %q", n)
		}
		norm := strings.TrimSuffix(strings.ToLower(n), ".")
		if norm != n {
			return fmt.Errorf("ad küçük harfle ve sonunda nokta olmadan yazılmalı: %q", n)
		}
		if !strings.Contains(norm, ".") {
			return fmt.Errorf("ad en az bir nokta içermeli: %q", n)
		}
		if seen[norm] {
			return fmt.Errorf("ad iki kez yazılmış: %q", n)
		}
		seen[norm] = true
	}
	return nil
}

// ValidatePluginPins checks the pin list: valid names, lowercase 64 digit
// hex digests, at most MaxPluginPins entries and no repeated name.
func ValidatePluginPins(pins []PluginPin) error {
	if len(pins) > MaxPluginPins {
		return fmt.Errorf("en çok %d eklenti sabitlenebilir", MaxPluginPins)
	}
	seen := map[string]bool{}
	for _, p := range pins {
		if !validPluginName(p.Name) {
			return fmt.Errorf("eklenti adı geçersiz: %q", p.Name)
		}
		if seen[p.Name] {
			return fmt.Errorf("eklenti iki kez sabitlenmiş: %s", p.Name)
		}
		seen[p.Name] = true
		if !validHexDigest(p.ModuleSHA256) || !validHexDigest(p.ManifestSHA256) {
			return fmt.Errorf("eklenti %s: özetler 64 küçük onaltılık karakter olmalı", p.Name)
		}
	}
	return nil
}

func validPluginName(s string) bool {
	if len(s) == 0 || len(s) > maxPluginPinName || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func validHexDigest(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// SetPluginPin adds or replaces the pin of p.Name; the result is validated.
func (d *Document) SetPluginPin(p PluginPin) error {
	next := make([]PluginPin, 0, len(d.Plugins)+1)
	replaced := false
	for _, q := range d.Plugins {
		if q.Name == p.Name {
			next = append(next, p)
			replaced = true
			continue
		}
		next = append(next, q)
	}
	if !replaced {
		next = append(next, p)
	}
	if err := ValidatePluginPins(next); err != nil {
		return err
	}
	d.Plugins = next
	return nil
}

// RemovePluginPin removes the pin of name.
func (d *Document) RemovePluginPin(name string) error {
	for i, q := range d.Plugins {
		if q.Name == name {
			d.Plugins = append(d.Plugins[:i:i], d.Plugins[i+1:]...)
			if len(d.Plugins) == 0 {
				d.Plugins = nil
			}
			return nil
		}
	}
	return errors.New("bu adla sabitlenmiş eklenti yok")
}

// SetBlocking replaces the blocking settings after validating them; an
// empty value removes the field.
func (d *Document) SetBlocking(b *BlockingSettings) error {
	if b.Empty() {
		d.Blocking = nil
		return nil
	}
	if err := b.Validate(); err != nil {
		return err
	}
	c := *b
	d.Blocking = &c
	return nil
}
