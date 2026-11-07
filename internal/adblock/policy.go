package adblock

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Policy limits.
const (
	MaxPolicyKeys   = 4096
	MaxExceptions   = 4096
	maxPolicyKeyLen = 128
)

// ErrKeepListRequired is returned when operating system telemetry is
// turned on without a keep list: blocking telemetry without protecting
// the update domains can stop security updates (#697).
var ErrKeepListRequired = errors.New("işletim sistemi telemetrisi engeli güncelleme alanlarını koruyan bir istisna (keep) listesi olmadan açılamaz")

// Policy is the owner's choice of categories per tag and per device.
//
// Resolution for a device: its own entry in Devices if present; else the
// union of the entries of its tags that appear in Tags, if any; else
// Default. A device or tag entry therefore can turn categories off as
// well as on.
type Policy struct {
	Default CategorySet            `json:"default"`
	Tags    map[string]CategorySet `json:"tags,omitempty"`
	Devices map[string]CategorySet `json:"devices,omitempty"`
	// Exceptions are never blocked on any device; DeviceExceptions only on
	// the named device. A name covers itself and every name below it.
	Exceptions       []string            `json:"exceptions,omitempty"`
	DeviceExceptions map[string][]string `json:"device_exceptions,omitempty"`
}

// compiledPolicy is a validated, normalized policy.
type compiledPolicy struct {
	def        CategorySet
	tags       map[string]CategorySet
	devices    map[string]CategorySet
	exceptions []string
	devExc     map[string][]string
	used       CategorySet
}

func validKey(k string) bool {
	return k != "" && len(k) <= maxPolicyKeyLen && !strings.ContainsAny(k, "\x00\r\n")
}

func normalizeNames(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		n, err := NormalizeName(s)
		if err != nil {
			return nil, err
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Validate checks the policy's limits and names.
func (p Policy) Validate() error {
	_, err := p.compile()
	return err
}

func (p Policy) compile() (*compiledPolicy, error) {
	if len(p.Tags)+len(p.Devices)+len(p.DeviceExceptions) > MaxPolicyKeys {
		return nil, fmt.Errorf("politikada en fazla %d etiket ve cihaz olabilir", MaxPolicyKeys)
	}
	c := &compiledPolicy{
		def: p.Default & AllSet, tags: map[string]CategorySet{}, devices: map[string]CategorySet{},
		devExc: map[string][]string{},
	}
	c.used = c.def
	for k, v := range p.Tags {
		if !validKey(k) {
			return nil, fmt.Errorf("geçersiz etiket: %q", k)
		}
		c.tags[k] = v & AllSet
		c.used |= v
	}
	for k, v := range p.Devices {
		if !validKey(k) {
			return nil, fmt.Errorf("geçersiz cihaz adı: %q", k)
		}
		c.devices[k] = v & AllSet
		c.used |= v
	}
	total := len(p.Exceptions)
	for _, v := range p.DeviceExceptions {
		total += len(v)
	}
	if total > MaxExceptions {
		return nil, fmt.Errorf("en fazla %d kalıcı istisna olabilir", MaxExceptions)
	}
	var err error
	if c.exceptions, err = normalizeNames(p.Exceptions); err != nil {
		return nil, err
	}
	for k, v := range p.DeviceExceptions {
		if !validKey(k) {
			return nil, fmt.Errorf("geçersiz cihaz adı: %q", k)
		}
		if c.devExc[k], err = normalizeNames(v); err != nil {
			return nil, err
		}
	}
	c.used &= AllSet
	return c, nil
}

// categoriesFor resolves the categories in force for a device.
func (c *compiledPolicy) categoriesFor(device string, tags []string) CategorySet {
	if s, ok := c.devices[device]; ok && device != "" {
		return s
	}
	var s CategorySet
	found := false
	for _, t := range tags {
		if v, ok := c.tags[t]; ok {
			s |= v
			found = true
		}
	}
	if found {
		return s
	}
	return c.def
}

func (c *compiledPolicy) excepted(device, n string) bool {
	for _, d := range c.exceptions {
		if under(n, d) {
			return true
		}
	}
	if device == "" {
		return false
	}
	for _, d := range c.devExc[device] {
		if under(n, d) {
			return true
		}
	}
	return false
}
