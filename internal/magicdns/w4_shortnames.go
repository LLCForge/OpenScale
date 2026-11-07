package magicdns

import (
	"maps"
	"strings"
	"sync/atomic"

	"golang.org/x/net/dns/dnsmessage"
)

// Short names (#762, ADR-0216): the owner's local "nas" → "nas-sunucu"
// table (netdrive.ShortNames, shortnames.json) answered as
// "<kisa>.<alan>". The table maps a label to a device name; the address
// always comes from the signed document at answer time, so a short name
// can never point outside the network. Device names, aliases, records
// and published services win: a short name only fills a name that would
// otherwise not exist.
var shortNames atomic.Pointer[map[string]string]

// SetShortNames replaces the short name table (label → device name).
// A nil or empty map turns short names off.
func SetShortNames(m map[string]string) {
	if len(m) == 0 {
		shortNames.Store(nil)
		return
	}
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[strings.ToLower(strings.TrimSuffix(k, "."))] = v
	}
	shortNames.Store(&c)
}

// ShortNames returns a copy of the current table.
func ShortNames() map[string]string {
	p := shortNames.Load()
	if p == nil {
		return map[string]string{}
	}
	return maps.Clone(*p)
}

func (z zone) shortAnswer(rel string, owner dnsmessage.Name, qtype dnsmessage.Type) (bool, []rr) {
	p := shortNames.Load()
	if p == nil {
		return false, nil
	}
	dev, ok := (*p)[rel]
	if !ok {
		return false, nil
	}
	d, ok := z.owners[dev]
	if !ok {
		return false, nil
	}
	return true, addrRRs(owner, qtype, d.IPv4, d.IPv6)
}
