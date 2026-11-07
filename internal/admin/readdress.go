package admin

import (
	"net/netip"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// PrepareReaddress prepares the next version with the overlay moved to
// ipv4 and/or ipv6 (F-185, #330, ADR-0136); a zero prefix keeps the
// current one. Like Prepare it signs and writes nothing: the plan is the
// dry run, and Commit signs it with the root key as one version, so every
// device learns its new address from a single signed document.
func (n *Network) PrepareReaddress(now time.Time, validity time.Duration, ipv4, ipv6 netip.Prefix) (*Plan, []trust.AddressMove, error) {
	var moves []trust.AddressMove
	plan, err := n.Prepare(now, validity, func(doc *trust.Document) error {
		m, err := doc.Readdress(ipv4, ipv6)
		moves = m
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return plan, moves, nil
}
