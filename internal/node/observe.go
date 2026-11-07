package node

import "github.com/openscale/openscale/internal/filter"

// PacketFilter returns the tunnel's packet filter, for the refused
// connection log, the packet counters and the debug capture (ADR-0105).
func (e *Engine) PacketFilter() *filter.Filter { return e.filter }
