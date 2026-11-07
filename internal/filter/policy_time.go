package filter

import (
	"time"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// Rule language extensions in the packet filter (ADR-0120): rules are
// evaluated with the packet's ICMP type and the filter's clock, and the
// connection table is forgotten whenever a time-limited rule opens or
// closes, so a one-time access window (#104) or a schedule (#103) also
// ends the connections it allowed. Connections other rules still allow
// are opened again by their next packet, as after a new document.

// ruleQuery is the rule evaluation input for a new connection.
func ruleQuery(info packet.Info, now time.Time) trust.PacketQuery {
	q := trust.PacketQuery{Proto: int(info.Proto), ICMPType: -1, At: now}
	switch info.Proto {
	case packet.ProtoTCP, packet.ProtoUDP:
		q.Port = info.DstPort
	case packet.ProtoICMPv4, packet.ProtoICMPv6:
		q.ICMPType = int(info.ICMPType)
	}
	return q
}

// timeRuleCheck is how often the active time-limited rules are recomputed.
const timeRuleCheck = time.Second

// timeRuleState tracks which time-limited rules were active.
type timeRuleState struct {
	enabled bool
	next    time.Time
	state   string
}

// resetTimeRulesLocked starts tracking for a new document. Called with
// f.mu held.
func (f *Filter) resetTimeRulesLocked(now time.Time) {
	f.timeRules = timeRuleState{}
	if f.doc == nil || !f.doc.HasTimeRules() {
		return
	}
	f.timeRules = timeRuleState{enabled: true, next: now.Add(timeRuleCheck), state: f.doc.TimeRuleState(now)}
}

// timeRulesTickLocked forgets the connection table when the set of active
// time-limited rules changed. Called with f.mu held.
func (f *Filter) timeRulesTickLocked(now time.Time) {
	if !f.timeRules.enabled || f.doc == nil || now.Before(f.timeRules.next) {
		return
	}
	f.timeRules.next = now.Add(timeRuleCheck)
	if st := f.doc.TimeRuleState(now); st != f.timeRules.state {
		f.timeRules.state = st
		f.flows = map[flowKey]time.Time{}
		f.frags = map[fragKey]time.Time{}
	}
}
