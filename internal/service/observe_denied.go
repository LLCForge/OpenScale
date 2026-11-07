package service

import (
	"fmt"
	"strconv"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/privacy"
	"github.com/openscale/openscale/internal/trust"
)

// The refused connection log (F-199, #107): the filter counts refused
// packets with a coarse reason; here a refusal by the rules is explained
// with the document the filter used: no rule allows it, a deny rule
// forbids it, or a disabled rule would have allowed it.

func protoName(p uint8) string {
	switch p {
	case packet.ProtoTCP:
		return "tcp"
	case packet.ProtoUDP:
		return "udp"
	case packet.ProtoICMPv4, packet.ProtoICMPv6:
		return "icmp"
	}
	return strconv.Itoa(int(p))
}

// withRules returns a shallow copy of doc with other rules.
func withRules(doc *trust.Document, rules []trust.Rule) *trust.Document {
	c := *doc
	c.Rules = rules
	return &c
}

// ruleCause explains why the rules refuse initiator → responder.
func ruleCause(doc *trust.Document, initiator, responder string, proto uint8, port uint16) (reason string, rule int, why string) {
	// A disabled rule that would allow it on its own.
	for i, r := range doc.Rules {
		if !r.Disabled || r.IsDeny() {
			continue
		}
		rules := append([]trust.Rule(nil), doc.Rules...)
		rules[i].Disabled = false
		if withRules(doc, rules).AllowsIP(initiator, responder, proto, port) {
			return panel.DenyDisabledRule, i + 1, fmt.Sprintf("Kural %d buna izin verirdi ama devre dışı: %s", i+1, admin.RuleString(r))
		}
	}
	// A deny rule: without the deny rules it would pass.
	var allows []trust.Rule
	for _, r := range doc.Rules {
		if !r.IsDeny() {
			allows = append(allows, r)
		}
	}
	if withRules(doc, allows).AllowsIP(initiator, responder, proto, port) {
		src, _ := doc.DeviceByName(initiator)
		dst, _ := doc.DeviceByName(responder)
		s, d := subjectOf(doc, src), subjectOf(doc, dst)
		for i, r := range doc.Rules {
			if r.Disabled || !r.IsDeny() {
				continue
			}
			from, _ := entriesMatch(r.From, s)
			to, _ := entriesMatch(r.To, d)
			pm, _ := traceProtoMatches(r, int(proto), port)
			if from && to && pm {
				return panel.DenyDenyRule, i + 1, fmt.Sprintf("Kural %d reddediyor (reddet kuralı her zaman kazanır): %s", i+1, admin.RuleString(r))
			}
		}
		return panel.DenyDenyRule, 0, "Bir reddet kuralı engelliyor."
	}
	return panel.DenyNoRule, 0, fmt.Sprintf("%s → %s için izin veren kural yok (varsayılan ret). Kural eklemek için panelde Kurallar sayfası veya 'openscale policy'.", initiator, responder)
}

var denyTexts = map[string]string{
	filter.DenyNoDocument:   "Geçerli ağ belgesi yok; tünel tüm trafiği reddediyor.",
	filter.DenyUnknownPeer:  "Karşı taraf ağ belgesinde bir cihaz değil.",
	filter.DenyNotForDevice: "Paketin adresi bu cihaz değil (sahte veya yanlış yönlenmiş kaynak/hedef).",
	filter.DenyShields:      "Bu cihazda kalkanlar açık: diğer cihazların açtığı yeni bağlantılar reddedilir.",
	filter.DenyExitUsers:    "Gönderen cihaz çıkış düğümü kullanamaz (exit_users).",
	filter.DenyUntracked:    "Bu cihazın açtığı bir bağlantıya ait olmayan yanıt veya parça.",
	filter.DenyFlowLimit:    "Kural izin veriyor ama bağlantı tablosu dolu; bağlantı izleme sınırlarını artırın.",
}

// explainDenial turns a filter entry into what the owner sees. Addresses
// appear only for the other side when it is not a device, and masked.
func explainDenial(d filter.Denial) panel.DeniedEntry {
	e := panel.DeniedEntry{Direction: "out", Peer: d.Peer, Proto: protoName(d.Proto), Port: int(d.Port),
		Reason: d.Reason, Count: d.Count, First: d.First, Last: d.Last}
	if d.Inbound {
		e.Direction = "in"
	}
	if d.Peer == "" {
		e.Remote = privacy.MaskAddr(d.Remote)
	}
	if d.Reason == filter.DenyRules {
		e.Reason, e.Why = panel.DenyNoRule, "Kurallar izin vermiyor."
		if d.Document != nil && d.Peer != "" && d.Self != "" {
			initiator, responder := d.Self, d.Peer
			if d.Inbound {
				initiator, responder = d.Peer, d.Self
			}
			e.Reason, e.Rule, e.Why = ruleCause(d.Document, initiator, responder, d.Proto, d.Port)
		}
		return e
	}
	e.Why = denyTexts[d.Reason]
	if e.Why == "" {
		e.Why = "Paket süzgeci reddetti."
	}
	return e
}

// deniedReply builds "openscale denied" from a filter's log.
func deniedReply(f *filter.Filter) panel.DeniedReply {
	rep := panel.DeniedReply{Schema: panel.DiagSchema, Entries: []panel.DeniedEntry{}, Totals: map[string]uint64{}}
	if f == nil {
		return rep
	}
	l := f.DenyLog()
	for _, d := range l.List() {
		rep.Entries = append(rep.Entries, explainDenial(d))
	}
	rep.Totals = l.Totals()
	return rep
}

// Denied implements panel.Observability.
func (o *Observer) Denied() (panel.DeniedReply, error) {
	e := o.cfg.Engine()
	if e == nil {
		return deniedReply(nil), ErrTunnelNotRunning
	}
	return deniedReply(e.PacketFilter()), nil
}

// ClearDenied implements panel.Observability.
func (o *Observer) ClearDenied() error {
	e := o.cfg.Engine()
	if e == nil {
		return ErrTunnelNotRunning
	}
	e.PacketFilter().DenyLog().Clear()
	return nil
}
