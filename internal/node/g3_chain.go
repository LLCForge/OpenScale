package node

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// Two-hop exit (#618, ADR-0187). With ExitChain.Entry set, the exit node in
// use (the final hop) is not reached directly: the WireGuard datagrams for
// it travel, already encrypted for the final exit, inside the tunnel to the
// entry exit node as ordinary UDP to the final exit's public endpoint. The
// entry node forwards them like any member's internet traffic. So:
//
//   - the entry node sees this device and an encrypted stream to the final
//     exit, never the internet destinations;
//   - the final exit sees the internet destinations and the entry node's
//     public address, never this device's.
//
// Neither node needs new code: the entry only needs the exit node role and
// this device needs exit_users permission. This file holds the plan and the
// encapsulation; ADR-0187 lists what is not yet wired into the engine
// (the final exit's endpoint learned from the coordinator must be moved
// into the entry's allowed IPs and onto chainBind).

// ExitChainConfig configures the two-hop exit.
type ExitChainConfig struct {
	// Entry is the first exit node; "" turns chaining off.
	Entry string `json:"entry,omitempty"`
}

// chainPort is the UDP source port of encapsulated datagrams on this
// device's overlay address; nothing listens there.
const chainPort = 4061

type chainState struct {
	entry  string
	final  string
	target netip.AddrPort
}

// ErrChain is wrapped by every chain plan error.
var ErrChain = errors.New("çift sıçramalı çıkış planı geçersiz")

func (e *Engine) validateChain() error {
	c := e.cfg.G3.ExitChain
	if c.Entry == "" {
		return nil
	}
	if len(c.Entry) > 63 || !trust.ValidDNSProfileName(c.Entry) { // a DNS label, like device names
		return fmt.Errorf("%w: giriş düğümü adı %q geçersiz", ErrChain, c.Entry)
	}
	if c.Entry == e.cfg.ExitNode {
		return fmt.Errorf("%w: giriş ve çıkış düğümü aynı olamaz", ErrChain)
	}
	return nil
}

// chainPlan checks a chain against the document: entry and final are
// distinct exit nodes other than self, both valid now, and self may use
// exit nodes.
func chainPlan(doc *trust.Document, self trust.Device, entryName, finalName string) (entry, final trust.Device, err error) {
	if entryName == "" || finalName == "" {
		return trust.Device{}, trust.Device{}, fmt.Errorf("%w: giriş ve çıkış düğümü seçilmeli", ErrChain)
	}
	if entryName == finalName {
		return trust.Device{}, trust.Device{}, fmt.Errorf("%w: giriş ve çıkış düğümü aynı olamaz", ErrChain)
	}
	if entryName == self.Name || finalName == self.Name {
		return trust.Device{}, trust.Device{}, fmt.Errorf("%w: cihaz kendi çıkış düğümü olamaz", ErrChain)
	}
	if !doc.MayUseExitNode(self.Name) {
		return trust.Device{}, trust.Device{}, fmt.Errorf("%w: belge bu cihaza çıkış düğümü kullanma izni vermiyor", ErrChain)
	}
	for _, n := range []string{entryName, finalName} {
		d, ok := doc.DeviceByName(n)
		if !ok || !d.HasRole(trust.RoleExitNode) {
			return trust.Device{}, trust.Device{}, fmt.Errorf("%w: %s bir çıkış düğümü değil", ErrChain, n)
		}
		if n == entryName {
			entry = d
		} else {
			final = d
		}
	}
	return entry, final, nil
}

// encapChain wraps one WireGuard datagram for the final exit into the UDP
// packet the entry node forwards to the internet.
func encapChain(self netip.Addr, target netip.AddrPort, datagram []byte) ([]byte, error) {
	if !self.Is4() || !target.Addr().Is4() || target.Port() == 0 {
		return nil, fmt.Errorf("%w: zincir yalnızca IPv4 uç noktalarla çalışır", ErrChain)
	}
	return packet.BuildUDP4(self, target.Addr(), chainPort, target.Port(), datagram)
}

// decapChain returns the WireGuard datagram inside a packet that came back
// from the entry node: UDP from the final exit's endpoint to this device's
// chain port. ok is false for anything else.
func decapChain(pkt []byte, self netip.Addr, target netip.AddrPort) ([]byte, bool) {
	in, err := packet.Parse(pkt)
	if err != nil || in.Proto != packet.ProtoUDP || in.Fragment {
		return nil, false
	}
	if in.Dst != self || in.DstPort != chainPort || in.Src != target.Addr() || in.SrcPort != target.Port() {
		return nil, false
	}
	return in.Payload, true
}

// ChainStatus describes the two-hop exit.
type ChainStatus struct {
	Entry string `json:"entry,omitempty"`
	Final string `json:"final,omitempty"`
	// Ready is true when the plan is valid against the document.
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
	// Wired is true only when the path through the final exit was verified
	// end to end recently: on an entry, by packets back from the final; on
	// a member, by the entry's answer (#618, ADR-0222). The local nested
	// plan of ADR-0187 never sets it.
	Wired bool `json:"wired"`
	// Signed: the chain comes from the signed document (ADR-0222); Role is
	// "entry" on the entry node and "member" on a device using it.
	Signed     bool      `json:"signed,omitempty"`
	Role       string    `json:"role,omitempty"`
	VerifiedAt time.Time `json:"verified_at,omitempty"`
}

// ExitChainStatus checks the configured chain against the document.
func (e *Engine) ExitChainStatus() ChainStatus {
	if self, err := e.Self(); err == nil {
		if st, ok := e.chainEntryStatus(self.Name); ok {
			return st
		}
	}
	if st, ok := e.chainMemberStatus(); ok {
		return st
	}
	c := e.cfg.G3.ExitChain
	st := ChainStatus{Entry: c.Entry, Final: e.ExitNode()}
	if c.Entry == "" {
		st.Reason = "kapalı"
		return st
	}
	self, err := e.Self()
	if err != nil {
		st.Reason = err.Error()
		return st
	}
	e.mu.Lock()
	want := e.exitWant
	e.mu.Unlock()
	if st.Final == "" {
		st.Final = want
	}
	if _, _, err := chainPlan(e.cfg.Store.Document(), self, c.Entry, st.Final); err != nil {
		st.Reason = err.Error()
		return st
	}
	st.Ready = true
	st.Reason = "Yerel iç içe zincir (ADR-0187) trafiğe bağlı değil; imzalı zinciri kullanın: openscale exit chain set --entry <giriş> --final <son>."
	return st
}
