package node

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Signed two-hop exit (#618, ADR-0222). The root-signed document may name
// a chain entry → final (trust.ExitChain). Members choose the entry exit
// node as usual. The entry does not write their internet traffic to its
// operating system: it translates each packet to its own overlay address
// in user space and sends it through the tunnel to the final exit node,
// which forwards it like any member's traffic. Replies come back the same
// way and are translated back to the member. So:
//
//   - the final exit and the internet see only the entry's overlay address
//     (inside the tunnel) and the final's public address, never the member;
//   - the entry sees the member and the destinations, like any exit node.
//
// This is the upstream-exit model of ADR-0142 with an OpenScale exit node
// as the upstream, done in the engine instead of policy routing, so no
// system setting changes and the path can be tested on 127.0.0.1.
//
// Fail closed: while the chain is in the document but cannot be used (the
// final lost its role, expired, exit_users excludes the entry, the final
// does not answer), the entry drops members' internet traffic and their
// DNS; it never sends it out itself. Members' IPv6 internet traffic and
// fragments are always dropped on a chained entry, and ICMP errors from
// internet routers are not translated (TCP MSS is clamped to the tunnel).
//
// The entry checks the final every chainProbeEvery with a DNS query to
// the final's exit resolver through the tunnel; any packet back from the
// final also counts. Members ask the entry on chainStatusPort whether its
// path is verified; the panel says "ready" only then.

const (
	chainProbePort  = 4062 // the entry's source port for its DNS probe to the final
	chainStatusPort = 4063 // members ask the entry for the chain state

	chainPortLo   = 20000
	chainPortHi   = 60999
	chainMaxFlows = 8192
	chainUDPIdle  = 2 * time.Minute
	chainTCPIdle  = 10 * time.Minute
)

// chainProbeEvery and chainFresh (how recent the last packet from the final
// must be for the path to count as verified) are variables for tests.
var (
	chainProbeEvery = 10 * time.Second
	chainFresh      = 45 * time.Second
)

var chainStatusMagic = []byte("OSCHAIN1")

type chainKey struct {
	proto uint8
	src   netip.AddrPort // the member
	dst   netip.AddrPort // the destination the member addressed
}

type chainRev struct {
	proto  uint8
	mapped uint16
	remote netip.AddrPort // the destination after translation
}

type chainFlow struct {
	key    chainKey
	remote netip.AddrPort
	mapped uint16
	// filtered: member internet traffic tracked by the packet filter;
	// relayed DNS is not, the entry answers it on the member's behalf.
	filtered bool
	last     time.Time
}

// chainRelay is the engine's two-hop exit state.
type chainRelay struct {
	// entry is set while this device is the entry of a signed chain; the
	// relay then consumes members' internet traffic whatever happens.
	entry atomic.Bool
	// asking is set while this device asks its exit node for the chain
	// state.
	asking atomic.Bool
	start  sync.Once

	mu       sync.Mutex
	final    string
	finalIP  netip.Addr
	selfIP   netip.Addr
	usable   bool
	reason   string
	overlay  netip.Prefix
	overlay6 netip.Prefix
	members  map[netip.Addr]bool
	flows    map[chainKey]*chainFlow
	rev      map[chainRev]*chainFlow
	next     uint16
	lastBack time.Time // last packet from the final
	probeID  uint16

	// Member side: the exit node in use and its answer.
	askEntry, askFinal string
	askIP              netip.Addr
	askVerified        bool
	askAt              time.Time
}

// chainPeers updates the chain state from the document. On an entry it
// gives the final exit every IPv4 internet address and keeps it configured.
func (e *Engine) chainPeers(doc *trust.Document, self trust.Device, expired bool, want map[trust.Key]wgconf.Peer, always map[trust.Key]bool) {
	r := &e.chain
	now := e.cfg.Now()
	finalName, chained := doc.ExitChainOf(self.Name)
	chained = chained && self.HasRole(trust.RoleExitNode)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.selfIP, r.overlay, r.overlay6 = self.IPv4, doc.IPv4Prefix, doc.IPv6Prefix
	r.final, r.finalIP, r.usable, r.reason = finalName, netip.Addr{}, false, ""
	r.members = map[netip.Addr]bool{}
	for _, d := range doc.Devices {
		if d.Name != self.Name && d.IPv4.IsValid() && now.Before(d.ExpiresAt) && doc.MayUseExitNode(d.Name) {
			r.members[d.IPv4] = true
		}
	}
	r.entry.Store(chained)
	if chained {
		final, ok := doc.DeviceByName(finalName)
		switch {
		case expired:
			r.reason = "belgenin veya bu cihazın süresi doldu"
		case !ok:
			r.reason = "son çıkış düğümü " + finalName + " belgede yok"
		case !final.HasRole(trust.RoleExitNode):
			r.reason = finalName + " bir çıkış düğümü değil"
		case !now.Before(final.ExpiresAt):
			r.reason = finalName + " cihazının süresi doldu"
		case !doc.MayUseExitNode(self.Name):
			r.reason = "belge bu cihaza çıkış düğümü kullanma izni vermiyor (exit_users)"
		case !final.IPv4.IsValid():
			r.reason = finalName + " cihazının IPv4 adresi yok"
		default:
			if p, ok := want[final.WireGuardKey]; ok {
				p.AllowedIPs = append(p.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
				want[final.WireGuardKey] = p
				always[final.WireGuardKey] = true
				r.finalIP, r.usable = final.IPv4, true
			} else {
				r.reason = finalName + " bu cihazın eşi değil"
			}
		}
	} else {
		r.dropFlowsLocked()
	}
	if !r.usable {
		r.lastBack = time.Time{}
	}
	if e.wrap != nil {
		r.start.Do(func() { go e.chainLoop() })
	}
}

func (r *chainRelay) dropFlowsLocked() {
	r.flows, r.rev = nil, nil
}

// chainLoop probes the final exit (entry side) and asks the exit node in
// use for its chain state (member side).
func (e *Engine) chainLoop() {
	t := time.NewTicker(chainProbeEvery)
	defer t.Stop()
	for {
		e.chainTick()
		w := e.wrap
		if w == nil {
			return
		}
		select {
		case <-w.closed:
			return
		case <-t.C:
		}
	}
}

func (e *Engine) chainTick() {
	if e.filter != nil && e.filter.Isolated() {
		return // lost mode: only the coordinator tunnel stays
	}
	r := &e.chain
	now := e.cfg.Now()
	var out [][]byte
	r.mu.Lock()
	r.gcLocked(now)
	if r.entry.Load() && r.usable {
		r.probeID++
		if q, err := chainProbeQuery(r.probeID); err == nil {
			if pkt, err := packet.BuildUDP4(r.selfIP, r.finalIP, chainProbePort, dnsPort, q); err == nil {
				out = append(out, pkt)
			}
		}
	}
	selfIP := r.selfIP
	r.mu.Unlock()

	// Member side: ask the exit node in use whether its chain is verified.
	exit := e.ExitNode()
	doc := e.cfg.Store.Document()
	final, chained := "", false
	var exitIP netip.Addr
	if exit != "" && doc != nil {
		final, chained = doc.ExitChainOf(exit)
		if d, ok := doc.DeviceByName(exit); ok {
			exitIP = d.IPv4
		}
	}
	r.mu.Lock()
	if !chained || r.entry.Load() || !exitIP.IsValid() || !selfIP.IsValid() {
		r.asking.Store(false)
		r.askEntry, r.askFinal, r.askIP, r.askVerified = "", "", netip.Addr{}, false
	} else {
		if r.askEntry != exit || r.askFinal != final {
			r.askVerified, r.askAt = false, time.Time{}
		}
		r.askEntry, r.askFinal, r.askIP = exit, final, exitIP
		r.asking.Store(true)
		if pkt, err := packet.BuildUDP4(selfIP, exitIP, chainStatusPort, chainStatusPort, chainStatusMagic); err == nil {
			out = append(out, pkt)
		}
	}
	r.mu.Unlock()
	if w := e.wrap; w != nil {
		for _, p := range out {
			w.Inject(p)
		}
	}
}

func chainProbeQuery(id uint16) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// chainIntercept handles packets from peers that belong to the chain. It
// returns true for every packet it consumed, forwarded or dropped.
func (e *Engine) chainIntercept(pkt []byte) bool {
	r := &e.chain
	entry, asking := r.entry.Load(), r.asking.Load()
	if !entry && !asking {
		return false
	}
	if len(pkt) == 0 {
		return false
	}
	if pkt[0]>>4 == 6 {
		if !entry {
			return false
		}
		in, err := packet.Parse(pkt)
		if err != nil {
			return false
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		// No IPv6 through the chain: a member's IPv6 internet traffic is
		// dropped rather than sent out by this node.
		return r.overlay6.IsValid() && r.overlay6.Contains(in.Src) && chainInternet(in.Dst, r.overlay6)
	}
	in, err := packet.Parse(pkt)
	if err != nil {
		return false
	}
	now := e.cfg.Now()
	r.mu.Lock()
	if asking && !entry {
		ok := in.Proto == packet.ProtoUDP && !in.Fragment && in.Src == r.askIP && in.Dst == r.selfIP &&
			in.SrcPort == chainStatusPort && in.DstPort == chainStatusPort
		if ok {
			if p := in.Payload; len(p) == len(chainStatusMagic)+1 && bytes.Equal(p[:len(chainStatusMagic)], chainStatusMagic) {
				r.askVerified, r.askAt = p[len(chainStatusMagic)] == 1, now
			}
		}
		r.mu.Unlock()
		return ok
	}
	out, consumed, filtered, back := r.handleLocked(in, pkt, now)
	r.mu.Unlock()
	if out == nil {
		return consumed
	}
	if !filtered && e.chainMemberRefused(in, out, back) {
		// Relayed DNS and the chain state do not pass the filter, so its
		// quarantine and lost mode decision is applied here (exitdns_g3.go).
		if !back {
			r.mu.Lock()
			r.forgetLocked(in)
			r.mu.Unlock()
		}
		return true
	}
	if back && filtered && !e.filter.Outbound(out) {
		return true
	}
	if !back && filtered && !e.filter.Inbound(pkt) {
		// The filter decides who may use the exit (exit_users) and keeps
		// the flow state; a refused packet is dropped, never sent out.
		r.mu.Lock()
		r.forgetLocked(in)
		r.mu.Unlock()
		return true
	}
	if e.wrap != nil {
		e.wrap.Inject(out)
	}
	return true
}

// chainMemberRefused reports whether the member of an unfiltered packet is
// refused: the source of in, or the destination of out when it goes back.
func (e *Engine) chainMemberRefused(in packet.Info, out []byte, back bool) bool {
	if !back {
		return e.peerAddrRefused(in.Src)
	}
	to, err := packet.Parse(out)
	return err != nil || e.peerAddrRefused(to.Dst)
}

// chainInternet reports whether a is a public destination: not in the
// overlay, private, shared, loopback, link-local or multicast.
func chainInternet(a netip.Addr, overlay netip.Prefix) bool {
	a = a.Unmap()
	if overlay.IsValid() && overlay.Contains(a) {
		return false
	}
	return a.IsGlobalUnicast() && !a.IsPrivate() && !chainShared.Contains(a)
}

var (
	chainShared    = netip.MustParsePrefix("100.64.0.0/10")
	errChainPacket = errors.New("zincir: geçersiz paket")
)

// handleLocked decides what to do with one IPv4 packet on an entry. out is
// the translated packet to inject; back marks a packet going to a member.
func (r *chainRelay) handleLocked(in packet.Info, pkt []byte, now time.Time) (out []byte, consumed, filtered, back bool) {
	// The final's answer to the entry's own probe.
	if in.Proto == packet.ProtoUDP && in.Src == r.finalIP && in.SrcPort == dnsPort && in.Dst == r.selfIP && in.DstPort == chainProbePort {
		if r.usable {
			r.lastBack = now
		}
		return nil, true, false, false
	}
	// A member asks for the chain state.
	if in.Proto == packet.ProtoUDP && in.Dst == r.selfIP && in.DstPort == chainStatusPort {
		if !r.members[in.Src] || in.SrcPort != chainStatusPort || !bytes.Equal(in.Payload, chainStatusMagic) {
			return nil, true, false, false
		}
		state := byte(0)
		if r.verifiedLocked(now) {
			state = 1
		}
		reply, err := packet.BuildUDP4(r.selfIP, in.Src, chainStatusPort, chainStatusPort, append(append([]byte(nil), chainStatusMagic...), state))
		if err != nil {
			return nil, true, false, false
		}
		return reply, true, false, true
	}
	// A reply from the final for a translated flow.
	if in.Dst == r.selfIP && !in.Fragment {
		port, ok := chainPortOf(in, false)
		if ok {
			if f := r.rev[chainRev{in.Proto, port, netip.AddrPortFrom(in.Src, chainRemotePort(in, false))}]; f != nil {
				if !r.usable {
					return nil, true, false, false
				}
				f.last, r.lastBack = now, now
				cp, err := chainRewrite(pkt, f.key.dst, f.key.src)
				if err != nil {
					return nil, true, false, false
				}
				return cp, true, f.filtered, true
			}
		}
	}
	if !r.members[in.Src] {
		return nil, false, false, false
	}
	dns := in.Dst == r.selfIP && in.DstPort == dnsPort && (in.Proto == packet.ProtoUDP || in.Proto == packet.ProtoTCP)
	internet := chainInternet(in.Dst, r.overlay)
	if !dns && !internet {
		return nil, false, false, false
	}
	// From here on the packet is the chain's: forwarded or dropped.
	if !r.usable || in.Fragment || in.MoreFragments {
		return nil, true, false, false
	}
	if in.Proto == packet.ProtoICMPv4 && !in.IsEchoRequest() {
		return nil, true, false, false
	}
	if in.Proto != packet.ProtoTCP && in.Proto != packet.ProtoUDP && in.Proto != packet.ProtoICMPv4 {
		return nil, true, false, false
	}
	srcPort, _ := chainPortOf(in, true)
	key := chainKey{in.Proto, netip.AddrPortFrom(in.Src, srcPort), netip.AddrPortFrom(in.Dst, chainRemotePort(in, true))}
	remote := key.dst
	if dns {
		remote = netip.AddrPortFrom(r.finalIP, dnsPort)
	}
	f := r.flows[key]
	if f == nil {
		var ok bool
		if f, ok = r.newFlowLocked(key, remote, now); !ok {
			return nil, true, false, false
		}
		f.filtered = !dns
	}
	f.last = now
	cp, err := chainRewrite(pkt, netip.AddrPortFrom(r.selfIP, f.mapped), remote)
	if err != nil {
		return nil, true, false, false
	}
	return cp, true, f.filtered, false
}

func (r *chainRelay) verifiedLocked(now time.Time) bool {
	return r.usable && !r.lastBack.IsZero() && now.Sub(r.lastBack) < chainFresh
}

func (r *chainRelay) newFlowLocked(key chainKey, remote netip.AddrPort, now time.Time) (*chainFlow, bool) {
	if r.flows == nil {
		r.flows, r.rev = map[chainKey]*chainFlow{}, map[chainRev]*chainFlow{}
	}
	if len(r.flows) >= chainMaxFlows {
		r.gcLocked(now)
		if len(r.flows) >= chainMaxFlows {
			return nil, false
		}
	}
	span := uint16(chainPortHi - chainPortLo + 1)
	for range int(span) {
		r.next = (r.next + 1) % span
		port := chainPortLo + r.next
		rk := chainRev{key.proto, port, remote}
		if r.rev[rk] != nil {
			continue
		}
		f := &chainFlow{key: key, remote: remote, mapped: port, last: now}
		r.flows[key], r.rev[rk] = f, f
		return f, true
	}
	return nil, false
}

func (r *chainRelay) forgetLocked(in packet.Info) {
	srcPort, _ := chainPortOf(in, true)
	key := chainKey{in.Proto, netip.AddrPortFrom(in.Src, srcPort), netip.AddrPortFrom(in.Dst, chainRemotePort(in, true))}
	if f := r.flows[key]; f != nil {
		delete(r.flows, key)
		delete(r.rev, chainRev{key.proto, f.mapped, f.remote})
	}
}

func (r *chainRelay) gcLocked(now time.Time) {
	for k, f := range r.flows {
		idle := chainUDPIdle
		if k.proto == packet.ProtoTCP {
			idle = chainTCPIdle
		}
		if now.Sub(f.last) > idle {
			delete(r.flows, k)
			delete(r.rev, chainRev{k.proto, f.mapped, f.remote})
		}
	}
}

// chainPortOf returns the member-side identifier: the source port of an
// outgoing packet (fromMember) or the destination port of a reply; the
// echo identifier for ICMP.
func chainPortOf(in packet.Info, fromMember bool) (uint16, bool) {
	switch in.Proto {
	case packet.ProtoTCP, packet.ProtoUDP:
		if fromMember {
			return in.SrcPort, true
		}
		return in.DstPort, true
	case packet.ProtoICMPv4:
		if fromMember && in.IsEchoRequest() || !fromMember && in.IsEchoReply() {
			return in.ICMPID, true
		}
	}
	return 0, false
}

// chainRemotePort is the far end's port; zero for ICMP.
func chainRemotePort(in packet.Info, fromMember bool) uint16 {
	if in.Proto != packet.ProtoTCP && in.Proto != packet.ProtoUDP {
		return 0
	}
	if fromMember {
		return in.DstPort
	}
	return in.SrcPort
}

// chainRewrite returns a copy of an IPv4 packet with new source and
// destination; ports (or the ICMP echo identifier, which src carries) are
// replaced and every checksum is computed again.
func chainRewrite(pkt []byte, src, dst netip.AddrPort) ([]byte, error) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil, errChainPacket
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || total < ihl || total > len(pkt) {
		return nil, errChainPacket
	}
	cp := append([]byte(nil), pkt[:total]...)
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(cp[12:16], s4[:])
	copy(cp[16:20], d4[:])
	cp[10], cp[11] = 0, 0
	binary.BigEndian.PutUint16(cp[10:12], chainSum(cp[:ihl], 0))
	seg := cp[ihl:]
	switch cp[9] {
	case packet.ProtoTCP, packet.ProtoUDP:
		csOff := 16
		if cp[9] == packet.ProtoUDP {
			if len(seg) < 8 {
				return nil, errChainPacket
			}
			csOff = 6
		} else if len(seg) < 20 {
			return nil, errChainPacket
		}
		binary.BigEndian.PutUint16(seg[0:2], src.Port())
		binary.BigEndian.PutUint16(seg[2:4], dst.Port())
		seg[csOff], seg[csOff+1] = 0, 0
		var pseudo uint32
		pseudo += uint32(binary.BigEndian.Uint16(s4[0:2])) + uint32(binary.BigEndian.Uint16(s4[2:4]))
		pseudo += uint32(binary.BigEndian.Uint16(d4[0:2])) + uint32(binary.BigEndian.Uint16(d4[2:4]))
		pseudo += uint32(cp[9]) + uint32(len(seg))
		cs := chainSum(seg, pseudo)
		if cp[9] == packet.ProtoUDP && cs == 0 {
			cs = 0xffff
		}
		binary.BigEndian.PutUint16(seg[csOff:csOff+2], cs)
	case packet.ProtoICMPv4:
		if len(seg) < 8 {
			return nil, errChainPacket
		}
		// Echo request: the identifier is the source side's; echo reply:
		// the destination side's.
		id := src.Port()
		if seg[0] == 0 {
			id = dst.Port()
		}
		binary.BigEndian.PutUint16(seg[4:6], id)
		seg[2], seg[3] = 0, 0
		binary.BigEndian.PutUint16(seg[2:4], chainSum(seg, 0))
	default:
		return nil, errChainPacket
	}
	return cp, nil
}

func chainSum(b []byte, sum uint32) uint16 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

// chainEntryStatus is the chain state on an entry; ok is false elsewhere.
func (e *Engine) chainEntryStatus(selfName string) (ChainStatus, bool) {
	r := &e.chain
	if !r.entry.Load() {
		return ChainStatus{}, false
	}
	now := e.cfg.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	st := ChainStatus{Entry: selfName, Final: r.final, Ready: r.usable, Signed: true, Role: "entry"}
	switch {
	case !r.usable:
		st.Reason = "Zincir belgede tanımlı ama kullanılamıyor: " + r.reason + ". Üyelerin internet trafiği bu düğümden doğrudan çıkmıyor, düşürülüyor."
	case r.verifiedLocked(now):
		st.Wired = true
		st.VerifiedAt = r.lastBack
	default:
		st.Reason = "Son çıkış düğümü " + r.final + " yanıt vermiyor; üyelerin internet trafiği düşürülüyor (kapalı başarısızlık)."
	}
	return st, true
}

// chainMemberStatus is the state reported by the entry this device uses.
func (e *Engine) chainMemberStatus() (ChainStatus, bool) {
	r := &e.chain
	if !r.asking.Load() {
		return ChainStatus{}, false
	}
	now := e.cfg.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	st := ChainStatus{Entry: r.askEntry, Final: r.askFinal, Ready: true, Signed: true, Role: "member"}
	switch {
	case r.askAt.IsZero() || now.Sub(r.askAt) > 3*chainProbeEvery:
		st.Reason = "Giriş düğümü " + r.askEntry + " zincir durumunu bildirmedi."
	case !r.askVerified:
		st.Reason = "Giriş düğümü " + r.askEntry + " son çıkışa (" + r.askFinal + ") ulaşamıyor; internet trafiği düşürülüyor."
	default:
		st.Wired = true
		st.VerifiedAt = r.askAt
	}
	return st, true
}
