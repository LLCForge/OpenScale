package node

import (
	mrand "math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/testnet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// natPair is two probers behind simulated NATs (internal/testnet).
type natPair struct {
	a, b       *probeNode
	natA, natB *testnet.NAT
	net        *testnet.NATNet
	now        time.Time
}

func newNATPair(t *testing.T, seed uint64, m testnet.NATMapping, f testnet.NATFiltering) *natPair {
	t.Helper()
	np := &natPair{now: time.Now()}
	clock := func() time.Time { return np.now }
	pn := newProbeNet()
	np.a = newProbeNode(t, pn, clock, "a", "192.168.1.10:41641")
	np.b = newProbeNode(t, pn, clock, "b", "10.0.0.20:51820")
	np.natA = testnet.NewNAT(netip.MustParseAddr("198.51.100.10"), m, f, seed)
	np.natB = testnet.NewNAT(netip.MustParseAddr("203.0.113.20"), m, f, seed+1000)
	np.net = testnet.NewNATNet(np.natA, np.natB)
	owner := map[netip.AddrPort]*prober{np.a.addrs[0]: np.a.p, np.b.addrs[0]: np.b.p}
	wire := func(n *probeNode, nat *testnet.NAT) {
		n.p.sendDirect = func(pkt []byte, to netip.AddrPort) error {
			src, dst, ok := np.net.Send(nat, n.addrs[0], to)
			if !ok {
				return nil
			}
			if p := owner[dst]; p != nil {
				p.handle(probeIn{data: append([]byte(nil), pkt...), from: src})
			}
			return nil
		}
		n.p.scanPace = 0
		n.p.selfHard = func() bool { return true }
		n.p.scanRand = mrand.New(mrand.NewPCG(seed, uint64(len(n.dev.Name))))
	}
	wire(np.a, np.natA)
	wire(np.b, np.natB)
	pair(np.a, np.b)
	// What the coordinator observed: each side's mapping toward it.
	coord := netip.MustParseAddrPort("192.0.2.1:4040")
	obsA, _ := np.natA.Outbound(np.a.addrs[0], coord)
	obsB, _ := np.natB.Outbound(np.b.addrs[0], coord)
	np.a.p.setInfo(np.b.dev.WireGuardKey, obsB, nil)
	np.b.p.setInfo(np.a.dev.WireGuardKey, obsA, nil)
	hints := sealedPayload{hardNAT: true, scan: true}
	np.a.p.setSealed(np.b.dev.ID, hints)
	np.b.p.setSealed(np.a.dev.ID, hints)
	return np
}

// rounds runs relayed probe rounds on a until it starts a scan, then lets
// b answer the call the way the coordinator push would.
func (np *natPair) scan(t *testing.T) (calledB bool) {
	t.Helper()
	st := statusOf(np.b.dev)
	for i := 0; i < 6 && np.a.p.scans == 0; i++ {
		for _, id := range np.a.p.round(st, staleHandshake) {
			if id == np.b.dev.ID && np.a.p.scans > 0 {
				calledB = true
			}
		}
		np.now = np.now.Add(probeMaxWait)
	}
	np.now = np.now.Add(-probeMaxWait + time.Second)
	if calledB {
		obsA, _ := np.natA.Outbound(np.a.addrs[0], netip.MustParseAddrPort("192.0.2.1:4040"))
		np.b.p.called(np.a.dev.ID, obsA, nil)
	}
	return calledB
}

// Two devices behind NATs with random per-destination ports and address
// filtering find a direct path with the bounded birthday scan, within the
// packet budget.
func TestBirthdayScanThroughSymmetricNATs(t *testing.T) {
	const trials = 10
	found := 0
	for seed := uint64(1); seed <= trials; seed++ {
		np := newNATPair(t, seed, testnet.MapRandom, testnet.FilterAddress)
		if !np.scan(t) {
			t.Fatalf("seed %d: no scan or no call", seed)
		}
		if np.a.p.scans != 1 || np.b.p.scans != 1 {
			t.Fatalf("seed %d: scans a=%d b=%d", seed, np.a.p.scans, np.b.p.scans)
		}
		// Each side sent at most one scan plus its few plain probes.
		if sent := np.net.Sent(); sent > 2*(DefaultBirthdayProbes+16) {
			t.Fatalf("seed %d: %d datagrams", seed, sent)
		}
		if ap, ok := np.b.p.validated(np.a.dev.WireGuardKey, probeFresh); ok {
			if ap.Addr() != np.natA.Public() {
				t.Fatalf("seed %d: validated %v", seed, ap)
			}
			found++
		}
	}
	// 1 - exp(-256*256/64512) is about 64 %; the seeded run is fixed.
	if found < trials/3 {
		t.Fatalf("birthday scan found a path in %d of %d runs", found, trials)
	}
	t.Logf("birthday scan found a path in %d of %d runs", found, trials)
}

// Address-and-port filtering NATs need a double coincidence: the scan stays
// within its budget and gives up (the relay keeps working).
func TestBirthdayScanBoundedAgainstPortRestrictedNATs(t *testing.T) {
	np := newNATPair(t, 7, testnet.MapRandom, testnet.FilterAddressPort)
	np.scan(t)
	if _, ok := np.b.p.validated(np.a.dev.WireGuardKey, probeFresh); ok {
		t.Fatal("path validated through port-restricted NATs")
	}
	before := np.net.Sent()
	// No second scan of the same peer within birthdayEvery, however often
	// the rounds or calls come.
	for i := 0; i < 5; i++ {
		np.now = np.now.Add(time.Minute)
		np.a.p.round(statusOf(np.b.dev), staleHandshake)
		np.b.p.called(np.a.dev.ID, netip.AddrPort{}, nil)
	}
	if np.a.p.scans != 1 || np.b.p.scans != 1 {
		t.Fatalf("rescanned: a=%d b=%d", np.a.p.scans, np.b.p.scans)
	}
	if extra := np.net.Sent() - before; extra > 40 {
		t.Fatalf("%d datagrams after the scan", extra)
	}
}

// The scan never starts unless both sides say their NAT is hard, the owner
// left it on, the peer is relayed after failed rounds and its address is a
// public IPv4 one; and the hourly budget caps it across peers.
func TestBirthdayScanEligibility(t *testing.T) {
	np := newNATPair(t, 3, testnet.MapRandom, testnet.FilterAddress)
	p, pp := np.a.p, np.a.p.peers[np.b.dev.ID]
	now := np.now
	if !p.scanEligibleLocked(pp, true, now) {
		t.Fatal("eligible pair refused")
	}
	if p.scanEligibleLocked(pp, false, now) {
		t.Fatal("scan with an easy NAT on this side")
	}
	pp.peerHard = false
	if p.scanEligibleLocked(pp, true, now) {
		t.Fatal("scan with an easy NAT on the peer's side")
	}
	pp.peerHard, pp.peerScan = true, false
	if p.scanEligibleLocked(pp, true, now) {
		t.Fatal("scan although the peer opted out")
	}
	pp.peerScan = true
	saved := pp.observed
	for _, s := range []string{"10.1.2.3:4000", "100.64.0.9:4000", "[2001:db8::1]:4000"} {
		pp.observed = netip.MustParseAddrPort(s)
		if p.scanEligibleLocked(pp, true, now) {
			t.Fatalf("scan of %s", s)
		}
	}
	pp.observed = saved
	if err := p.configureBirthday(true, 0); err != nil {
		t.Fatal(err)
	}
	if p.scanEligibleLocked(pp, true, now) {
		t.Fatal("scan although turned off")
	}
	for _, n := range []int{MinBirthdayProbes - 1, MaxBirthdayProbes + 1} {
		if err := p.configureBirthday(false, n); err == nil {
			t.Fatalf("%d probes accepted", n)
		}
	}
	if err := p.configureBirthday(false, MaxBirthdayProbes); err != nil {
		t.Fatal(err)
	}
	// Budget: four full scans an hour, whatever the peers.
	for i := 0; i < birthdayBudget/MaxBirthdayProbes; i++ {
		pp.lastScan = time.Time{}
		if !p.scanEligibleLocked(pp, true, now) {
			t.Fatalf("scan %d refused within the budget", i)
		}
		p.scanPingsLocked(pp, now)
	}
	pp.lastScan = time.Time{}
	if p.scanEligibleLocked(pp, true, now) {
		t.Fatal("budget exceeded")
	}
	if !p.scanEligibleLocked(pp, true, now.Add(time.Hour)) {
		t.Fatal("budget not refilled after an hour")
	}
	// A healthy direct peer is never scanned by round.
	direct := wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{}}
	direct.Peers[np.b.dev.WireGuardKey] = wgconf.PeerStatus{Endpoint: netip.MustParseAddrPort("203.0.113.20:5000"), LastHandshakeUnix: now.Unix()}
	before := p.scans
	for i := 0; i < 4; i++ {
		np.now = np.now.Add(probeMaxWait)
		p.round(direct, staleHandshake)
	}
	if p.scans != before {
		t.Fatal("direct peer scanned")
	}
}

func TestBirthdayPortsDistinctAndBounded(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	addr := netip.MustParseAddr("203.0.113.9")
	skip := []netip.AddrPort{netip.AddrPortFrom(addr, 40000)}
	got := birthdayPorts(rng, addr, MaxBirthdayProbes, skip)
	if len(got) != MaxBirthdayProbes {
		t.Fatalf("%d ports", len(got))
	}
	seen := map[netip.AddrPort]bool{}
	for _, ap := range got {
		if ap.Addr() != addr || ap.Port() < birthdayMinPort || seen[ap] || ap == skip[0] {
			t.Fatalf("bad port %v", ap)
		}
		seen[ap] = true
	}
}
