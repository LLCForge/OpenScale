package node

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

type sealSide struct {
	s   *sealer
	dev trust.Device
}

func newSealSide(t *testing.T, name string) sealSide {
	t.Helper()
	sec, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sig, wg, err := sec.PublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSealer(sec.WireGuardPrivate, wg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return sealSide{s: s, dev: trust.Device{ID: sec.DeviceID, Name: name, SigningKey: sig, WireGuardKey: wg, ExpiresAt: time.Now().Add(time.Hour)}}
}

var sealTestCands = []netip.AddrPort{
	netip.MustParseAddrPort("192.168.44.17:41641"),
	netip.MustParseAddrPort("[2001:db8:44::17]:41641"),
	netip.MustParseAddrPort("203.0.113.44:51820"),
}

// The coordinator relays the blob but cannot read it, cannot change it,
// cannot replay it, cannot reflect it back and cannot move it to another
// network or receiver: every one of those fails to open.
func TestSealedBlobIsOpaqueAndAuthenticated(t *testing.T) {
	const network = "ag-1"
	a, b, c := newSealSide(t, "a"), newSealSide(t, "b"), newSealSide(t, "c")
	now := time.Now()
	payload := sealedPayload{cands: sealTestCands, hardNAT: true, scan: true}
	blob, err := a.s.seal(network, a.dev.ID, b.dev, payload, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) > control.MaxSealed {
		t.Fatalf("blob of %d bytes exceeds MaxSealed", len(blob))
	}
	// Nothing readable: no address in text or binary form.
	for _, ap := range sealTestCands {
		raw := ap.Addr().As16()
		if bytes.Contains(blob, raw[:]) || strings.Contains(string(blob), ap.Addr().String()) {
			t.Fatalf("blob shows %s", ap)
		}
	}

	got, err := b.s.open(network, b.dev.ID, a.dev, blob, now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(got.cands) != len(sealTestCands) || !got.hardNAT || !got.scan {
		t.Fatalf("payload %+v", got)
	}
	for i := range sealTestCands {
		if got.cands[i] != sealTestCands[i] {
			t.Fatalf("cand %d = %v", i, got.cands[i])
		}
	}
	if !b.s.capable(a.dev.ID) {
		t.Fatal("a valid blob does not prove the peer reads sealed blobs")
	}

	// Replay: the same blob a second time.
	if _, err := b.s.open(network, b.dev.ID, a.dev, blob, now); !errors.Is(err, errSealReplay) {
		t.Fatalf("replay: %v", err)
	}
	// A third device (or a coordinator with its own key) cannot open it as
	// if it came from a.
	if _, err := c.s.open(network, c.dev.ID, a.dev, blob, now); !errors.Is(err, errSealOpen) {
		t.Fatalf("third party: %v", err)
	}
	// Reflected back to a as if b sent it: the direction keys differ.
	if _, err := a.s.open(network, a.dev.ID, b.dev, blob, now); !errors.Is(err, errSealOpen) {
		t.Fatalf("reflection: %v", err)
	}
	// Another network with the same keys.
	blob2, _ := a.s.seal(network, a.dev.ID, b.dev, payload, now)
	if _, err := b.s.open("ag-2", b.dev.ID, a.dev, blob2, now); err == nil {
		t.Fatal("blob opened in another network")
	}
	// Every single flipped bit is refused.
	blob3, _ := a.s.seal(network, a.dev.ID, b.dev, payload, now)
	for i := range blob3 {
		bad := bytes.Clone(blob3)
		bad[i] ^= 0x04
		if _, err := b.s.open(network, b.dev.ID, a.dev, bad, now); err == nil {
			t.Fatalf("flipped byte %d accepted", i)
		}
	}
	if _, err := b.s.open(network, b.dev.ID, a.dev, blob3[:len(blob3)-1], now); err == nil {
		t.Fatal("truncated blob accepted")
	}
	if _, err := b.s.open(network, b.dev.ID, a.dev, blob3, now); err != nil {
		t.Fatalf("intact blob after the forgeries: %v", err)
	}
	// An older blob (lower counter) after a newer one is a replay too.
	older, _ := a.s.seal(network, a.dev.ID, b.dev, payload, now)
	newer, _ := a.s.seal(network, a.dev.ID, b.dev, payload, now)
	if _, err := b.s.open(network, b.dev.ID, a.dev, newer, now); err != nil {
		t.Fatal(err)
	}
	if _, err := b.s.open(network, b.dev.ID, a.dev, older, now); !errors.Is(err, errSealReplay) {
		t.Fatalf("reordered: %v", err)
	}
	// A blob captured and held back too long is refused by its clock.
	late, _ := a.s.seal(network, a.dev.ID, b.dev, payload, now)
	if _, err := b.s.open(network, b.dev.ID, a.dev, late, now.Add(sealMaxAge+time.Minute)); !errors.Is(err, errSealClock) {
		t.Fatalf("stale: %v", err)
	}
}

func TestSealedPayloadDecodeBounds(t *testing.T) {
	enc := encodeSealedPayload(sealedPayload{cands: sealTestCands})
	if _, err := decodeSealedPayload(enc); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, {0}, {0x80, 0}, {0, 1}, {0, control.MaxCandidates + 1}, append(bytes.Clone(enc), 0)} {
		if _, err := decodeSealedPayload(bad); err == nil {
			t.Errorf("payload %x accepted", bad)
		}
	}
	// A family byte that does not match the address is refused.
	wrong := bytes.Clone(enc)
	wrong[2+18] = 6 // first entry is IPv4
	if _, err := decodeSealedPayload(wrong); err == nil {
		t.Fatal("IPv4 entry marked IPv6 accepted")
	}
	// Unusable addresses (loopback) are dropped, not fatal.
	p, err := decodeSealedPayload(encodeSealedPayload(sealedPayload{cands: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1"), sealTestCands[0]}}))
	if err != nil || len(p.cands) != 1 || p.cands[0] != sealTestCands[0] {
		t.Fatalf("filtered = %+v %v", p, err)
	}
}

func TestPlainCandidatesDecision(t *testing.T) {
	cases := []struct {
		mode                     SealedCandidatesMode
		coord, listed, legacy, w bool
	}{
		{SealedCandidatesOff, true, true, false, true},
		{SealedCandidatesOnly, false, false, true, false},
		{SealedCandidatesOnly, true, true, true, false},
		{SealedCandidatesAuto, false, false, false, true}, // old coordinator
		{SealedCandidatesAuto, true, false, false, true},  // listing failed
		{SealedCandidatesAuto, true, true, false, false},  // every online peer reads sealed blobs
		{SealedCandidatesAuto, true, true, true, true},    // an old peer is online
	}
	for i, c := range cases {
		if got := plainCandidatesAllowed(c.mode, c.coord, c.listed, c.legacy); got != c.w {
			t.Errorf("case %d: got %v", i, got)
		}
	}
	for _, s := range []string{"", "auto", "only", "OFF"} {
		m, err := ParseSealedCandidatesMode(s)
		if err != nil {
			t.Fatal(err)
		}
		if again, _ := ParseSealedCandidatesMode(m.String()); again != m {
			t.Fatalf("%q round trip", s)
		}
	}
	if _, err := ParseSealedCandidatesMode("sometimes"); err == nil {
		t.Fatal("bad mode accepted")
	}
}

// A peer counts as plain-only only after two listings in a row said so,
// and stops counting the moment it shows up as capable or offline.
func TestSealedListingHysteresis(t *testing.T) {
	s := newSealSide(t, "a").s
	ids := []string{"b"}
	s.noteListing([]control.PeerSealed{{ID: "b", Old: true}})
	if s.legacyOnline(ids) {
		t.Fatal("old after one listing")
	}
	s.noteListing([]control.PeerSealed{{ID: "b", Old: true}})
	if !s.legacyOnline(ids) {
		t.Fatal("not old after two listings")
	}
	s.noteListing(nil)
	if s.legacyOnline(ids) {
		t.Fatal("an offline peer still forces plain candidates")
	}
	s.noteListing([]control.PeerSealed{{ID: "b", Cap: true}})
	if s.legacyOnline(ids) || !s.capable("b") {
		t.Fatal("capable peer")
	}
}
