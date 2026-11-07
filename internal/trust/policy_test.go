package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func policyDoc(t *testing.T) (*fixture, *Document) {
	t.Helper()
	f := newFixture(t)
	doc, err := f.doc.Next(testNow, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"laptop", "masaustu", "vps", "telefon"} {
		_, req := newRequest(t, name)
		if _, err := doc.AddDevice(req, name, nil, testNow, DefaultDeviceLife); err != nil {
			t.Fatal(err)
		}
	}
	rules := []Rule{
		{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: ProtocolTCP, Ports: []string{"3389", "5900-5910"}},
		{From: []string{"*"}, To: []string{"vps"}, Protocol: ProtocolICMP},
	}
	for _, r := range rules {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	return f, doc
}

func TestAllows(t *testing.T) {
	_, doc := policyDoc(t)
	cases := []struct {
		src, dst string
		proto    Protocol
		port     uint16
		want     bool
	}{
		{"laptop", "masaustu", ProtocolTCP, 3389, true},
		{"laptop", "masaustu", ProtocolTCP, 5905, true},
		{"laptop", "masaustu", ProtocolTCP, 22, false},
		{"laptop", "masaustu", ProtocolUDP, 3389, false},
		{"masaustu", "laptop", ProtocolTCP, 3389, false},
		{"telefon", "vps", ProtocolICMP, 0, true},
		{"telefon", "vps", ProtocolTCP, 22, false},
		{"vps", "vps", ProtocolICMP, 0, false},
	}
	for _, c := range cases {
		if got := doc.Allows(c.src, c.dst, c.proto, c.port); got != c.want {
			t.Errorf("Allows(%s -> %s %s/%d) = %v, want %v", c.src, c.dst, c.proto, c.port, got, c.want)
		}
	}
}

func TestVisibility(t *testing.T) {
	_, doc := policyDoc(t)
	names := func(ds []Device) map[string]bool {
		m := map[string]bool{}
		for _, d := range ds {
			m[d.Name] = true
		}
		return m
	}
	laptop := names(doc.PeersOf("laptop"))
	if !laptop["masaustu"] || !laptop["vps"] || laptop["telefon"] || laptop["laptop"] {
		t.Fatalf("laptop peers = %v", laptop)
	}
	masaustu := names(doc.PeersOf("masaustu"))
	if !masaustu["laptop"] || !masaustu["vps"] || masaustu["telefon"] {
		t.Fatalf("masaustu peers = %v (reverse direction and wildcard must count)", masaustu)
	}
}

func TestSetCoordinator(t *testing.T) {
	_, doc := policyDoc(t)
	var key Key
	key[0] = 9
	if err := doc.SetCoordinator("vpn.example.com:51820", key); err != nil {
		t.Fatalf("SetCoordinator: %v", err)
	}
	c := doc.Coordinator
	for _, d := range doc.Devices {
		if d.IPv4 == c.IPv4 || d.IPv6 == c.IPv6 {
			t.Fatal("coordinator address collides with a device")
		}
	}
	ipv4 := c.IPv4
	key[1] = 1
	if err := doc.SetCoordinator("1.2.3.4:51820", key); err != nil {
		t.Fatal(err)
	}
	if doc.Coordinator.IPv4 != ipv4 {
		t.Fatal("changing the endpoint must keep the coordinator address")
	}
	if err := doc.SetCoordinator("no-port", key); err == nil {
		t.Fatal("endpoint without a port must be rejected")
	}
	if doc.Coordinator.Endpoint != "1.2.3.4:51820" {
		t.Fatal("failed update must keep the previous coordinator")
	}
	_, req := newRequest(t, "yeni")
	if _, err := doc.AddDevice(req, "yeni", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	if last := doc.Devices[len(doc.Devices)-1]; last.IPv4 == ipv4 {
		t.Fatal("new device received the coordinator address")
	}
}

func TestJoinBundle(t *testing.T) {
	f := newFixture(t)
	env := f.sign(t, f.doc)
	var root Key
	copy(root[:], f.rootPub)
	line, err := EncodeJoinBundle(JoinBundle{RootKey: root, Document: env})
	if err != nil {
		t.Fatal(err)
	}
	fp := RootFingerprint(f.rootPub)
	anchor, doc, _, err := OpenJoinBundle(line, fp)
	if err != nil {
		t.Fatalf("OpenJoinBundle: %v", err)
	}
	if anchor.NetworkID != doc.NetworkID || !anchor.RootKey.Equal(f.rootPub) {
		t.Fatal("anchor does not match the bundle")
	}
	if _, _, _, err := OpenJoinBundle(line, "AAAA-BBBB-CCCC-DDDD"); !errors.Is(err, ErrRootFingerprintMismatch) {
		t.Fatalf("wrong fingerprint error = %v", err)
	}

	// An attacker replaces the root key with their own and re-signs.
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	forgedEnv, _ := SignDocument(f.doc, otherPriv)
	var other Key
	copy(other[:], otherPub)
	forged, _ := EncodeJoinBundle(JoinBundle{RootKey: other, Document: forgedEnv})
	if _, _, _, err := OpenJoinBundle(forged, fp); !errors.Is(err, ErrRootFingerprintMismatch) {
		t.Fatalf("forged bundle error = %v", err)
	}
}
