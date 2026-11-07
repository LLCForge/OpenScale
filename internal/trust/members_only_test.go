package trust

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type membersNet struct {
	f       *fixture
	full    *Document
	secrets map[string]*DeviceSecrets
}

// Distinctive strings that must never reach the coordinator.
const (
	secretTag  = "gizlietiket"
	secretPort = "47123"
)

func newMembersNet(t *testing.T, names ...string) *membersNet {
	t.Helper()
	f := newFixture(t)
	doc, err := f.doc.Next(testNow, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	n := &membersNet{f: f, full: doc, secrets: map[string]*DeviceSecrets{}}
	for _, name := range names {
		s, req := newRequest(t, name)
		if _, err := doc.AddDevice(req, name, nil, testNow, DefaultDeviceLife); err != nil {
			t.Fatal(err)
		}
		n.secrets[name] = s
	}
	doc.Devices[0].Tags = []string{secretTag}
	if err := doc.AddRule(Rule{From: []string{names[0]}, To: []string{names[1]}, Protocol: ProtocolTCP, Ports: []string{secretPort}}); err != nil {
		t.Fatal(err)
	}
	doc.MinClientVersion = MembersOnlyMinClientVersion
	return n
}

func (n *membersNet) seal(t *testing.T, doc *Document) (*Document, Envelope) {
	t.Helper()
	pub, plain, err := SealMembersOnly(doc, rand.Reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(plain) == 0 {
		t.Fatal("no plaintext copy")
	}
	return pub, n.f.sign(t, pub)
}

func (n *membersNet) open(t *testing.T, name string, pub *Document) (*Document, error) {
	t.Helper()
	s := n.secrets[name]
	return OpenMembersOnly(pub, s.DeviceID, s.WireGuardPrivate)
}

func TestMembersOnlyHidesNamesAndRulesFromCoordinator(t *testing.T) {
	n := newMembersNet(t, "gizlilaptop", "gizlisunucu", "gizlitelefon")
	_, env := n.seal(t, n.full)
	// The coordinator's view: the verified public part, as State.Accept
	// returns it to a member without keys.
	st := &State{Anchor: n.f.anchor}
	pub, err := st.Accept(env, testNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	encoded, _ := json.Marshal(pub)
	for _, secret := range []string{"gizlilaptop", "gizlisunucu", "gizlitelefon", secretTag, secretPort} {
		if bytes.Contains(env.Payload, []byte(secret)) || bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("%q is visible in the public part", secret)
		}
	}
	if len(pub.Devices) != 3 || pub.Devices[0].WireGuardKey != n.full.Devices[0].WireGuardKey || pub.Devices[0].IPv4 != n.full.Devices[0].IPv4 {
		t.Fatal("public part lost keys or addresses")
	}
	// Members open it and all reach the same complete document.
	want, _ := json.Marshal(n.full)
	var first []byte
	for _, name := range []string{"gizlilaptop", "gizlisunucu", "gizlitelefon"} {
		got, err := n.open(t, name, pub)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, _ := json.Marshal(got)
		if !bytes.Equal(data, want) {
			t.Fatalf("%s merged a different document", name)
		}
		if first == nil {
			first = data
		}
		if peers := got.TunnelPeersOf("gizlilaptop"); len(peers) != 1 || peers[0].Name != "gizlisunucu" {
			t.Fatalf("%s decides differently: %+v", name, peers)
		}
	}
}

func TestMembersOnlyNewAndRemovedMembers(t *testing.T) {
	n := newMembersNet(t, "a", "b", "c")
	pub1, _ := n.seal(t, n.full)
	// Version 2 adds d and removes c.
	next, err := n.full.Next(testNow, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	s, req := newRequest(t, "d")
	if _, err := next.AddDevice(req, "d", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	n.secrets["d"] = s
	if _, err := next.RevokeDevice("c", testNow); err != nil {
		t.Fatal(err)
	}
	pub2, _ := n.seal(t, next)
	for _, name := range []string{"a", "b", "d"} {
		if _, err := n.open(t, name, pub2); err != nil {
			t.Fatalf("%s cannot read version 2: %v", name, err)
		}
	}
	if _, err := n.open(t, "c", pub2); !errors.Is(err, ErrPrivatePart) {
		t.Fatalf("removed member read version 2: %v", err)
	}
	if _, err := n.open(t, "c", pub1); err != nil {
		t.Fatalf("c could read version 1: %v", err)
	}
	if _, err := n.open(t, "d", pub1); !errors.Is(err, ErrPrivatePart) {
		t.Fatalf("new member read an older version: %v", err)
	}
}

func TestMembersOnlyStrictValidation(t *testing.T) {
	n := newMembersNet(t, "a", "b")
	// Opening requires the client minimum.
	old := *n.full
	old.MinClientVersion = ""
	if _, _, err := SealMembersOnly(&old, rand.Reader); !errors.Is(err, ErrMembersOnly) {
		t.Fatalf("sealed without a client minimum: %v", err)
	}
	old.MinClientVersion = "0.9.0"
	if _, _, err := SealMembersOnly(&old, rand.Reader); !errors.Is(err, ErrMembersOnly) {
		t.Fatalf("sealed with a low client minimum: %v", err)
	}
	pub, _ := n.seal(t, n.full)
	mutations := map[string]func(d *Document){
		"name":        func(d *Document) { d.Devices[0].Name = "a" },
		"tag":         func(d *Document) { d.Devices[0].Tags = []string{"x"} },
		"rule":        func(d *Document) { d.Rules = append(d.Rules, n.full.Rules[0]) },
		"min version": func(d *Document) { d.MinClientVersion = "" },
		"recipients":  func(d *Document) { d.MembersOnly.Part.Recipients = d.MembersOnly.Part.Recipients[:1] },
		"digest":      func(d *Document) { d.MembersOnly.Digest = "00" },
		"display":     func(d *Document) { d.DisplayName = "Ev" },
	}
	for name, mutate := range mutations {
		d, err := cloneDocument(pub)
		if err != nil {
			t.Fatal(err)
		}
		mutate(d)
		if err := d.Validate(); err == nil {
			t.Fatalf("%s: tampered public part validated", name)
		}
	}
	// A plaintext that does not match the signed digest is refused.
	if _, err := MergeMembersPlain(pub, []byte(`{"format":"openscale-members-part-v1"}`)); !errors.Is(err, ErrMembersOnly) {
		t.Fatalf("merge of a foreign plaintext: %v", err)
	}
	// Documents without the field encode exactly as before.
	plain, _ := json.Marshal(n.full)
	if bytes.Contains(plain, []byte("members_only")) {
		t.Fatal("unsealed document carries members_only")
	}
}
