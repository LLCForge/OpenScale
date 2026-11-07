package trust

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func coordFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	if err := f.doc.SetCoordinator("vps.example.com:51820", testKey(t)); err != nil {
		t.Fatalf("SetCoordinator: %v", err)
	}
	return f
}

func TestSingleCoordinatorEncodingUnchanged(t *testing.T) {
	f := coordFixture(t)
	env := f.sign(t, f.doc)
	for _, field := range []string{"coordinators", "\"name\"", "\"region\"", "\"until\""} {
		if bytes.Contains(env.Payload, []byte(field)) {
			t.Fatalf("a document without additional coordinators must not encode %s", field)
		}
	}
}

func TestAddCoordinatorAndOpen(t *testing.T) {
	f := coordFixture(t)
	home := testKey(t)
	if err := f.doc.AddCoordinator("ev.example.net:41820", home, "ev", "ist"); err != nil {
		t.Fatalf("AddCoordinator: %v", err)
	}
	if err := f.doc.AddCoordinator("ev2.example.net:41820", home, "", ""); err == nil {
		t.Fatal("the same key twice must be rejected")
	}
	if err := f.doc.AddCoordinator("ev2.example.net:41820", testKey(t), "ev", ""); err == nil {
		t.Fatal("a duplicate name must be rejected")
	}
	if len(f.doc.Coordinators) != 1 {
		t.Fatal("a failed add must leave the list unchanged")
	}
	c := f.doc.Coordinators[0]
	if c.IPv4 == f.doc.Coordinator.IPv4 || c.IPv6 == f.doc.Coordinator.IPv6 {
		t.Fatal("additional coordinator must get its own addresses")
	}
	f.doc.Version++
	env := f.sign(t, f.doc)
	got, err := OpenDocument(env, f.anchor, 0, testNow)
	if err != nil {
		t.Fatalf("OpenDocument: %v", err)
	}
	all := got.AllCoordinators()
	if len(all) != 2 || all[0].WireGuardKey != f.doc.Coordinator.WireGuardKey || all[1].WireGuardKey != home || all[1].Region != "ist" {
		t.Fatalf("AllCoordinators = %+v", all)
	}
	if cc, ok := got.CoordinatorByKey(home); !ok || cc.CoordinatorLabel() != "ev" {
		t.Fatal("CoordinatorByKey must find the additional coordinator")
	}
	// A new device does not receive a coordinator address.
	_, req := newRequest(t, "yeni")
	d, err := f.doc.AddDevice(req, "yeni", nil, testNow, DefaultDeviceLife)
	if err != nil {
		t.Fatal(err)
	}
	if d.IPv4 == c.IPv4 || d.IPv6 == c.IPv6 {
		t.Fatal("new device received an additional coordinator's address")
	}
}

func TestCoordinatorValidation(t *testing.T) {
	f := coordFixture(t)
	prim := *f.doc.Coordinator
	good := Coordinator{Endpoint: "203.0.113.9:41820", WireGuardKey: testKey(t)}
	var err error
	if good.IPv4, err = f.doc.freeAddr(f.doc.IPv4Prefix); err != nil {
		t.Fatal(err)
	}
	if good.IPv6, err = f.doc.freeAddr(f.doc.IPv6Prefix); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(c *Coordinator, d *Document){
		"same key as primary": func(c *Coordinator, _ *Document) { c.WireGuardKey = prim.WireGuardKey },
		"same ipv4":           func(c *Coordinator, _ *Document) { c.IPv4 = prim.IPv4 },
		"bad endpoint":        func(c *Coordinator, _ *Document) { c.Endpoint = "yok" },
		"zero key":            func(c *Coordinator, _ *Document) { c.WireGuardKey = Key{} },
		"bad name":            func(c *Coordinator, _ *Document) { c.Name = "Büyük" },
		"long region":         func(c *Coordinator, _ *Document) { c.Region = "abcdefghijklmnopqrstuvwxyz0123456789" },
		"resolver address":    func(c *Coordinator, d *Document) { c.IPv4 = d.DNSResolverIPv4() },
		"primary until":       func(_ *Coordinator, d *Document) { d.Coordinator.Until = testNow.Add(time.Hour) },
		"no primary":          func(_ *Coordinator, d *Document) { d.Coordinator = nil },
		"revoked key": func(c *Coordinator, d *Document) {
			d.Revoked = append(d.Revoked, Revocation{DeviceID: "0123456789abcdef0123456789abcdef", Name: "eski", SigningKey: testKey(t), WireGuardKey: c.WireGuardKey, RevokedAt: testNow})
		},
	}
	for name, mutate := range cases {
		doc := *f.doc
		p := prim
		doc.Coordinator = &p
		c := good
		mutate(&c, &doc)
		doc.Coordinators = []Coordinator{c}
		if err := doc.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
	doc := *f.doc
	doc.Coordinators = []Coordinator{}
	if err := doc.Validate(); err == nil {
		t.Error("an empty but present list must be rejected (it would change the encoding)")
	}
	doc.Coordinators = []Coordinator{good}
	if err := doc.Validate(); err != nil {
		t.Fatalf("valid additional coordinator rejected: %v", err)
	}
	// Too many.
	for i := 0; i < MaxExtraCoordinators; i++ {
		if err := f.doc.AddCoordinator("203.0.113.10:4182"+string(rune('0'+i)), testKey(t), "", ""); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if err := f.doc.AddCoordinator("203.0.113.11:41820", testKey(t), "", ""); err == nil {
		t.Fatal("more than MaxExtraCoordinators must be rejected")
	}
}

func TestRotateCoordinatorKeepsBothKeys(t *testing.T) {
	f := coordFixture(t)
	old := *f.doc.Coordinator
	newKey := testKey(t)
	if err := f.doc.RotateCoordinator("vps.example.com:51821", newKey, "vps", "", 0, testNow); err != nil {
		t.Fatalf("RotateCoordinator: %v", err)
	}
	if f.doc.Coordinator.WireGuardKey != newKey || f.doc.Coordinator.Until != (time.Time{}) {
		t.Fatal("new key must be the primary coordinator without an end")
	}
	if len(f.doc.Coordinators) != 1 || f.doc.Coordinators[0].WireGuardKey != old.WireGuardKey || f.doc.Coordinators[0].IPv4 != old.IPv4 {
		t.Fatal("old key must stay as an additional coordinator at its addresses")
	}
	until := f.doc.Coordinators[0].Until
	if !until.Equal(testNow.Add(DefaultCoordinatorTransition)) {
		t.Fatalf("until = %v", until)
	}
	if got := f.doc.UsableCoordinators(testNow); len(got) != 2 {
		t.Fatal("both keys must be usable during the transition")
	}
	if got := f.doc.UsableCoordinators(until); len(got) != 1 || got[0].WireGuardKey != newKey {
		t.Fatal("only the new key must be usable after the transition")
	}
	if n := f.doc.PruneCoordinators(until); n != 1 || f.doc.Coordinators != nil {
		t.Fatal("PruneCoordinators must drop the old key")
	}
	if err := f.doc.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := f.doc.RotateCoordinator("x.example:1", testKey(t), "", "", time.Minute, testNow); err == nil {
		t.Fatal("a too short transition must be rejected")
	}
}

func TestPromoteAndRemoveCoordinator(t *testing.T) {
	f := coordFixture(t)
	prim := *f.doc.Coordinator
	home := testKey(t)
	if err := f.doc.AddCoordinator("ev.example.net:41820", home, "ev", ""); err != nil {
		t.Fatal(err)
	}
	if err := f.doc.RemoveCoordinator(prim.WireGuardKey); err == nil {
		t.Fatal("the primary must not be removable")
	}
	if err := f.doc.PromoteCoordinator(home, time.Time{}); err != nil {
		t.Fatalf("PromoteCoordinator: %v", err)
	}
	if f.doc.Coordinator.WireGuardKey != home || f.doc.Coordinators[0].WireGuardKey != prim.WireGuardKey {
		t.Fatal("promote must swap the coordinators")
	}
	if err := f.doc.RemoveCoordinator(prim.WireGuardKey); err != nil {
		t.Fatalf("RemoveCoordinator: %v", err)
	}
	if f.doc.Coordinators != nil {
		t.Fatal("an emptied list must be nil")
	}
	if err := f.doc.RemoveCoordinator(prim.WireGuardKey); err != ErrUnknownCoordinator {
		t.Fatalf("second remove: %v", err)
	}
	// The JSON round trip keeps everything.
	raw, err := json.Marshal(f.doc)
	if err != nil {
		t.Fatal(err)
	}
	var back Document
	if err := decodeStrict(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Coordinator.WireGuardKey != home {
		t.Fatal("round trip changed the primary")
	}
}
