package trust

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"testing/quick"
	"time"
)

// Property-based tests of document edits (#573) with testing/quick: a
// random sequence of edits is applied and the invariants below must hold
// after every step, whatever the order.
//
//   - a revoked device id or key never comes back;
//   - device names stay unique and every document stays valid;
//   - every signed version is higher than the last, and a device never
//     moves back;
//   - a rename rewrites every reference to the old name.

// propPool holds enrollment requests shared by every property: generating
// device keys is the slow part.
var propPool struct {
	once sync.Once
	reqs []*EnrollmentRequest
}

func propRequests(t *testing.T) []*EnrollmentRequest {
	propPool.once.Do(func() {
		for i := range 8 {
			_, req := newRequest(t, fmt.Sprintf("cihaz%d", i))
			propPool.reqs = append(propPool.reqs, req)
		}
	})
	if len(propPool.reqs) != 8 {
		t.Fatal("request pool not initialized")
	}
	return propPool.reqs
}

var propNames = []string{"a", "b", "c", "d", "laptop", "masaustu"}

// propOp applies one random edit; failures that the API reports are fine,
// the invariants are checked on whatever the document became.
func propOp(doc *Document, reqs []*EnrollmentRequest, op, x, y uint8, now time.Time) {
	name := propNames[int(x)%len(propNames)]
	other := propNames[int(y)%len(propNames)]
	switch op % 6 {
	case 0, 1:
		_, _ = doc.AddDevice(reqs[int(y)%len(reqs)], name, nil, now, DefaultDeviceLife)
	case 2:
		_, _ = doc.RevokeDevice(name, now)
	case 3:
		_ = doc.RenameDevice(name, other)
	case 4:
		_ = doc.AddRule(Rule{From: []string{name}, To: []string{other}, Protocol: ProtocolTCP, Ports: []string{"22"}})
	case 5:
		if len(doc.Devices) > 0 {
			_ = doc.SetGroup("g", []string{doc.Devices[int(x)%len(doc.Devices)].Name})
		}
	}
}

func propConfig() *quick.Config {
	n := 60
	if testing.Short() {
		n = 15
	}
	return &quick.Config{MaxCount: n}
}

func TestPropRevokedNeverReturns(t *testing.T) {
	reqs := propRequests(t)
	revocations := 0
	prop := func(ops []uint8) bool {
		f := newFixture(t)
		doc := f.doc
		for i := 0; i+2 < len(ops); i += 3 {
			propOp(doc, reqs, ops[i], ops[i+1], ops[i+2], testNow)
		}
		revocations += len(doc.Revoked)
		// Every revoked identity stays out, under any name.
		for _, r := range doc.Revoked {
			for _, req := range reqs {
				if req.DeviceID != r.DeviceID && req.SigningKey != r.SigningKey && req.WireGuardKey != r.WireGuardKey {
					continue
				}
				if _, err := doc.AddDevice(req, "geri-gelen", nil, testNow, DefaultDeviceLife); !errors.Is(err, ErrRevokedKey) {
					t.Logf("revoked %s re-enrolled: %v", r.Name, err)
					return false
				}
			}
			for _, d := range doc.Devices {
				if d.ID == r.DeviceID || d.SigningKey == r.SigningKey || d.WireGuardKey == r.WireGuardKey {
					t.Logf("revoked identity %s is a member again as %s", r.Name, d.Name)
					return false
				}
			}
		}
		return true
	}
	if err := quick.Check(prop, propConfig()); err != nil {
		t.Fatal(err)
	}
	if revocations == 0 {
		t.Fatal("no random sequence revoked a device; the property was never exercised")
	}
}

func TestPropNamesUniqueAndValid(t *testing.T) {
	reqs := propRequests(t)
	prop := func(ops []uint8) bool {
		doc := newFixture(t).doc
		for i := 0; i+2 < len(ops); i += 3 {
			propOp(doc, reqs, ops[i], ops[i+1], ops[i+2], testNow)
			seen := map[string]bool{}
			ids := map[string]bool{}
			for _, d := range doc.Devices {
				if seen[d.Name] || ids[d.ID] {
					t.Logf("duplicate device %s/%s after op %d", d.Name, d.ID, ops[i]%6)
					return false
				}
				seen[d.Name], ids[d.ID] = true, true
			}
			if err := doc.Validate(); err != nil {
				t.Logf("invalid document after op %d: %v", ops[i]%6, err)
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, propConfig()); err != nil {
		t.Fatal(err)
	}
}

func TestPropVersionIncreases(t *testing.T) {
	reqs := propRequests(t)
	prop := func(ops []uint8, back uint8) bool {
		f := newFixture(t)
		state := State{Anchor: f.anchor}
		doc := f.doc
		var envs []Envelope
		now := testNow
		for i := 0; i+2 < len(ops) && len(envs) < 12; i += 3 {
			next, err := doc.Next(now, DefaultValidity)
			if err != nil {
				t.Logf("Next: %v", err)
				return false
			}
			if next.Version != doc.Version+1 {
				t.Logf("Next went from %d to %d", doc.Version, next.Version)
				return false
			}
			propOp(next, reqs, ops[i], ops[i+1], ops[i+2], now)
			env, err := SignDocument(next, f.rootPriv)
			if err != nil {
				t.Logf("SignDocument: %v", err)
				return false
			}
			prev := state.HighestVersion
			got, err := state.Accept(env, now)
			if err != nil || got.Version <= prev && prev != 0 {
				t.Logf("Accept v%d after v%d: %v", next.Version, prev, err)
				return false
			}
			envs = append(envs, env)
			doc = next
			now = now.Add(time.Minute)
		}
		if len(envs) < 2 {
			return true
		}
		// Any older envelope is refused afterwards.
		old := envs[int(back)%(len(envs)-1)]
		if _, err := state.Accept(old, now); !errors.Is(err, ErrRollback) {
			t.Logf("older version accepted: %v", err)
			return false
		}
		return true
	}
	if err := quick.Check(prop, propConfig()); err != nil {
		t.Fatal(err)
	}
}

func TestPropRenameRewritesReferences(t *testing.T) {
	reqs := propRequests(t)
	prop := func(ops []uint8, pick, to uint8) bool {
		doc := newFixture(t).doc
		for i := 0; i+2 < len(ops); i += 3 {
			propOp(doc, reqs, ops[i], ops[i+1], ops[i+2], testNow)
		}
		if len(doc.Devices) == 0 {
			return true
		}
		old := doc.Devices[int(pick)%len(doc.Devices)].Name
		newName := fmt.Sprintf("yeni%d", to)
		before := propRefs(doc, old)
		if err := doc.RenameDevice(old, newName); err != nil {
			t.Logf("rename %s -> %s: %v", old, newName, err)
			return false
		}
		if n := propRefs(doc, old); n != 0 {
			t.Logf("%d references to %s survived the rename", n, old)
			return false
		}
		if after := propRefs(doc, newName); after != before {
			t.Logf("references: %d before, %d after", before, after)
			return false
		}
		_, ok := doc.DeviceByName(newName)
		return ok
	}
	if err := quick.Check(prop, propConfig()); err != nil {
		t.Fatal(err)
	}
}

// propRefs counts the places that name a device: rules, groups and
// exit_users.
func propRefs(doc *Document, name string) int {
	n := 0
	count := func(list []string) {
		for _, e := range list {
			if e == name {
				n++
			}
		}
	}
	for _, r := range doc.Rules {
		count(r.From)
		count(r.To)
		count(r.Via)
	}
	for _, g := range doc.Groups {
		count(g.Members)
	}
	if doc.ExitUsers != nil {
		count(*doc.ExitUsers)
	}
	if slices.ContainsFunc(doc.Devices, func(d Device) bool { return d.Name == name }) {
		n++
	}
	return n
}
