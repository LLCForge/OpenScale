package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// --- Backward compatibility ---

func TestP08FieldsAbsentKeepEncoding(t *testing.T) {
	f := newFixture(t)
	_, req := newRequest(t, "laptop")
	if _, err := f.doc.AddDevice(req, "laptop", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	env := f.sign(t, f.doc)
	for _, field := range []string{"recovery_keys", "root_epoch", "min_client_version", "ephemeral", "preauthorized", "max_uses", "\"uses\""} {
		if bytes.Contains(env.Payload, []byte(field)) {
			t.Fatalf("unused field %s appears in the encoding", field)
		}
	}
	// A state that accepted documents before root epochs existed keeps
	// accepting the next version unchanged.
	st := &State{Anchor: f.anchor}
	if _, err := st.Accept(env, testNow); err != nil {
		t.Fatal(err)
	}
	next, err := f.doc.Next(testNow, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Accept(f.sign(t, next), testNow); err != nil {
		t.Fatalf("next version rejected: %v", err)
	}
	if st.Epoch != 0 || len(st.RecoveryKeys) != 0 {
		t.Fatal("state changed root fields for an old-style document")
	}
}

// --- Root rotation and recovery (ADR-0027) ---

type rootNet struct {
	f        *fixture
	recPub   Key
	recPriv  ed25519.PrivateKey
	root     ed25519.PrivateKey
	rootPub  Key
	doc      *Document
	lastEnv  Envelope
	stateDev *State
}

func newRootNet(t *testing.T) *rootNet {
	t.Helper()
	f := newFixture(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var rec Key
	copy(rec[:], pub)
	if err := f.doc.AddRecoveryKey(rec); err != nil {
		t.Fatal(err)
	}
	rn := &rootNet{f: f, recPub: rec, recPriv: priv, root: f.rootPriv, doc: f.doc}
	copy(rn.rootPub[:], f.rootPub)
	rn.lastEnv = f.sign(t, f.doc)
	rn.stateDev = &State{Anchor: f.anchor}
	if _, err := rn.stateDev.Accept(rn.lastEnv, testNow); err != nil {
		t.Fatal(err)
	}
	if len(rn.stateDev.RecoveryKeys) != 1 {
		t.Fatal("recovery key was not pinned on first sight")
	}
	return rn
}

func newRoot(t *testing.T) (Key, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var k Key
	copy(k[:], pub)
	return k, priv
}

func signWith(t *testing.T, doc *Document, priv ed25519.PrivateKey) Envelope {
	t.Helper()
	env, err := SignDocument(doc, priv)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestRootRotation(t *testing.T) {
	rn := newRootNet(t)
	newPub, newPriv := newRoot(t)
	st, err := SignRootRotation(rn.root, RootTransition{
		NetworkID: rn.doc.NetworkID, RevokedRoot: rn.rootPub, NewRoot: newPub,
		LastGoodVersion: rn.doc.Version, LastGoodDigest: DocumentDigest(rn.lastEnv), Epoch: 1, IssuedAt: testNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	line, err := EncodeRootTransition(st)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRootTransition(line)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := rn.doc.Next(testNow, DefaultValidity)
	next.RootEpoch = 1
	env := signWith(t, next, newPriv)

	// Without the transition the new root's document does not verify.
	if _, err := rn.stateDev.Accept(env, testNow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want bad signature", err)
	}
	// A failing document leaves the state untouched.
	bad, _ := rn.doc.Next(testNow, DefaultValidity)
	bad.RootEpoch = 2
	before := rn.stateDev.Clone()
	if _, _, err := rn.stateDev.AcceptWithTransitions([]SignedRootTransition{decoded}, signWith(t, bad, newPriv), testNow); err == nil {
		t.Fatal("document at the wrong epoch accepted")
	}
	if !bytes.Equal(rn.stateDev.Anchor.RootKey, before.Anchor.RootKey) || rn.stateDev.Epoch != 0 {
		t.Fatal("failed transition changed the state")
	}
	doc, applied, err := rn.stateDev.AcceptWithTransitions([]SignedRootTransition{decoded}, env, testNow)
	if err != nil {
		t.Fatalf("AcceptWithTransitions: %v", err)
	}
	if len(applied) != 1 || doc.RootEpoch != 1 || rn.stateDev.Epoch != 1 {
		t.Fatal("rotation not applied")
	}
	// Every document of the old root is now rejected, even a newer one.
	old, _ := next.Next(testNow, DefaultValidity)
	old.RootEpoch = 0
	if _, err := rn.stateDev.Accept(signWith(t, old, rn.root), testNow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("old root still accepted: %v", err)
	}
	// The same transition cannot be applied twice.
	if _, err := rn.stateDev.ApplyTransition(decoded, testNow); err == nil {
		t.Fatal("transition applied twice")
	}
	// Recovery keys stay pinned: a new-root document that drops them fails.
	drop, _ := next.Next(testNow, DefaultValidity)
	drop.RecoveryKeys = nil
	if _, err := rn.stateDev.Accept(signWith(t, drop, newPriv), testNow); !errors.Is(err, ErrRecoveryKeysChanged) {
		t.Fatalf("got %v, want recovery keys changed", err)
	}
}

func TestRootRotationRejections(t *testing.T) {
	rn := newRootNet(t)
	newPub, _ := newRoot(t)
	base := RootTransition{NetworkID: rn.doc.NetworkID, RevokedRoot: rn.rootPub, NewRoot: newPub,
		LastGoodVersion: rn.doc.Version, LastGoodDigest: DocumentDigest(rn.lastEnv), Epoch: 1, IssuedAt: testNow}
	cases := map[string]func(t *RootTransition){
		"epoch jump":     func(t *RootTransition) { t.Epoch = 2 },
		"stale version":  func(t *RootTransition) { t.LastGoodVersion = 0 },
		"stale digest":   func(t *RootTransition) { t.LastGoodDigest = strings.Repeat("0", 64) },
		"other network":  func(t *RootTransition) { t.NetworkID = strings.Repeat("a", 32) },
		"future":         func(t *RootTransition) { t.IssuedAt = testNow.Add(time.Hour) },
		"new is current": func(t *RootTransition) { t.NewRoot = t.RevokedRoot },
	}
	for name, mutate := range cases {
		tr := base
		mutate(&tr)
		st, err := SignRootRotation(rn.root, tr)
		if err != nil {
			continue // rejected at signing already
		}
		s := rn.stateDev.Clone()
		if _, err := s.ApplyTransition(st, testNow); err == nil {
			t.Errorf("%s: transition accepted", name)
		}
	}
	// A rotation signed by a stranger is rejected.
	_, stranger := newRoot(t)
	tr := base
	strangerPub, _ := keyFromSlice(stranger.Public().(ed25519.PublicKey))
	tr.RevokedRoot = strangerPub
	st, err := SignRootRotation(stranger, tr)
	if err != nil {
		t.Fatal(err)
	}
	s := rn.stateDev.Clone()
	if _, err := s.ApplyTransition(st, testNow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want bad signature", err)
	}
	// A recovery transition cannot be built with the root key's context.
	if _, err := SignRootRecovery(rn.recPriv, RootTransition{NetworkID: rn.doc.NetworkID, RevokedRoot: rn.rootPub, NewRoot: rn.recPub,
		LastGoodDigest: base.LastGoodDigest, Epoch: 1, IssuedAt: testNow}); err == nil {
		t.Fatal("recovery key became the root")
	}
}

func TestRootRecoveryAfterCompromise(t *testing.T) {
	rn := newRootNet(t)
	goodEnv := rn.lastEnv
	good := rn.doc

	// The attacker holds the root: adds a device, bumps the version far and
	// even rotates to a root of its own; one device follows all of it.
	attacked, _ := good.Next(testNow, DefaultValidity)
	_, req := newRequest(t, "evil")
	evil, err := attacked.AddDevice(req, "evil", nil, testNow, DefaultDeviceLife)
	if err != nil {
		t.Fatal(err)
	}
	attacked.Version = 1_000_000
	attackedEnv := signWith(t, attacked, rn.root)
	victim := rn.stateDev.Clone()
	if _, err := victim.Accept(attackedEnv, testNow); err != nil {
		t.Fatal(err)
	}
	attackerPub, attackerPriv := newRoot(t)
	rot, err := SignRootRotation(rn.root, RootTransition{NetworkID: good.NetworkID, RevokedRoot: rn.rootPub, NewRoot: attackerPub,
		LastGoodVersion: attacked.Version, LastGoodDigest: DocumentDigest(attackedEnv), Epoch: 1, IssuedAt: testNow})
	if err != nil {
		t.Fatal(err)
	}
	attacked2, _ := attacked.Next(testNow, DefaultValidity)
	attacked2.RootEpoch = 1
	followed := victim.Clone()
	if _, _, err := followed.AcceptWithTransitions([]SignedRootTransition{rot}, signWith(t, attacked2, attackerPriv), testNow); err != nil {
		t.Fatal(err)
	}
	// The attacker cannot swap the recovery keys.
	swap, _ := attacked2.Next(testNow, DefaultValidity)
	other, _ := newRoot(t)
	swap.RecoveryKeys = []Key{other}
	if _, err := cp(followed).Accept(signWith(t, swap, attackerPriv), testNow); !errors.Is(err, ErrRecoveryKeysChanged) {
		t.Fatalf("got %v, want recovery keys changed", err)
	}

	// The owner recovers from the last good version with the recovery key.
	newPub, newPriv := newRoot(t)
	rec, err := SignRootRecovery(rn.recPriv, RootTransition{NetworkID: good.NetworkID, RevokedRoot: rn.rootPub, NewRoot: newPub,
		LastGoodVersion: good.Version, LastGoodDigest: DocumentDigest(goodEnv), Epoch: 2, IssuedAt: testNow})
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := good.Next(testNow, DefaultValidity)
	fresh.Version = attacked.Version + 1
	fresh.RootEpoch = 2
	fresh.Revoked = append(fresh.Revoked, Revocation{DeviceID: evil.ID, Name: evil.Name, SigningKey: evil.SigningKey, WireGuardKey: evil.WireGuardKey, RevokedAt: testNow})
	freshEnv := signWith(t, fresh, newPriv)

	for name, st := range map[string]State{"untouched": rn.stateDev.Clone(), "victim": victim, "followed": followed} {
		st := st
		doc, _, err := st.AcceptWithTransitions([]SignedRootTransition{rot, rec}, freshEnv, testNow)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, ok := doc.DeviceByName("evil"); ok || st.Epoch != 2 {
			t.Fatalf("%s: recovery not in effect", name)
		}
		// The compromised and the attacker's roots are revoked for good.
		if _, err := cp(st).Accept(attackedEnv, testNow); err == nil {
			t.Fatalf("%s: attacker document accepted after recovery", name)
		}
		again, err := SignRootRotation(rn.root, RootTransition{NetworkID: good.NetworkID, RevokedRoot: rn.rootPub, NewRoot: attackerPub,
			LastGoodVersion: 0, LastGoodDigest: strings.Repeat("0", 64), Epoch: 3, IssuedAt: testNow})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cp(st).ApplyTransition(again, testNow); err == nil {
			t.Fatalf("%s: revoked root rotated again", name)
		}
	}
}

func TestFreshStateAdoptsEpoch(t *testing.T) {
	f := newFixture(t)
	f.doc.RootEpoch = 3
	env := f.sign(t, f.doc)
	st := &State{Anchor: f.anchor}
	if _, err := st.Accept(env, testNow); err != nil {
		t.Fatal(err)
	}
	if st.Epoch != 3 {
		t.Fatalf("epoch %d, want 3", st.Epoch)
	}
	lower, _ := f.doc.Next(testNow, DefaultValidity)
	lower.RootEpoch = 2
	if _, err := st.Accept(f.sign(t, lower), testNow); !errors.Is(err, ErrRollback) {
		t.Fatalf("got %v, want rollback", err)
	}
	higher, _ := f.doc.Next(testNow, DefaultValidity)
	higher.RootEpoch = 4
	if _, err := st.Accept(f.sign(t, higher), testNow); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("got %v, want epoch mismatch", err)
	}
}

func TestRecoveryKeyValidation(t *testing.T) {
	f := newFixture(t)
	_, req := newRequest(t, "a")
	d, err := f.doc.AddDevice(req, "a", nil, testNow, DefaultDeviceLife)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.doc.AddRecoveryKey(d.SigningKey); err == nil {
		t.Fatal("device key accepted as recovery key")
	}
	for i := 0; i < MaxRecoveryKeys; i++ {
		k, _ := newRoot(t)
		if err := f.doc.AddRecoveryKey(k); err != nil {
			t.Fatal(err)
		}
	}
	k, _ := newRoot(t)
	if err := f.doc.AddRecoveryKey(k); err == nil {
		t.Fatal("too many recovery keys accepted")
	}
}

// --- Multi-use invites (F-184) ---

func TestMultiUseInvite(t *testing.T) {
	f, code, inv := newInviteFixture(t)
	idx := 0
	f.doc.Invites[idx].MaxUses = 2
	if err := f.doc.Validate(); err != nil {
		t.Fatal(err)
	}
	enroll := func() (*DeviceSecrets, SignedInviteEnrollment) {
		s, err := GenerateDeviceSecrets(rand.Reader, testNow)
		if err != nil {
			t.Fatal(err)
		}
		se, _, err := s.NewInviteEnrollment(code, "host", testNow)
		if err != nil {
			t.Fatal(err)
		}
		return s, se
	}
	for i, name := range []string{"one", "two"} {
		_, se := enroll()
		req, got, err := OpenInviteEnrollment(f.doc, se, testNow)
		if err != nil || got.ID != inv.ID {
			t.Fatalf("enrollment %d: %v", i, err)
		}
		if _, err := f.doc.AddDevice(req, name, nil, testNow, DefaultDeviceLife); err != nil {
			t.Fatal(err)
		}
		if err := f.doc.MarkInviteUsed(inv.ID, req.DeviceID); err != nil {
			t.Fatalf("mark %d: %v", i, err)
		}
		if i == 0 {
			if err := f.doc.MarkInviteUsed(inv.ID, req.DeviceID); !errors.Is(err, ErrInviteUsed) {
				t.Fatal("same device recorded twice")
			}
		}
	}
	got, _ := f.doc.InviteByID(inv.ID)
	if !got.Exhausted() || got.UsedBy != "" || len(got.Uses) != 2 {
		t.Fatalf("invite state %+v", got)
	}
	_, se := enroll()
	if _, _, err := OpenInviteEnrollment(f.doc, se, testNow); !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("third enrollment: %v", err)
	}
	// Mixed or overfull use records are invalid.
	bad := f.doc.Invites[idx]
	bad.UsedBy = got.Uses[0]
	f.doc.Invites[idx] = bad
	if err := f.doc.Validate(); err == nil {
		t.Fatal("multi-use invite with used_by accepted")
	}
	bad.UsedBy, bad.MaxUses = "", 1
	f.doc.Invites[idx] = bad
	if err := f.doc.Validate(); err == nil {
		t.Fatal("single-use invite with uses accepted")
	}
}

func TestAddInviteWithOptions(t *testing.T) {
	f, _, _ := newInviteFixture(t)
	seed, _ := NewInviteSeed(rand.Reader)
	keys, _ := DeriveInviteKeys(seed)
	id, _ := NewNetworkID(rand.Reader)
	if _, err := f.doc.AddInviteWith(id, keys, testNow, InviteOptions{Life: time.Hour, MaxUses: MaxInviteUses + 1}); err == nil {
		t.Fatal("too many uses accepted")
	}
	inv, err := f.doc.AddInviteWith(id, keys, testNow, InviteOptions{Life: time.Hour, MaxUses: 5, Tags: []string{"ci"}})
	if err != nil {
		t.Fatal(err)
	}
	if inv.MaxUses != 5 || inv.Remaining() != 5 || !inv.MultiUse() {
		t.Fatalf("invite %+v", inv)
	}
}

// --- Ephemeral devices (#22) ---

func TestEphemeralDevices(t *testing.T) {
	f := newFixture(t)
	_, req := newRequest(t, "guest")
	if _, err := f.doc.AddDevice(req, "guest", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	if err := f.doc.SetDeviceEphemeral("guest", true, testNow); err != nil {
		t.Fatal(err)
	}
	d, _ := f.doc.DeviceByName("guest")
	if !d.Ephemeral || d.ExpiresAt.Sub(d.AddedAt) > MaxEphemeralLife {
		t.Fatalf("device %+v", d)
	}
	d.ExpiresAt = d.AddedAt.Add(MaxEphemeralLife + time.Hour)
	f.doc.Devices[0] = d
	if err := f.doc.Validate(); !errors.Is(err, ErrEphemeralLifetime) {
		t.Fatalf("got %v", err)
	}
	f.doc.Devices[0].ExpiresAt = d.AddedAt.Add(time.Hour)
	if got := f.doc.PruneEphemeral(d.AddedAt.Add(30 * time.Minute)); got != nil {
		t.Fatal("active ephemeral device pruned")
	}
	if got := f.doc.PruneEphemeral(d.AddedAt.Add(2 * time.Hour)); len(got) != 1 || got[0] != "guest" {
		t.Fatalf("pruned %v", got)
	}
	if len(f.doc.Devices) != 0 || len(f.doc.Revoked) != 1 {
		t.Fatal("expired ephemeral device not revoked")
	}
}

// --- Preauthorized enrollment keys (F-098) ---

func TestPreauthKey(t *testing.T) {
	f := newFixture(t)
	secrets, err := GenerateDeviceSecrets(rand.Reader, testNow)
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.doc.AddPreauthorizedDevice(secrets, PreauthOptions{Name: "ci", Tags: []string{"ci"}, Lifetime: time.Hour, Ephemeral: true}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Preauthorized || !d.Ephemeral || d.HasRole(RoleAdmin) {
		t.Fatalf("device %+v", d)
	}
	env := f.sign(t, f.doc)
	var root Key
	copy(root[:], f.rootPub)
	line, err := EncodePreauthKey(&PreauthKey{RootKey: root, Device: *secrets, Document: env})
	if err != nil {
		t.Fatal(err)
	}
	k, anchor, doc, err := OpenPreauthKey(line, testNow)
	if err != nil {
		t.Fatalf("OpenPreauthKey: %v", err)
	}
	if anchor.NetworkID != f.doc.NetworkID || k.Device.DeviceID != secrets.DeviceID || doc.Version != f.doc.Version {
		t.Fatal("wrong key contents")
	}
	if _, _, _, err := OpenPreauthKey(line, testNow.Add(2*time.Hour)); !errors.Is(err, ErrPreauthExpired) {
		t.Fatalf("got %v, want expired", err)
	}
	// Admin role is never allowed on a preauthorized device.
	idx := len(f.doc.Devices) - 1
	f.doc.Devices[idx].Roles = []Role{RoleAdmin}
	if err := f.doc.Validate(); err == nil {
		t.Fatal("preauthorized admin accepted")
	}
	f.doc.Devices[idx].Roles = []Role{}
	// A key whose device is not marked preauthorized is refused.
	f.doc.Devices[idx].Preauthorized = false
	line2, _ := EncodePreauthKey(&PreauthKey{RootKey: root, Device: *secrets, Document: f.sign(t, f.doc)})
	if _, _, _, err := OpenPreauthKey(line2, testNow); !errors.Is(err, ErrNotPreauthorized) {
		t.Fatalf("got %v", err)
	}
	// A key with another root does not verify its document.
	other, _ := newRoot(t)
	line3, _ := EncodePreauthKey(&PreauthKey{RootKey: other, Device: *secrets, Document: env})
	if _, _, _, err := OpenPreauthKey(line3, testNow); err == nil {
		t.Fatal("document of another root accepted")
	}
}

// --- Self-requested leave (F-106) ---

func TestLeaveRequest(t *testing.T) {
	f := newFixture(t)
	secrets, req := newRequest(t, "phone")
	if _, err := f.doc.AddDevice(req, "phone", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	sl, err := secrets.NewLeaveRequest(rand.Reader, f.doc.NetworkID, testNow)
	if err != nil {
		t.Fatal(err)
	}
	line, err := EncodeLeave(sl)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeLeave(line)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenLeaveRequest(f.doc, decoded, testNow.Add(LeaveMaxAge+time.Hour)); !errors.Is(err, ErrLeaveExpired) {
		t.Fatalf("got %v", err)
	}
	other, _ := GenerateDeviceSecrets(rand.Reader, testNow)
	forged, _ := other.NewLeaveRequest(rand.Reader, f.doc.NetworkID, testNow)
	forged.DeviceID = secrets.DeviceID
	if _, _, err := OpenLeaveRequest(f.doc, forged, testNow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
	dev, _, err := f.doc.ApplyLeave(decoded, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Name != "phone" || len(f.doc.Devices) != 0 || len(f.doc.Revoked) != 1 {
		t.Fatal("device not revoked")
	}
	if _, _, err := f.doc.ApplyLeave(decoded, testNow); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("second apply: %v", err)
	}
}

// --- Minimum client version (F-027) ---

func TestClientVersion(t *testing.T) {
	cases := []struct {
		have, min string
		ok        bool
	}{
		{"1.2.3", "", true},
		{"1.2.3", "1.2.3", true},
		{"1.10.0", "1.9.9", true},
		{"v2.0.0", "1.9.9", true},
		{"1.2.3-rc1", "1.2.3", true},
		{"1.2.3 (abc)", "1.2.4", false},
		{"0.0.0-dev", "0.1.0", false},
		{"garbage", "0.0.1", false},
		{"", "0.0.1", false},
	}
	for _, c := range cases {
		if got := ClientVersionAtLeast(c.have, c.min); got != c.ok {
			t.Errorf("%q >= %q: got %v", c.have, c.min, got)
		}
	}
	f := newFixture(t)
	for _, bad := range []string{"1.2", "1.2.3.4", "01.2.3", "1.2.x", "1.2.3-rc1"} {
		if err := f.doc.SetMinClientVersion(bad); !errors.Is(err, ErrInvalidClientVersion) {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := f.doc.SetMinClientVersion("1.2.3"); err != nil || f.doc.MinClientVersion != "1.2.3" {
		t.Fatal(err)
	}
}

func TestRevokeDevicesAtomic(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{"a", "b"} {
		_, req := newRequest(t, n)
		if _, err := f.doc.AddDevice(req, n, nil, testNow, DefaultDeviceLife); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.doc.RevokeDevices([]string{"a", "missing"}, testNow); err == nil {
		t.Fatal("unknown device accepted")
	}
	if len(f.doc.Devices) != 2 {
		t.Fatal("failed bulk revoke left a partial change")
	}
	if _, err := f.doc.RevokeDevices([]string{"a", "b", "a"}, testNow); err != nil {
		t.Fatal(err)
	}
	if len(f.doc.Devices) != 0 || len(f.doc.Revoked) != 2 {
		t.Fatal("bulk revoke incomplete")
	}
}

// --- Fuzz targets ---

func FuzzDecodeRootTransition(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	var old, nw Key
	copy(old[:], pub)
	copy(nw[:], newPub)
	st, err := SignRootRotation(priv, RootTransition{NetworkID: strings.Repeat("ab", 16), RevokedRoot: old, NewRoot: nw,
		LastGoodVersion: 3, LastGoodDigest: strings.Repeat("0", 64), Epoch: 1, IssuedAt: testNow})
	if err != nil {
		f.Fatal(err)
	}
	line, _ := EncodeRootTransition(st)
	f.Add(line)
	f.Add("osroot1.")
	f.Add("osroot1.e30")
	f.Fuzz(func(t *testing.T, line string) {
		st, err := DecodeRootTransition(line)
		if err != nil {
			return
		}
		s := &State{Anchor: Anchor{RootKey: pub, NetworkID: strings.Repeat("ab", 16)}, HighestVersion: 3}
		_, _ = s.ApplyTransition(st, testNow)
		_, _ = ParseRootTransition(st)
		if _, err := json.Marshal(st); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzDecodeLeave(f *testing.F) {
	secrets, err := GenerateDeviceSecrets(rand.Reader, testNow)
	if err != nil {
		f.Fatal(err)
	}
	sl, _ := secrets.NewLeaveRequest(rand.Reader, strings.Repeat("cd", 16), testNow)
	line, _ := EncodeLeave(sl)
	f.Add(line)
	f.Add("osleave1.")
	fx := &Document{NetworkID: strings.Repeat("cd", 16)}
	f.Fuzz(func(t *testing.T, line string) {
		sl, err := DecodeLeave(line)
		if err != nil {
			return
		}
		_, _, _ = OpenLeaveRequest(fx, sl, testNow)
	})
}

func FuzzOpenPreauthKey(f *testing.F) {
	f.Add("osauth1.")
	f.Add("osauth1.e30")
	f.Add("osauth1." + strings.Repeat("A", 100))
	f.Fuzz(func(t *testing.T, line string) {
		_, _, _, _ = OpenPreauthKey(line, testNow)
	})
}

func cp(s State) *State {
	c := s.Clone()
	return &c
}
