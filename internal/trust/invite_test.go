package trust

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func newInviteFixture(t *testing.T) (*fixture, *InviteCode, Invite) {
	t.Helper()
	f := newFixture(t)
	if err := f.doc.SetCoordinator("vpn.example.org:41820", testKey(t)); err != nil {
		t.Fatal(err)
	}
	seed, err := NewInviteSeed(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveInviteKeys(seed)
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewNetworkID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := f.doc.AddInvite(id, keys, testNow, DefaultInviteLife)
	if err != nil {
		t.Fatalf("AddInvite: %v", err)
	}
	code, err := NewInviteCode(f.rootPub, f.doc, inv, seed)
	if err != nil {
		t.Fatal(err)
	}
	return f, code, inv
}

func testKey(t *testing.T) Key {
	t.Helper()
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestInviteCodeRoundTrip(t *testing.T) {
	f, code, inv := newInviteFixture(t)
	line, err := code.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, invitePrefix) || len(line) > maxInviteChars {
		t.Fatalf("unexpected code line length %d", len(line))
	}
	// Line breaks and spaces added by chat apps are ignored.
	got, err := DecodeInviteCode(line[:40] + "\n  " + line[40:])
	if err != nil {
		t.Fatalf("DecodeInviteCode: %v", err)
	}
	if got.InviteID != inv.ID || got.IPv4 != inv.IPv4 || got.RootKey != code.RootKey || got.Coordinator != code.Coordinator {
		t.Fatal("decoded code differs")
	}
	if !got.Anchor().RootKey.Equal(f.rootPub) {
		t.Fatal("anchor root key differs")
	}
	if _, err := DecodeInviteCode(line[:len(line)-4]); err == nil {
		t.Fatal("truncated code accepted")
	}
	if _, err := DecodeInviteCode("osjoin1.abc"); err == nil {
		t.Fatal("foreign prefix accepted")
	}
}

func TestInviteEnrollmentVerifies(t *testing.T) {
	f, code, inv := newInviteFixture(t)
	secrets, _ := newRequest(t, "laptop")
	se, req, err := secrets.NewInviteEnrollment(code, "Laptop.local", testNow)
	if err != nil {
		t.Fatal(err)
	}
	got, gotInv, err := OpenInviteEnrollment(f.doc, se, testNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("OpenInviteEnrollment: %v", err)
	}
	if gotInv.ID != inv.ID || got.Fingerprint() != req.Fingerprint() || got.Hostname != "laptop" {
		t.Fatal("verified enrollment differs")
	}
	if c := got.ShortCode(); len(c) != 4 || !SameShortCode(c, req.ShortCode()) {
		t.Fatalf("short code %q", c)
	}

	// The payload is bound by both signatures.
	tampered := se
	tampered.Payload = []byte(strings.Replace(string(se.Payload), "laptop", "evil00", 1))
	if _, _, err := OpenInviteEnrollment(f.doc, tampered, testNow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered payload: %v", err)
	}

	// Someone without the invite seed (e.g. the coordinator) cannot sign.
	other, _ := newRequest(t, "intruder")
	forgedCode := *code
	forgedCode.Seed = make([]byte, InviteSeedSize)
	forged, _, err := other.NewInviteEnrollment(&forgedCode, "intruder", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenInviteEnrollment(f.doc, forged, testNow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged enrollment: %v", err)
	}

	if _, _, err := OpenInviteEnrollment(f.doc, se, inv.ExpiresAt); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("expired invite: %v", err)
	}
	if err := f.doc.MarkInviteUsed(inv.ID, got.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenInviteEnrollment(f.doc, se, testNow); !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("used invite: %v", err)
	}
}

func TestInviteValidation(t *testing.T) {
	f, _, inv := newInviteFixture(t)
	dup := inv
	f.doc.Invites = append(f.doc.Invites, dup)
	if err := f.doc.Validate(); err == nil {
		t.Fatal("duplicate invite accepted")
	}
	f.doc.Invites = f.doc.Invites[:1]

	// A device added afterwards never takes the invite's address.
	_, req := newRequest(t, "pc")
	d, err := f.doc.AddDevice(req, "pc", nil, testNow, DefaultDeviceLife)
	if err != nil {
		t.Fatal(err)
	}
	if d.IPv4 == inv.IPv4 {
		t.Fatal("device got the invite address")
	}

	long := inv
	long.ExpiresAt = long.CreatedAt.Add(MaxInviteLife + time.Second)
	f.doc.Invites[0] = long
	if err := f.doc.Validate(); err == nil {
		t.Fatal("over-long invite accepted")
	}
	f.doc.Invites[0] = inv

	if n := f.doc.PruneInvites(inv.ExpiresAt); n != 1 || f.doc.Invites != nil {
		t.Fatalf("prune removed %d", n)
	}
}

func TestTaggedInvite(t *testing.T) {
	f, _, _ := newInviteFixture(t)
	doc, err := f.doc.Next(testNow, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := NewInviteSeed(rand.Reader)
	keys, _ := DeriveInviteKeys(seed)
	inv, err := doc.AddTaggedInvite(strings.Repeat("7", 32), keys, testNow, DefaultInviteLife, []string{"tag:mobil", "aile"})
	if err != nil {
		t.Fatalf("AddTaggedInvite: %v", err)
	}
	if len(inv.Tags) != 2 || inv.Tags[0] != "mobil" {
		t.Fatalf("invite tags = %v", inv.Tags)
	}
	if got := doc.TagUsage(); len(got) != 0 {
		t.Fatalf("invite tags must count as used: %v", got)
	}
	seed2, _ := NewInviteSeed(rand.Reader)
	keys2, _ := DeriveInviteKeys(seed2)
	if _, err := doc.AddTaggedInvite(strings.Repeat("8", 32), keys2, testNow, DefaultInviteLife, []string{"Kötü"}); err == nil {
		t.Fatal("invalid invite tag must be rejected")
	}
}

func TestInviteNeedsCoordinator(t *testing.T) {
	f := newFixture(t)
	keys, err := DeriveInviteKeys(make([]byte, InviteSeedSize))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := NewNetworkID(rand.Reader)
	if _, err := f.doc.AddInvite(id, keys, testNow, time.Hour); err == nil {
		t.Fatal("invite without coordinator accepted")
	}
}
