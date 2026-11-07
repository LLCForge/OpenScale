package trust

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSplitInviteRoundTrip(t *testing.T) {
	_, code, _ := newInviteFixture(t)
	a, b, err := SplitInviteCode(code, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a, "osinv2a.") || !strings.HasPrefix(b, "osinv2b.") || strings.Contains(a, b[8:]) {
		t.Fatalf("parts: %q %q", a, b)
	}
	got, err := CombineInviteParts(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Seed) != string(code.Seed) || got.InviteID != code.InviteID {
		t.Fatal("combined code differs")
	}
	// Part B read aloud: lower case, spaces, no prefix.
	spoken := strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(b, "osinv2b."), "-", " "))
	if _, err := CombineInviteParts(a, spoken); err != nil {
		t.Fatalf("spoken part B: %v", err)
	}
	// Both parts in one field, either order, through DecodeInviteCode.
	for _, line := range []string{a + "\n" + b, b + " " + a} {
		got, err := DecodeInviteCode(line)
		if err != nil || string(got.Seed) != string(code.Seed) {
			t.Fatalf("decode %q: %v", line[:12], err)
		}
	}
	// One part alone never yields a code.
	for _, one := range []string{a, b} {
		if _, err := DecodeInviteCode(one); !errors.Is(err, ErrSplitPartMissing) {
			t.Fatalf("single part: %v", err)
		}
	}
	// Part A alone does not contain the seed.
	if strings.Contains(a, string(code.Seed)) {
		t.Fatal("seed visible in part A")
	}
	// A part B of another split does not match.
	_, b2, err := SplitInviteCode(code, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CombineInviteParts(a, b2); !errors.Is(err, ErrSplitMismatch) {
		t.Fatalf("mismatched parts: %v", err)
	}
	// A forged part A (other root key) is caught by the check.
	f2, code2, _ := newInviteFixture(t)
	_ = f2
	a2, _, err := SplitInviteCode(code2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CombineInviteParts(a2, b); !errors.Is(err, ErrSplitMismatch) {
		t.Fatalf("forged part A: %v", err)
	}
	// Garbage is rejected without panicking.
	for _, bad := range []string{"osinv2a.!!", "osinv2a.e30", "osinv2b.AAAA"} {
		if _, err := CombineInviteParts(bad, b); err == nil {
			t.Fatalf("accepted %q", bad)
		}
		if _, err := CombineInviteParts(a, bad); err == nil {
			t.Fatalf("accepted part B %q", bad)
		}
	}
	// The old single code still decodes.
	line, _ := code.Encode()
	if _, err := DecodeInviteCode(line); err != nil {
		t.Fatal(err)
	}
}

func p02Doc(t *testing.T) (*Document, map[string]*DeviceSecrets) {
	t.Helper()
	f := newFixture(t)
	doc, err := f.doc.Next(testNow, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]*DeviceSecrets{}
	for _, name := range []string{"laptop", "masaustu", "yeni", "nas"} {
		s, req := newRequest(t, name)
		secrets[name] = s
		if _, err := doc.AddDevice(req, name, nil, testNow, DefaultDeviceLife); err != nil {
			t.Fatal(err)
		}
	}
	if err := doc.SetDeviceTags("laptop", []string{"aile"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetGroup("evdekiler", []string{"laptop", "nas"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetExitUsers([]string{"laptop"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Rule{
		{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: ProtocolTCP, Ports: []string{"3389"}},
		{From: []string{"masaustu", "laptop"}, To: []string{"nas"}, Protocol: ProtocolTCP, Ports: []string{"445"}},
		{From: []string{"tag:aile"}, To: []string{"nas"}, Protocol: ProtocolTCP, Ports: []string{"80"}},
		{From: []string{"nas"}, To: []string{"laptop"}, Protocol: ProtocolUDP, Ports: []string{"9"}},
	} {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	return doc, secrets
}

func TestLikeDevice(t *testing.T) {
	doc, _ := p02Doc(t)
	s, err := doc.LikeDevice("laptop", "yeni")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Tags) != 1 || s.Tags[0] != "aile" || len(s.Groups) != 1 || !s.ExitUser {
		t.Fatalf("suggestion: %+v", s)
	}
	// Rules naming laptop directly (3 of them); the tag rule is covered by the tag.
	if len(s.Rules) != 3 {
		t.Fatalf("rules: %+v", s.Rules)
	}
	if s.Rules[1].From[0] != "masaustu" || s.Rules[1].From[1] != "yeni" {
		t.Fatalf("replace: %+v", s.Rules[1])
	}
	before := len(doc.Rules)
	if err := doc.ApplyLike(s, true); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != before+3 || !doc.Allows("yeni", "masaustu", ProtocolTCP, 3389) || !doc.Allows("yeni", "nas", ProtocolTCP, 80) {
		t.Fatal("yeni did not get laptop's access")
	}
	if users, _ := doc.ExitUsersList(); len(users) != 2 {
		t.Fatalf("exit users: %v", users)
	}
	// Applying the same suggestion again proposes nothing new.
	again, _ := doc.LikeDevice("laptop", "yeni")
	if len(again.Rules) != 0 || len(again.Tags) != 0 || len(again.Groups) != 0 || again.ExitUser {
		t.Fatalf("second suggestion: %+v", again)
	}
	if _, err := doc.LikeDevice("laptop", "laptop"); err == nil {
		t.Fatal("self copy accepted")
	}
	if _, err := doc.LikeDevice("yok", "yeni"); !errors.Is(err, ErrUnknownDevice) {
		t.Fatal(err)
	}
}

func TestDeviceExposureAndDrop(t *testing.T) {
	doc, _ := p02Doc(t)
	e, err := doc.DeviceExposure("laptop")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Outbound) != 3 || len(e.Inbound) != 1 || !e.ExitUser || len(e.Groups) != 1 {
		t.Fatalf("exposure: %+v", e)
	}
	if !e.Outbound[0].OnlyThisDevice || e.Outbound[1].OnlyThisDevice {
		t.Fatalf("only flags: %+v", e.Outbound)
	}
	if n := doc.DropRulesOnlyFor("laptop"); n != 2 {
		t.Fatalf("dropped %d", n)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAccessRequest(t *testing.T) {
	doc, secrets := p02Doc(t)
	now := testNow.Add(time.Hour)
	line, _, err := secrets["laptop"].NewAccessRequest(doc, AccessRequestInput{To: "masaustu", Service: ServiceSSH, Users: []string{"ali"}, Hours: 8, Reason: "yedek kontrolü"}, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, id, err := OpenAccessRequest(doc, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.From != "laptop" || r.To != "masaustu" || len(id) != 24 {
		t.Fatalf("request: %+v %s", r, id)
	}
	rule, err := r.Rule(now, 0)
	if err != nil || !rule.NotAfter.Equal(now.UTC().Truncate(time.Second).Add(8*time.Hour)) {
		t.Fatalf("rule: %+v %v", rule, err)
	}
	if err := doc.AddRule(rule); err != nil {
		t.Fatalf("approved rule invalid: %v", err)
	}
	if _, err := r.Rule(now, 9); err == nil {
		t.Fatal("approval lengthened the request")
	}
	// Tampering breaks the signature.
	tampered := line[:len(line)-3] + "AAA"
	if _, _, err := OpenAccessRequest(doc, tampered, now); err == nil {
		t.Fatal("tampered request accepted")
	}
	// Too old.
	if _, _, err := OpenAccessRequest(doc, line, now.Add(AccessRequestMaxAge+time.Hour)); err == nil {
		t.Fatal("old request accepted")
	}
	// Revoked device.
	if _, err := doc.RevokeDevice("laptop", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenAccessRequest(doc, line, now); err == nil {
		t.Fatal("request of a revoked device accepted")
	}
	// Bad inputs.
	for _, in := range []AccessRequestInput{
		{To: "nas", Hours: 0, Service: ServiceSSH},
		{To: "nas", Hours: 2, Protocol: ProtocolTCP},
		{To: "nas", Hours: 2},
		{To: "yeni", Hours: 2, Service: ServiceSSH, Ports: []string{"22"}},
	} {
		if _, _, err := secrets["yeni"].NewAccessRequest(doc, in, now, rand.Reader); err == nil {
			t.Fatalf("accepted %+v", in)
		}
	}
}
