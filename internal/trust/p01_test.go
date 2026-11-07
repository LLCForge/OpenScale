package trust

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"
)

func p01Doc(t *testing.T, names ...string) (*fixture, *Document) {
	t.Helper()
	f := newFixture(t)
	doc := f.doc
	for _, n := range names {
		_, req := newRequest(t, n)
		var roles []Role
		if n == "admin" {
			roles = []Role{RoleAdmin}
		}
		if _, err := doc.AddDevice(req, n, roles, testNow, DefaultDeviceLife); err != nil {
			t.Fatal(err)
		}
	}
	doc.Rules = append(doc.Rules, Rule{From: []string{RuleWildcard}, To: []string{RuleWildcard}, Protocol: ProtocolAny, Ports: []string{}})
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	return f, doc
}

func TestP01FieldsAbsentEncodeAsBefore(t *testing.T) {
	f, doc := p01Doc(t, "a")
	env := f.sign(t, doc)
	for _, field := range []string{"revoked_key_digests", "max_key_age_days", "lockdown"} {
		if bytes.Contains(env.Payload, []byte(field)) {
			t.Fatalf("a document without %s must not carry it", field)
		}
	}
	// Setting and clearing every field restores the exact bytes.
	next := *doc
	_ = next.SetMaxKeyAge(30)
	_ = next.SetLockdown(true, "x", testNow)
	_ = next.SetMaxKeyAge(0)
	_ = next.SetLockdown(false, "", testNow)
	a, _ := DocumentPayload(doc)
	b, _ := DocumentPayload(&next)
	if !bytes.Equal(a, b) {
		t.Fatal("cleared fields changed the encoding")
	}
}

func TestRevokedDigestsValidateStrictly(t *testing.T) {
	_, doc := p01Doc(t, "a")
	k := doc.Devices[0].SigningKey
	d1, d2 := RevokedKeyDigest(Key{1}), RevokedKeyDigest(Key{2})
	lo, hi := min(d1, d2), max(d1, d2)
	cases := map[string][]string{
		"unsorted":  {hi, lo},
		"duplicate": {lo, lo},
		"upper":     {strings.ToUpper(lo)},
		"short":     {lo[:31]},
		"nonhex":    {strings.Repeat("z", 32)},
		"device":    {RevokedKeyDigest(k)},
	}
	for name, ds := range cases {
		c := *doc
		c.RevokedKeyDigests = ds
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: must not validate", name)
		}
	}
	c := *doc
	c.RevokedKeyDigests = []string{lo, hi}
	if err := c.Validate(); err != nil {
		t.Fatalf("sorted digests: %v", err)
	}
}

func TestCompactRevocationsKeepsKeysRevoked(t *testing.T) {
	_, doc := p01Doc(t, "a", "b", "c")
	gone := map[string]Device{}
	for i, n := range []string{"a", "b"} {
		d, _ := doc.DeviceByName(n)
		gone[n] = d
		if _, err := doc.RevokeDevice(n, testNow.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	n, err := doc.CompactRevocations(1)
	if err != nil || n != 1 {
		t.Fatalf("compact: %d %v", n, err)
	}
	if len(doc.Revoked) != 1 || doc.Revoked[0].Name != "b" || len(doc.RevokedKeyDigests) != 2 {
		t.Fatalf("kept the wrong revocation: %+v %d", doc.Revoked, len(doc.RevokedKeyDigests))
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	a := gone["a"]
	if !doc.KeyRevoked(a.SigningKey) || !doc.KeyRevoked(a.WireGuardKey) || !doc.KeyRevoked(gone["b"].SigningKey) {
		t.Fatal("compacted keys must stay revoked")
	}
	// Re-adding the compacted key is refused by Validate.
	c, _ := doc.DeviceByName("c")
	re := *doc
	re.Devices = slices.Clone(doc.Devices)
	c.SigningKey = a.SigningKey
	re.Devices[0] = c
	if err := re.Validate(); err == nil {
		t.Fatal("a compacted key must never be enrolled again")
	}
	if n, _ := doc.CompactRevocations(1); n != 0 {
		t.Fatal("nothing left to compact")
	}
	if _, err := doc.CompactRevocations(-1); err == nil {
		t.Fatal("negative keep")
	}
}

func TestLockdownSuspendsRulesAndRestores(t *testing.T) {
	_, doc := p01Doc(t, "admin", "a", "b")
	if !doc.Allows("a", "b", ProtocolTCP, 22) || !doc.MayUseExitNode("a") {
		t.Fatal("rules allow before the lock")
	}
	if err := doc.SetLockdown(true, "ele geçirme şüphesi", testNow); err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	if doc.Allows("a", "b", ProtocolTCP, 22) || doc.Allows("b", "admin", ProtocolTCP, 22) || doc.Visible("a", "b") {
		t.Fatal("members must be cut off under the lock")
	}
	if !doc.Allows("admin", "a", ProtocolTCP, 22) || !doc.Visible("a", "admin") {
		t.Fatal("the admin device keeps access")
	}
	if d := doc.Explain("a", "b", PacketQuery{Proto: 6, Port: 22, ICMPType: -1, At: testNow}); d.Reason != ReasonLockdown {
		t.Fatalf("reason %q", d.Reason)
	}
	if doc.MayUseExitNode("a") || doc.HostsService("b", ServiceSSH) {
		t.Fatal("exit and services are off under the lock")
	}
	if err := doc.SetLockdown(false, "", testNow); err != nil {
		t.Fatal(err)
	}
	if !doc.Allows("a", "b", ProtocolTCP, 22) {
		t.Fatal("rules must come back unchanged")
	}
}

func TestLockdownValidate(t *testing.T) {
	_, doc := p01Doc(t, "a")
	for _, l := range []*Lockdown{
		{},
		{Since: doc.IssuedAt.Add(time.Hour)},
		{Since: doc.IssuedAt, Reason: "a\nb"},
		{Since: doc.IssuedAt, Reason: strings.Repeat("x", maxLockdownReason+1)},
		{Since: doc.IssuedAt, Reason: "\xff"},
	} {
		c := *doc
		c.Lockdown = l
		if err := c.Validate(); err == nil {
			t.Fatalf("lockdown %+v must not validate", l)
		}
	}
	if err := doc.SetLockdown(true, "a\x00", testNow); err == nil {
		t.Fatal("control characters")
	}
}

func TestKeyAgePolicy(t *testing.T) {
	_, doc := p01Doc(t, "a", "b")
	later := testNow.Add(100 * 24 * time.Hour)
	if _, over := doc.KeyOverdue("a", later); over {
		t.Fatal("no policy, nothing overdue")
	}
	if err := doc.SetMaxKeyAge(MaxKeyAgeDays + 1); err == nil {
		t.Fatal("too long")
	}
	if err := doc.SetMaxKeyAge(90); err != nil {
		t.Fatal(err)
	}
	// b rotated its key 50 days in.
	b, _ := doc.DeviceByName("b")
	doc.RetiredKeys = append(doc.RetiredKeys, RetiredKey{DeviceID: b.ID, SigningKey: Key{9}, WireGuardKey: Key{8}, RetiredAt: testNow.Add(50 * 24 * time.Hour)})
	st, over := doc.KeyOverdue("a", later)
	if !over || st.AgeDays != 100 {
		t.Fatalf("a: %+v %v", st, over)
	}
	if _, over := doc.KeyOverdue("b", later); over {
		t.Fatal("b rotated 50 days ago")
	}
	c := *doc
	c.MaxKeyAgeDays = MaxKeyAgeDays + 1
	if err := c.Validate(); err == nil {
		t.Fatal("max_key_age_days bound")
	}
}

func TestLimitUsages(t *testing.T) {
	_, doc := p01Doc(t, "a")
	if len(doc.NearLimits()) != 0 {
		t.Fatal("a small document is near no limit")
	}
	doc.Rules = make([]Rule, (MaxRules*8+9)/10)
	near := doc.NearLimits()
	if len(near) != 1 || near[0].Code != "rules" || near[0].Percent() != 80 {
		t.Fatalf("near: %+v", near)
	}
	if !strings.Contains(LimitWarning(near[0]), "%80") {
		t.Fatal(LimitWarning(near[0]))
	}
}

func TestRandomArt(t *testing.T) {
	a := RandomArt("KÖK", "ABCD-EFGH-IJKL-MNOP")
	b := RandomArt("KÖK", "abcd efgh ijkl mnop")
	c := RandomArt("KÖK", "ABCD-EFGH-IJKL-MNOQ")
	if len(a) != artHeight+2 || !slices.Equal(a, b) || slices.Equal(a, c) {
		t.Fatal("art must be deterministic, normalized and differ for other fingerprints")
	}
	for _, l := range a {
		if n := len([]rune(l)); n != artWidth+2 {
			t.Fatalf("line width %d: %q", n, l)
		}
	}
	if !strings.Contains(strings.Join(a, ""), "S") {
		t.Fatal("start mark")
	}
	rows := SideBySide(a, RandomArt(strings.Repeat("x", 40), "x\x00y"))
	if len(rows) != artHeight+2 {
		t.Fatal("side by side")
	}
}

func FuzzP01Fields(f *testing.F) {
	f.Add("ab", uint32(30), "not", int64(0))
	f.Add(strings.Repeat("a", 32), uint32(0), "", int64(-1))
	f.Fuzz(func(t *testing.T, digest string, days uint32, reason string, since int64) {
		doc := newFixture(t).doc
		doc.RevokedKeyDigests = []string{digest}
		doc.MaxKeyAgeDays = days
		doc.Lockdown = &Lockdown{Since: doc.IssuedAt.Add(time.Duration(since) * time.Second), Reason: reason}
		if err := doc.Validate(); err != nil {
			return
		}
		if !isHexOfLen(digest, revokedDigestLen) || days > MaxKeyAgeDays || doc.Lockdown.Since.After(doc.IssuedAt) {
			t.Fatalf("invalid fields validated: %q %d %d", digest, days, since)
		}
		_ = RandomArt(reason, digest)
	})
}
