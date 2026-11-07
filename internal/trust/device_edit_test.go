package trust

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestRenameDeviceRewritesReferences(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.SetDeviceTags("telefon", []string{"mobil"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetGroup("ofis", []string{"laptop", "tag:mobil"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetExitUsers([]string{"laptop", "group:ofis"}); err != nil {
		t.Fatal(err)
	}
	before, _ := doc.DeviceByName("laptop")
	if err := doc.RenameDevice("laptop", "dizustu"); err != nil {
		t.Fatalf("RenameDevice: %v", err)
	}
	after, ok := doc.DeviceByName("dizustu")
	if !ok || after.ID != before.ID || after.IPv4 != before.IPv4 || after.SigningKey != before.SigningKey {
		t.Fatal("rename must keep id, keys and addresses")
	}
	if _, ok := doc.DeviceByName("laptop"); ok {
		t.Fatal("old name still present")
	}
	if !slices.Equal(doc.Rules[0].From, []string{"dizustu"}) {
		t.Fatalf("rule not rewritten: %v", doc.Rules[0].From)
	}
	if g, _ := doc.GroupByName("ofis"); !slices.Equal(g.Members, []string{"dizustu", "tag:mobil"}) {
		t.Fatalf("group not rewritten: %v", g.Members)
	}
	if users, _ := doc.ExitUsersList(); !slices.Equal(users, []string{"dizustu", "group:ofis"}) {
		t.Fatalf("exit_users not rewritten: %v", users)
	}
	if !doc.Allows("dizustu", "masaustu", ProtocolTCP, 3389) {
		t.Fatal("renamed device lost its rule")
	}
}

func TestRenameDeviceRejections(t *testing.T) {
	_, doc := policyDoc(t)
	snapshot, _ := doc.clone()
	cases := []struct {
		old, new string
		want     error
	}{
		{"laptop", "masaustu", ErrNameTaken},
		{"laptop", CoordinatorName, ErrNameReserved},
		{"laptop", "Bad_Name", ErrInvalidName},
		{"laptop", "", ErrInvalidName},
		{"laptop", "laptop", ErrSameName},
		{"yok", "yeni", ErrUnknownDevice},
	}
	for _, c := range cases {
		if err := doc.RenameDevice(c.old, c.new); !errors.Is(err, c.want) {
			t.Errorf("RenameDevice(%q, %q) = %v, want %v", c.old, c.new, err, c.want)
		}
	}
	if !sameJSON(t, doc, snapshot) {
		t.Fatal("rejected renames must not change the document")
	}
}

func TestExtendAndExpireDevice(t *testing.T) {
	_, doc := policyDoc(t)
	later := testNow.Add(100 * 24 * time.Hour)
	d, err := doc.ExtendDevice("laptop", later, 3650*24*time.Hour)
	if err != nil {
		t.Fatalf("ExtendDevice: %v", err)
	}
	if want := later.Add(MaxDeviceLife); !d.ExpiresAt.Equal(want) {
		t.Fatalf("expires %v, want %v", d.ExpiresAt, want)
	}
	for _, bad := range []time.Duration{0, -time.Hour, time.Millisecond, MaxDeviceLife + time.Second} {
		if _, err := doc.ExtendDevice("laptop", later, bad); !errors.Is(err, ErrInvalidLifetime) {
			t.Errorf("lifetime %v error = %v", bad, err)
		}
	}
	if _, err := doc.ExtendDevice("yok", later, time.Hour); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("unknown device error = %v", err)
	}
	if _, err := doc.ExtendDevice("laptop", testNow.Add(-48*time.Hour), time.Hour); err == nil {
		t.Fatal("an end before added_at must be rejected")
	}

	d, err = doc.ExpireDevice("laptop", later)
	if err != nil {
		t.Fatalf("ExpireDevice: %v", err)
	}
	if !d.ExpiresAt.Equal(later) {
		t.Fatalf("expire set %v, want %v", d.ExpiresAt, later)
	}
	// Expiring right at enrollment keeps expires_at after added_at.
	d, err = doc.ExpireDevice("masaustu", testNow)
	if err != nil || !d.ExpiresAt.After(d.AddedAt) {
		t.Fatalf("expire at added_at: %v %v", d.ExpiresAt, err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAddDeviceLifetimeCap(t *testing.T) {
	f := newFixture(t)
	doc, _ := f.doc.Next(testNow, DefaultValidity)
	_, req := newRequest(t, "a")
	if _, err := doc.AddDevice(req, "a", nil, testNow, MaxDeviceLife+time.Hour); !errors.Is(err, ErrInvalidLifetime) {
		t.Fatalf("over-long lifetime error = %v", err)
	}
	if _, err := doc.AddDevice(req, "a", nil, testNow, MaxDeviceLife); err != nil {
		t.Fatalf("maximum lifetime rejected: %v", err)
	}
}

func sameJSON(t *testing.T, a, b *Document) bool {
	t.Helper()
	x, err := a.clone()
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.clone()
	if err != nil {
		t.Fatal(err)
	}
	ex, _ := jsonBytes(x)
	ey, _ := jsonBytes(y)
	return string(ex) == string(ey)
}
