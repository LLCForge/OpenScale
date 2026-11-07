package service

import (
	"context"
	"crypto/rand"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/p2psend"
	"github.com/openscale/openscale/internal/trust"
)

// f2ExpiredNet makes a signed network where device "eski" holds a files rule
// to "b" but its membership has already ended.
func f2ExpiredNet(t *testing.T) (*member.Store, map[string]*trust.DeviceSecrets) {
	t.Helper()
	base := t.TempDir()
	opts := admin.Options{Argon2: trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}, Random: rand.Reader}
	n, err := admin.Init(filepath.Join(base, "ag"), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, wirePass, opts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commit := func(change admin.Change) {
		plan, err := n.Prepare(time.Now(), trust.DefaultValidity, change)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Commit(plan, wirePass); err != nil {
			t.Fatal(err)
		}
	}
	cs, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, cwg, _ := cs.PublicKeys()
	commit(func(doc *trust.Document) error { return doc.SetCoordinator("127.0.0.1:51820", cwg) })
	secrets := map[string]*trust.DeviceSecrets{}
	for _, name := range []string{"eski", "b"} {
		s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		secrets[name] = s
		env, _, err := s.NewEnrollmentRequest(name, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req, err := trust.OpenEnrollmentRequest(env, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		added, life := time.Now(), trust.DefaultDeviceLife
		if name == "eski" {
			added, life = time.Now().Add(-2*time.Hour), time.Hour
		}
		commit(func(doc *trust.Document) error {
			_, err := doc.AddDevice(req, name, nil, added, life)
			return err
		})
	}
	commit(func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"eski"}, To: []string{"b"}, Service: trust.ServiceFiles})
	})
	bundle, err := n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	st, err := member.Join(filepath.Join(base, "b"), bundle, n.RootFingerprint(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return st, secrets
}

// TestE2EReceiverRefusesExpiredMember: the tunnel drops a device whose
// membership ended, but on a relayed stream the receiver only sees the last
// relay. The signed document still names the device and its rule, so the
// receiver itself must refuse it as a sender, relay hop and relay target.
func TestE2EReceiverRefusesExpiredMember(t *testing.T) {
	store, secrets := f2ExpiredNet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	old, ok := store.Document().DeviceByName("eski")
	if !ok || !time.Now().After(old.ExpiresAt) {
		t.Fatalf("fixture: device %+v should have expired", old)
	}
	if !store.Document().AllowsFileSend("eski", "b") {
		t.Fatal("fixture: rule should still name the expired device")
	}

	rb := newIdleRuntime(t)
	rb.wire.listenOverride = netip.MustParseAddrPort("127.0.0.1:0")
	rb.wire.tamperPaths = []string{filepath.Join(t.TempDir(), "yok")}
	self, _ := store.Document().DeviceByName("b")
	rb.startWire(ctx, store, secrets["b"], self)
	rb.wire.mu.Lock()
	addr := rb.wire.listen
	rb.wire.mu.Unlock()
	if !addr.IsValid() || addr.Port() == 0 {
		t.Fatalf("receiver not listening: %v", addr)
	}

	var priv [p2psend.KeySize]byte
	copy(priv[:], secrets["eski"].WireGuardPrivate)
	id, err := p2psend.NewIdentity(priv)
	clear(priv[:])
	if err != nil {
		t.Fatal(err)
	}
	_, bwg, _ := secrets["b"].PublicKeys()
	src := filepath.Join(t.TempDir(), "eski.txt")
	if err := os.WriteFile(src, []byte("uyelik bitti"), 0o600); err != nil {
		t.Fatal(err)
	}
	sendCtx, sendCancel := context.WithTimeout(ctx, 3*time.Second)
	defer sendCancel()
	_, err = p2psend.Send(sendCtx, id, p2psend.Target{Name: "b", Key: p2psend.Key(bwg), Addr: addr}, src,
		&p2psend.SendOptions{Route: p2psend.RouteDirect})
	if err == nil {
		t.Fatal("expired member's transfer succeeded")
	}
	if n := len(rb.E2EPending()); n != 0 {
		t.Fatalf("%d offers from an expired member reached the owner", n)
	}
	files, err := rb.E2EQuarantine().List()
	if err != nil || len(files) != 0 {
		t.Fatalf("quarantine: %+v %v", files, err)
	}

	dir := docDirectory{store: store, now: time.Now}
	if _, ok := dir.ByKey(p2psend.Key(old.WireGuardKey)); ok {
		t.Fatal("directory resolved an expired device by key")
	}
	if _, ok := dir.ByAddr(old.IPv4); ok {
		t.Fatal("directory resolved an expired device by address")
	}
	if _, ok := dir.byName("eski"); ok {
		t.Fatal("directory resolved an expired device by name")
	}
	if _, ok := dir.byName("b"); !ok {
		t.Fatal("directory lost a current device")
	}
}
