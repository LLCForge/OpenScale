package service

import (
	"context"
	"crypto/rand"
	"errors"
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

// f2Net makes a signed network where a may send files to b and c is a
// member without any rule towards b.
func f2Net(t *testing.T) (*member.Store, map[string]*trust.DeviceSecrets) {
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
	for _, name := range []string{"a", "b", "c"} {
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
		commit(func(doc *trust.Document) error {
			_, err := doc.AddDevice(req, name, nil, time.Now(), trust.DefaultDeviceLife)
			return err
		})
	}
	commit(func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"a"}, To: []string{"b"}, Service: trust.ServiceFiles})
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

// TestE2EReceiverEnforcesSignedFilesRule: the service wires the receiver to
// the signed document, so a member without a files rule is refused before
// the owner's approval queue, whichever path its stream took.
func TestE2EReceiverEnforcesSignedFilesRule(t *testing.T) {
	store, secrets := f2Net(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
	copy(priv[:], secrets["c"].WireGuardPrivate)
	idC, err := p2psend.NewIdentity(priv)
	clear(priv[:])
	if err != nil {
		t.Fatal(err)
	}
	_, bwg, _ := secrets["b"].PublicKeys()
	src := filepath.Join(t.TempDir(), "yasak.txt")
	if err := os.WriteFile(src, []byte("kural yok"), 0o600); err != nil {
		t.Fatal(err)
	}
	sendCtx, sendCancel := context.WithTimeout(ctx, 5*time.Second)
	defer sendCancel()
	_, err = p2psend.Send(sendCtx, idC, p2psend.Target{Name: "b", Key: p2psend.Key(bwg), Addr: addr}, src,
		&p2psend.SendOptions{Route: p2psend.RouteDirect})
	if !errors.Is(err, p2psend.ErrRejected) {
		t.Fatalf("offer from member without a rule: got %v, want rejected", err)
	}
	if n := len(rb.E2EPending()); n != 0 {
		t.Fatalf("%d offers reached the owner", n)
	}
	files, err := rb.E2EQuarantine().List()
	if err != nil || len(files) != 0 {
		t.Fatalf("quarantine: %+v %v", files, err)
	}
}
