package service

import (
	"bytes"
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

var wirePass = []byte("bağlama testi parolası 1")

// wireNet makes a signed network with devices a and b; b hosts the files
// service for a. It returns each device's store and secrets.
func wireNet(t *testing.T) (map[string]*member.Store, map[string]*trust.DeviceSecrets) {
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
	cs, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	_, cwg, _ := cs.PublicKeys()
	commit(func(doc *trust.Document) error { return doc.SetCoordinator("127.0.0.1:51820", cwg) })
	secrets := map[string]*trust.DeviceSecrets{}
	for _, name := range []string{"a", "b"} {
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
	stores := map[string]*member.Store{}
	for _, name := range []string{"a", "b"} {
		st, err := member.Join(filepath.Join(base, name), bundle, n.RootFingerprint(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		stores[name] = st
	}
	return stores, secrets
}

// TestE2EFilesWiredOnLoopback: the service builds the receiver from the
// device key and the document, the panel methods see the offer, and an
// accepted file lands in the quarantine.
func TestE2EFilesWiredOnLoopback(t *testing.T) {
	stores, secrets := wireNet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rb := newIdleRuntime(t)
	rb.wire.listenOverride = netip.MustParseAddrPort("127.0.0.1:0")
	rb.wire.tamperPaths = []string{filepath.Join(t.TempDir(), "yok")}
	self, _ := stores["b"].Document().DeviceByName("b")
	rb.startWire(ctx, stores["b"], secrets["b"], self)
	rb.wire.mu.Lock()
	addr := rb.wire.listen
	rb.wire.mu.Unlock()
	if !addr.IsValid() || addr.Port() == 0 {
		t.Fatalf("receiver not listening: %v", addr)
	}

	var priv [p2psend.KeySize]byte
	copy(priv[:], secrets["a"].WireGuardPrivate)
	idA, err := p2psend.NewIdentity(priv)
	if err != nil {
		t.Fatal(err)
	}
	_, bwg, _ := secrets["b"].PublicKeys()
	src := filepath.Join(t.TempDir(), "rapor.txt")
	payload := bytes.Repeat([]byte("uçtan uca "), 500)
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() {
		_, err := p2psend.Send(ctx, idA, p2psend.Target{Name: "b", Key: p2psend.Key(bwg), Addr: addr}, src, nil)
		sent <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for len(rb.E2EPending()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("offer never reached the panel")
		}
		time.Sleep(20 * time.Millisecond)
	}
	offer := rb.E2EPending()[0]
	if err := rb.E2EDecide(offer.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatalf("send: %v", err)
	}
	files, err := rb.E2EQuarantine().List()
	if err != nil || len(files) != 1 || files[0].Size != int64(len(payload)) {
		t.Fatalf("quarantine: %+v %v", files, err)
	}
	// Relay choice is kept for the next start.
	if err := rb.SetE2ERelay(true); err != nil || !rb.loadE2ESettings().Relay {
		t.Fatalf("relay: %v", err)
	}
	if sealed, _ := rb.DeviceKeySealed(); sealed {
		t.Fatal("no device key reported sealed")
	}
	cancel()
	waitFor(t, "E2E service stop", 5*time.Second, func() bool {
		_, err := rb.e2eService()
		return err != nil
	})
	if err := rb.E2EStart(p2psend.SendRequest{Device: "a", Path: src}); err == nil {
		t.Fatal("send accepted without a tunnel")
	}
}

func TestTamperWatchWired(t *testing.T) {
	stores, secrets := wireNet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watched := filepath.Join(t.TempDir(), "openscale.exe")
	if err := os.WriteFile(watched, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newIdleRuntime(t)
	r.wire.tamperPaths = []string{watched}
	r.wire.tamperEvery = 50 * time.Millisecond
	self, _ := stores["a"].Document().DeviceByName("a")
	if err := r.startTamper(ctx, secrets["a"], self); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(watched, []byte("v2 değişti"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tamper event", 5*time.Second, func() bool { return len(r.TamperEvents()) > 0 })
	cancel()
	// A new start reads the signed log back.
	r2 := newIdleRuntime(t)
	r2.cfg.DataDir = r.cfg.DataDir
	r2.wire.tamperPaths = []string{watched}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if err := r2.startTamper(ctx2, secrets["a"], self); err != nil {
		t.Fatal(err)
	}
	if len(r2.TamperEvents()) == 0 {
		t.Fatal("signed log not read back")
	}
}
