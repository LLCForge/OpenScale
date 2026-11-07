package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/testnet/evilcoord"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/winapp"
)

// Owner note (1.0.0-beta.2): even a fully compromised coordinator must not
// get remote access. The coordinator only relays signed documents and
// endpoints; it never holds the root key. These tests play the attacker:
// forged, altered, stripped, foreign and replayed documents, a document
// that adds the attacker's own device or swaps a member's WireGuard key, and
// connections from addresses the signed document does not list. None of it
// may grant a remote desktop or SSH session, and the Windows firewall limit
// for RDP and OpenSSH must only ever use the root-signed address ranges.
// Nothing here touches the real firewall: the scope calls are fakes.

var compromiseNow = time.Now().UTC().Truncate(time.Second)

// compromiseNet is a root-signed network: nas hosts remote desktop and
// SSH for laptop; tv is a member without any rule.
type compromiseNet struct {
	root    ed25519.PrivateKey
	anchor  trust.Anchor
	doc     *trust.Document
	env     []byte
	sshUser string
}

func compromiseAddDevice(t *testing.T, doc *trust.Document, name string) {
	t.Helper()
	s, err := trust.GenerateDeviceSecrets(rand.Reader, compromiseNow)
	if err != nil {
		t.Fatal(err)
	}
	_, req, err := s.NewEnrollmentRequest(name, compromiseNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doc.AddDevice(req, name, nil, compromiseNow, 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

func newCompromiseNet(t *testing.T) *compromiseNet {
	t.Helper()
	pub, priv, err := trust.GenerateRootKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := trust.NewNetworkID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.NewDocument(id, "ev.test", netip.MustParsePrefix("100.64.0.0/24"), netip.MustParsePrefix("fd7a:115c:a1e0::/64"), compromiseNow, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"nas", "laptop", "tv"} {
		compromiseAddDevice(t, doc, n)
	}
	user := "ali"
	if runtime.GOOS == "windows" {
		user = trust.SSHWindowsUser
	}
	for _, r := range []trust.Rule{
		{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceRemoteDesktop, AllowControl: true},
		{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSSH, Users: []string{user}},
	} {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	return &compromiseNet{root: priv, anchor: trust.Anchor{RootKey: pub, NetworkID: id}, doc: doc, env: signEnv(t, doc, priv), sshUser: user}
}

func signEnv(t *testing.T, doc *trust.Document, key ed25519.PrivateKey) []byte {
	t.Helper()
	env, err := trust.SignDocument(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trust.MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// storeEngine serves the document of a member store: exactly what the
// device accepted, never what the coordinator merely sent.
type storeEngine struct {
	mu    sync.Mutex
	store *member.Store
	self  string
}

func (e *storeEngine) Document() *trust.Document {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.store.Document()
}

func (e *storeEngine) Self() (trust.Device, error) {
	d, ok := e.Document().DeviceByName(e.self)
	if !ok {
		return trust.Device{}, errors.New("not a member")
	}
	return d, nil
}

// attacks returns the documents a compromised coordinator can send.
func (n *compromiseNet) attacks(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	coord, err := evilcoord.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	coord.Publish(n.env)
	for _, b := range []evilcoord.Behavior{evilcoord.Forge, evilcoord.Tamper, evilcoord.Strip, evilcoord.Foreign} {
		coord.SetBehavior(b)
		data, err := coord.Serve("nas")
		if err != nil {
			t.Fatalf("%s: %v", b, err)
		}
		out["evilcoord-"+b.String()] = data
	}
	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The attacker's own device with remote desktop and SSH rules to nas,
	// signed with the coordinator's key.
	next, err := n.doc.Next(compromiseNow, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	compromiseAddDevice(t, next, "saldirgan")
	for _, r := range []trust.Rule{
		{From: []string{"saldirgan"}, To: []string{"nas"}, Service: trust.ServiceRemoteDesktop, AllowControl: true, AllowUnattended: true},
		{From: []string{"saldirgan"}, To: []string{"nas"}, Service: trust.ServiceSSH, Users: []string{n.sshUser}},
	} {
		if err := next.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	out["attacker-device"] = signEnv(t, next, attacker)
	// laptop's WireGuard key swapped for the attacker's (a fake peer key
	// behind laptop's address and rules).
	swap, err := n.doc.Next(compromiseNow, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	evil, err := trust.GenerateDeviceSecrets(rand.Reader, compromiseNow)
	if err != nil {
		t.Fatal(err)
	}
	_, evilReq, err := evil.NewEnrollmentRequest("laptop", compromiseNow)
	if err != nil {
		t.Fatal(err)
	}
	for i := range swap.Devices {
		if swap.Devices[i].Name == "laptop" {
			swap.Devices[i].WireGuardKey = evilReq.WireGuardKey
		}
	}
	out["swapped-key"] = signEnv(t, swap, attacker)
	// The genuine document with the network ranges widened to the
	// attacker's LAN inside the signed payload (signature kept).
	var env trust.Envelope
	if env, err = trust.UnmarshalEnvelope(n.env); err != nil {
		t.Fatal(err)
	}
	env.Payload = []byte(strings.Replace(string(env.Payload), `"100.64.0.0/24"`, `"0.0.0.0/0"`, 1))
	widened, err := trust.MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	out["widened-ranges"] = widened
	return out
}

func TestCompromisedCoordinatorDocumentsRefused(t *testing.T) {
	n := newCompromiseNet(t)
	store, err := member.JoinAnchor(t.TempDir(), n.anchor, n.env, compromiseNow)
	if err != nil {
		t.Fatal(err)
	}
	accepted := store.Document()
	for name, data := range n.attacks(t) {
		changed, err := store.Accept(data, compromiseNow.Add(time.Minute))
		if err == nil || changed {
			t.Errorf("%s: document accepted (changed=%v, err=%v)", name, changed, err)
		}
		if got := store.Document(); got.Version != accepted.Version || len(got.Devices) != len(accepted.Devices) || got.IPv4Prefix != accepted.IPv4Prefix {
			t.Fatalf("%s: stored document changed to v%d", name, got.Version)
		}
	}
	// Replaying the genuine document is harmless: nothing changes.
	if changed, err := store.Accept(n.env, compromiseNow.Add(time.Minute)); changed || err != nil {
		t.Fatalf("replay: changed=%v err=%v", changed, err)
	}
}

func TestCompromisedCoordinatorGetsNoRemoteDesktopOrSSH(t *testing.T) {
	n := newCompromiseNet(t)
	store, err := member.JoinAnchor(t.TempDir(), n.anchor, n.env, compromiseNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range n.attacks(t) {
		_, _ = store.Accept(data, compromiseNow.Add(time.Minute))
	}
	eng := &storeEngine{store: store, self: "nas"}
	a := NewApps(AppsConfig{Dir: t.TempDir(), Engine: func() AppEngine { return eng }})
	doc := store.Document()
	laptop, _ := doc.DeviceByName("laptop")
	tv, _ := doc.DeviceByName("tv")
	nas, _ := doc.DeviceByName("nas")

	// The legitimate rule still works (the checks are not simply closed).
	if d := a.authorizeRDesk(laptop.IPv4, rdesk.ModeControl); !d.Allowed {
		t.Fatalf("laptop control refused: %+v", d)
	}
	if ok, why := a.authorizeSSH(laptop.IPv4, n.sshUser); !ok {
		t.Fatalf("laptop SSH refused: %s", why)
	}

	// The address the forged document gave the attacker's device, the next
	// free one, an address outside the network, the coordinator's relay
	// path seen as a LAN address and loopback: none is a device of the
	// signed document.
	strangers := []netip.Addr{
		netip.MustParseAddr("100.64.0.4"), netip.MustParseAddr("100.64.0.200"),
		netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("203.0.113.7"),
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::99"),
	}
	for _, from := range strangers {
		for _, mode := range []rdesk.Mode{rdesk.ModeView, rdesk.ModeControl} {
			if d := a.authorizeRDesk(from, mode); d.Allowed {
				t.Errorf("remote desktop %v from %v allowed", mode, from)
			}
		}
		if ok, _ := a.authorizeSSH(from, n.sshUser); ok {
			t.Errorf("SSH from %v allowed", from)
		}
		if ok, _ := a.authorizeSSH(from, trust.SSHRootUser); ok {
			t.Errorf("SSH root from %v allowed", from)
		}
	}
	// A member without a rule and this device itself get nothing either.
	for _, dev := range []trust.Device{tv, nas} {
		if d := a.authorizeRDesk(dev.IPv4, rdesk.ModeView); d.Allowed {
			t.Errorf("remote desktop from %s allowed", dev.Name)
		}
		if ok, _ := a.authorizeSSH(dev.IPv4, n.sshUser); ok {
			t.Errorf("SSH from %s allowed", dev.Name)
		}
	}
	// laptop's key in the signed document is still laptop's own: the
	// swapped key is unknown to WireGuard, so its packets never reach the
	// services with laptop's address.
	for _, d := range doc.Devices {
		if d.Name == "saldirgan" {
			t.Fatal("attacker device in the accepted document")
		}
	}
	if got, _ := n.doc.DeviceByName("laptop"); got.WireGuardKey != laptop.WireGuardKey {
		t.Fatal("laptop key changed")
	}
}

// fakeRemoteAccess replaces the Windows firewall calls for one test.
type fakeRemoteAccess struct {
	mu        sync.Mutex
	status    winapp.RemoteAccessStatus
	statusErr error
	calls     []string
	prefixes  [][]netip.Prefix
	opened    bool
}

func installFakeRemoteAccess(t *testing.T, f *fakeRemoteAccess) {
	t.Helper()
	prevScope, prevStatus := remoteAccessScopeFn, remoteAccessStatusFn
	remoteAccessScopeFn = func(svc string, overlayOnly bool, prefixes []netip.Prefix) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if !overlayOnly {
			f.opened = true
		}
		f.calls = append(f.calls, svc)
		f.prefixes = append(f.prefixes, slices.Clone(prefixes))
		return nil
	}
	remoteAccessStatusFn = func() (winapp.RemoteAccessStatus, error) { return f.status, f.statusErr }
	t.Cleanup(func() { remoteAccessScopeFn, remoteAccessStatusFn = prevScope, prevStatus })
}

func boolPtr(v bool) *bool { return &v }

func TestRemoteAccessLimitedToTunnelByDefault(t *testing.T) {
	overlay := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/24"), netip.MustParsePrefix("fd7a:115c:a1e0::/64")}
	both := winapp.RemoteAccessStatus{RDPEnabled: true, SSHInstalled: true}
	cases := []struct {
		name      string
		st        settings
		status    winapp.RemoteAccessStatus
		statusErr error
		want      []string
	}{
		{"never chosen, both present", settings{}, both, nil, []string{"rdp", "ssh"}},
		{"never chosen, nothing installed", settings{}, winapp.RemoteAccessStatus{}, nil, nil},
		{"never chosen, only SSH", settings{}, winapp.RemoteAccessStatus{SSHInstalled: true}, nil, []string{"ssh"}},
		{"status unreadable fails closed", settings{}, winapp.RemoteAccessStatus{}, errors.New("powershell"), []string{"rdp", "ssh"}},
		{"owner turned RDP off", settings{RDPOverlayOnly: boolPtr(false)}, both, nil, []string{"ssh"}},
		{"owner turned both off", settings{RDPOverlayOnly: boolPtr(false), SSHOverlayOnly: boolPtr(false)}, both, nil, nil},
		{"owner turned RDP on", settings{RDPOverlayOnly: boolPtr(true), SSHOverlayOnly: boolPtr(false)}, winapp.RemoteAccessStatus{}, nil, []string{"rdp"}},
		{"unsupported platform", settings{}, both, winapp.ErrUnsupported, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeRemoteAccess{status: c.status, statusErr: c.statusErr}
			installFakeRemoteAccess(t, f)
			got := applyRemoteAccessScopes(c.st, overlay, slog.New(slog.DiscardHandler))
			if !slices.Equal(got, c.want) || !slices.Equal(f.calls, c.want) {
				t.Fatalf("applied %v (calls %v), want %v", got, f.calls, c.want)
			}
			if f.opened {
				t.Fatal("the default opened a service")
			}
			for _, p := range f.prefixes {
				if !slices.Equal(p, overlay) {
					t.Fatalf("scope %v, want %v", p, overlay)
				}
			}
		})
	}
	// Without the network ranges nothing is changed.
	f := &fakeRemoteAccess{status: both}
	installFakeRemoteAccess(t, f)
	if got := applyRemoteAccessScopes(settings{}, nil, nil); got != nil || len(f.calls) != 0 {
		t.Fatalf("no prefixes: %v", got)
	}
}

func TestRemoteAccessChoiceEncoding(t *testing.T) {
	dir := t.TempDir()
	// A settings file written before 1.0.0-beta.2 with the limit on.
	if err := os.WriteFile(filepath.Join(dir, settingsFile), []byte(`{"coordinator_port":41820,"rdp_overlay_only":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := loadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if on, explicit := overlayOnlyChoice(st.RDPOverlayOnly); !on || !explicit {
		t.Fatal("old RDP choice lost")
	}
	if on, explicit := overlayOnlyChoice(st.SSHOverlayOnly); !on || explicit {
		t.Fatal("missing SSH setting must mean the default (on)")
	}
	// The owner's "off" survives a save and load.
	st.SSHOverlayOnly = boolPtr(false)
	if err := saveSettings(dir, st); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, settingsFile))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["ssh_overlay_only"]) != "false" {
		t.Fatalf("explicit off not written: %s", data)
	}
	back, err := loadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if on, explicit := overlayOnlyChoice(back.SSHOverlayOnly); on || !explicit {
		t.Fatal("explicit off lost")
	}
}

// TestRemoteAccessScopeUsesSignedRanges: the firewall limit is built from
// the document the device accepted. A coordinator that sends a document
// with wider ranges (or a forged one) cannot widen who may reach RDP/SSH.
func TestRemoteAccessScopeUsesSignedRanges(t *testing.T) {
	n := newCompromiseNet(t)
	dataDir := t.TempDir()
	store, err := member.JoinAnchor(filepath.Join(dataDir, DeviceDir), n.anchor, n.env, compromiseNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range n.attacks(t) {
		_, _ = store.Accept(data, compromiseNow.Add(time.Minute))
	}
	f := &fakeRemoteAccess{status: winapp.RemoteAccessStatus{RDPEnabled: true, SSHInstalled: true}}
	installFakeRemoteAccess(t, f)
	r := &Runtime{cfg: Config{DataDir: dataDir, Now: time.Now}, logger: slog.New(slog.DiscardHandler)}
	r.reapplyRemoteAccess()
	want := []netip.Prefix{n.doc.IPv4Prefix, n.doc.IPv6Prefix}
	if !slices.Equal(f.calls, []string{"rdp", "ssh"}) {
		t.Fatalf("calls %v", f.calls)
	}
	for _, p := range f.prefixes {
		if !slices.Equal(p, want) {
			t.Fatalf("scope %v, want the signed ranges %v", p, want)
		}
		for _, x := range p {
			if x.Bits() == 0 {
				t.Fatalf("scope opened to everyone: %v", p)
			}
		}
	}
}
