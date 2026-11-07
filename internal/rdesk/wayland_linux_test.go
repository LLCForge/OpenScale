//go:build linux

package rdesk

import (
	"context"
	"errors"
	"image"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/dbuswire"
)

// fakePortal is xdg-desktop-portal's ScreenCast and RemoteDesktop on a
// private bus: every request answers through a Request object's Response
// signal, as the real portal does.
type fakePortal struct {
	bus   *dbuswire.Conn
	deny  string // method whose Response says "cancelled"
	mu    sync.Mutex
	calls []string
}

func (p *fakePortal) record(s string) {
	p.mu.Lock()
	p.calls = append(p.calls, s)
	p.mu.Unlock()
}

func (p *fakePortal) seen() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.calls, "|")
}

func optionsOf(v any) map[string]dbuswire.Variant { return variantMap(v) }

// request returns the request path and sends the Response a moment later.
func (p *fakePortal) request(method string, c *dbuswire.MethodCall, opts map[string]dbuswire.Variant, results func() map[string]dbuswire.Variant) ([]any, error) {
	p.record(method)
	token, _ := opts["handle_token"].Value.(string)
	path := portalRequestPath(c.Sender, token)
	code := uint32(0)
	if method == p.deny {
		code = 1
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = p.bus.Emit(path, portalRequest, "Response", "ua{sv}", code, results())
	}()
	return []any{path}, nil
}

func startFakePortal(t *testing.T, ctx context.Context, sock, deny string) *fakePortal {
	t.Helper()
	bus, err := dbuswire.Dial(ctx, dbuswire.Endpoint{Path: sock}, dbuswire.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bus.Close() })
	p := &fakePortal{bus: bus, deny: deny}
	none := func() map[string]dbuswire.Variant { return map[string]dbuswire.Variant{} }
	createSession := func(c *dbuswire.MethodCall) ([]any, error) {
		opts := optionsOf(c.Body[0])
		tok, _ := opts["session_handle_token"].Value.(string)
		handle := "/org/freedesktop/portal/desktop/session/" + portalSender(c.Sender) + "/" + tok
		_ = bus.Export(dbuswire.ObjectPath(handle), &dbuswire.Interface{Name: portalSessionIface, Methods: []dbuswire.Method{{Name: "Close", Handler: func(*dbuswire.MethodCall) ([]any, error) {
			p.record("Close")
			return nil, nil
		}}}})
		return p.request("CreateSession", c, opts, func() map[string]dbuswire.Variant {
			return map[string]dbuswire.Variant{"session_handle": dbuswire.MakeVariant(handle)}
		})
	}
	start := func(c *dbuswire.MethodCall) ([]any, error) {
		return p.request("Start", c, optionsOf(c.Body[2]), func() map[string]dbuswire.Variant {
			return map[string]dbuswire.Variant{
				"devices": dbuswire.MakeVariant(deviceKeyboard | devicePointer),
				"streams": dbuswire.NewVariant("a(ua{sv})", []any{dbuswire.Struct{uint32(44), map[string]dbuswire.Variant{
					"position": dbuswire.NewVariant("(ii)", dbuswire.Struct{int32(0), int32(0)}),
					"size":     dbuswire.NewVariant("(ii)", dbuswire.Struct{int32(1280), int32(800)}),
				}}}),
			}
		})
	}
	notify := func(name string) dbuswire.Method {
		sig := map[string]dbuswire.Signature{
			"NotifyPointerMotionAbsolute": "oa{sv}udd", "NotifyPointerButton": "oa{sv}iu",
			"NotifyPointerAxisDiscrete": "oa{sv}ui", "NotifyKeyboardKeycode": "oa{sv}iu", "NotifyKeyboardKeysym": "oa{sv}iu",
		}[name]
		return dbuswire.Method{Name: name, In: sig, Handler: func(*dbuswire.MethodCall) ([]any, error) {
			p.record(name)
			return nil, nil
		}}
	}
	u := func(v uint32) func() any { return func() any { return v } }
	if err := bus.Export(portalPath, &dbuswire.Interface{
		Name: portalScreenCast,
		Methods: []dbuswire.Method{
			{Name: "CreateSession", In: "a{sv}", Out: "o", Handler: createSession},
			{Name: "SelectSources", In: "oa{sv}", Out: "o", Handler: func(c *dbuswire.MethodCall) ([]any, error) {
				return p.request("SelectSources", c, optionsOf(c.Body[1]), none)
			}},
			{Name: "Start", In: "osa{sv}", Out: "o", Handler: start},
			{Name: "OpenPipeWireRemote", In: "oa{sv}", Out: "h", Handler: func(*dbuswire.MethodCall) ([]any, error) {
				p.record("OpenPipeWireRemote")
				return nil, &dbuswire.Error{Name: "org.freedesktop.portal.Error.NotAllowed", Message: "test"}
			}},
		},
		Properties: []dbuswire.Property{{Name: "AvailableSourceTypes", Sig: "u", Get: u(3)}, {Name: "AvailableCursorModes", Sig: "u", Get: u(7)}, {Name: "version", Sig: "u", Get: u(5)}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := bus.Export(portalPath, &dbuswire.Interface{
		Name: portalRemote,
		Methods: []dbuswire.Method{
			{Name: "CreateSession", In: "a{sv}", Out: "o", Handler: createSession},
			{Name: "SelectDevices", In: "oa{sv}", Out: "o", Handler: func(c *dbuswire.MethodCall) ([]any, error) {
				return p.request("SelectDevices", c, optionsOf(c.Body[1]), none)
			}},
			{Name: "Start", In: "osa{sv}", Out: "o", Handler: start},
			notify("NotifyPointerMotionAbsolute"), notify("NotifyPointerButton"), notify("NotifyPointerAxisDiscrete"),
			notify("NotifyKeyboardKeycode"), notify("NotifyKeyboardKeysym"),
		},
		Properties: []dbuswire.Property{{Name: "AvailableDeviceTypes", Sig: "u", Get: u(7)}, {Name: "version", Sig: "u", Get: u(2)}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := bus.RequestName(ctx, portalBus, dbuswire.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	return p
}

func privateBus(t *testing.T) string {
	t.Helper()
	if os.Getenv("OPENSCALE_DBUS_INTEROP") == "" {
		t.Skip("OPENSCALE_DBUS_INTEROP=1 ile çalışır")
	}
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon yok")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "bus")
	conf := filepath.Join(dir, "bus.conf")
	cfg := `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:path=` + sock + `</listen><auth>EXTERNAL</auth>
<policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>
`
	if err := os.WriteFile(conf, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(daemon, "--config-file="+conf, "--nofork", "--nopidfile")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+sock)
	return sock
}

func TestPortalSessionFlow(t *testing.T) {
	sock := privateBus(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := startFakePortal(t, ctx, sock, "")
	_, err := openPortalSession(ctx, true)
	// The fake portal cannot pass a PipeWire descriptor: the flow must
	// get that far, and close the session it made.
	if err == nil || !strings.Contains(err.Error(), "OpenPipeWireRemote") {
		t.Fatalf("err = %v", err)
	}
	want := "CreateSession|SelectDevices|SelectSources|Start|OpenPipeWireRemote|Close"
	deadline := time.Now().Add(3 * time.Second)
	for p.seen() != want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := p.seen(); got != want {
		t.Fatalf("calls %s", got)
	}

	// A view session never asks for input devices.
	p.mu.Lock()
	p.calls = nil
	p.mu.Unlock()
	if _, err := openPortalSession(ctx, false); err == nil {
		t.Fatal("no error")
	}
	if got := p.seen(); strings.Contains(got, "SelectDevices") || !strings.HasPrefix(got, "CreateSession|SelectSources|Start") {
		t.Fatalf("view calls %s", got)
	}
}

func TestPortalDenied(t *testing.T) {
	sock := privateBus(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	startFakePortal(t, ctx, sock, "Start")
	if _, err := openPortalSession(ctx, true); !errors.Is(err, ErrPortalDenied) {
		t.Fatalf("err = %v", err)
	}
}

// fakeFrames stands in for the PipeWire bridge: one 1280x800 stream.
type fakeFrames struct{}

func (fakeFrames) frame(_ int, buf []byte) ([]byte, image.Point, error) {
	n := 1280 * 800 * 4
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	return buf[:n], image.Pt(1280, 800), nil
}
func (fakeFrames) size(int) image.Point { return image.Pt(1280, 800) }
func (fakeFrames) close()               {}

func TestWaylandInjectorCalls(t *testing.T) {
	sock := privateBus(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := startFakePortal(t, ctx, sock, "")
	bus, err := dbuswire.Dial(ctx, dbuswire.Endpoint{Path: sock}, dbuswire.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := &portalSession{bus: bus, refs: 1, pw: fakeFrames{}, handle: "/org/freedesktop/portal/desktop/session/t/x",
		streams: []portalStream{{node: 44, size: image.Pt(1280, 800), hasPos: true}}}
	in := &waylandInjector{s: s}
	c := &waylandCapturer{s: s}
	s.retain()
	if err := in.Pointer(10, 20, ButtonLeft); err != nil {
		t.Fatal(err)
	}
	if err := in.Pointer(10, 20, 0); err != nil {
		t.Fatal(err)
	}
	if err := in.Wheel(0, 2); err != nil {
		t.Fatal(err)
	}
	if err := in.Key(0x04, true); err != nil {
		t.Fatal(err)
	}
	if err := in.Key(0xffff, true); err == nil {
		t.Fatal("unknown key sent")
	}
	if err := in.Text("ç"); err != nil {
		t.Fatal(err)
	}
	mons, _ := c.Monitors()
	if len(mons) != 1 || mons[0].Bounds != image.Rect(0, 0, 1280, 800) {
		t.Fatalf("%+v", mons)
	}
	if img, err := c.Capture(image.Rect(0, 0, 64, 64), nil); err != nil || img.Bounds().Dx() != 64 {
		t.Fatalf("capture %v", err)
	}
	want := "NotifyPointerMotionAbsolute|NotifyPointerButton|NotifyPointerMotionAbsolute|NotifyPointerButton|NotifyPointerAxisDiscrete|NotifyKeyboardKeycode|NotifyKeyboardKeysym|NotifyKeyboardKeysym"
	deadline := time.Now().Add(3 * time.Second)
	for p.seen() != want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := p.seen(); got != want {
		t.Fatalf("calls %s", got)
	}
	_ = in.Close()
	_ = c.Close()
	select {
	case <-bus.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("last Close did not end the session")
	}
}
