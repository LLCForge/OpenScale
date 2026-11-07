package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/rdesk"
	"golang.org/x/net/websocket"
)

type w1Screen struct{}

func (w1Screen) Monitors() ([]rdesk.Monitor, error) {
	return []rdesk.Monitor{{Bounds: image.Rect(0, 0, 64, 48), Primary: true}}, nil
}

func (w1Screen) Capture(r image.Rectangle, dst *image.RGBA) (*image.RGBA, error) {
	if dst == nil || dst.Rect != r {
		dst = image.NewRGBA(r)
	}
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			dst.Set(x, y, color.RGBA{R: 200, G: 40, B: 40, A: 255})
		}
	}
	return dst, nil
}

func (w1Screen) Close() error { return nil }

type w1Input struct {
	mu   sync.Mutex
	ptrs []image.Point
	keys []uint16
}

func (i *w1Input) Pointer(x, y int, _ uint8) error {
	i.mu.Lock()
	i.ptrs = append(i.ptrs, image.Pt(x, y))
	i.mu.Unlock()
	return nil
}
func (i *w1Input) Wheel(int, int) error { return nil }
func (i *w1Input) Key(u uint16, down bool) error {
	if down {
		i.mu.Lock()
		i.keys = append(i.keys, u)
		i.mu.Unlock()
	}
	return nil
}
func (i *w1Input) Text(string) error { return nil }
func (i *w1Input) Close() error      { return nil }

func (i *w1Input) seen() (int, int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.ptrs), len(i.keys)
}

// startW1Target runs an rdesk server on 127.0.0.1 that asks for an
// operating system account (ADR-0198) and grants control.
func startW1Target(t *testing.T, inj *w1Input) netip.AddrPort {
	t.Helper()
	cfg := rdesk.Config{
		ListenAddr: netip.MustParseAddrPort("127.0.0.1:1"),
		Authorize: func(remote netip.Addr, _ rdesk.Mode) rdesk.Decision {
			return rdesk.Decision{Allowed: remote.IsLoopback(), Unattended: true, Peer: "dizustu"}
		},
		Indicator:    func(rdesk.SessionEvent) {},
		NewCapturer:  func() (rdesk.Capturer, error) { return w1Screen{}, nil },
		NewInjector:  func() (rdesk.Injector, error) { return inj, nil },
		NewClipboard: func() (rdesk.Clipboard, error) { return nil, rdesk.ErrUnsupported },
		MaxFPS:       30,
		OSLogin: &rdesk.OSLoginConfig{Hint: "Windows hesabı", Verifier: rdesk.OSVerifierFunc(func(_ context.Context, user string, pw []byte) error {
			if user == "ayse" && string(pw) == "windows-parolasi" {
				return nil
			}
			return rdesk.ErrOSLoginFailed
		})},
	}
	srv, err := rdesk.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func TestRDeskViewerFromPanel(t *testing.T) {
	inj := &w1Input{}
	target := startW1Target(t, inj)
	srv := g5Server(t, nil)
	srv.SetRDeskTarget(func(name string) (netip.AddrPort, bool) { return target, name == "dizustu" })
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	srv.host = host
	post := func(path string, body any, c *http.Cookie, csrf string) (*http.Response, map[string]any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Host = host
		req.Header.Set("Origin", "http://"+host)
		if c != nil {
			req.AddCookie(c)
			req.Header.Set("X-CSRF-Token", csrf)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp, out
	}
	resp, _ := post("/api/login", map[string]string{"passphrase": testPass}, nil, "")
	c := resp.Cookies()[0]
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/session", nil)
	req.AddCookie(c)
	resp, _ = http.DefaultClient.Do(req)
	var sess struct{ CSRFToken string }
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	connect := func(body map[string]any) (int, map[string]any) {
		resp, out := post("/api/app/rdesk/connect", body, c, sess.CSRFToken)
		return resp.StatusCode, out
	}

	// Without CSRF the request is refused before dialing.
	if resp, _ := post("/api/app/rdesk/connect", map[string]any{"device": "dizustu", "mode": "control"}, c, "yanlis"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("connect without CSRF: %d", resp.StatusCode)
	}
	// Unknown channel names and unknown devices are refused.
	if code, _ := connect(map[string]any{"device": "dizustu", "mode": "control", "channels": []string{"root"}}); code != http.StatusBadRequest {
		t.Fatalf("unknown channel: %d", code)
	}
	if code, _ := connect(map[string]any{"device": "yok", "mode": "control"}); code != http.StatusNotFound {
		t.Fatalf("unknown device: %d", code)
	}
	// The target asks for an account: none, then a wrong one.
	if code, out := connect(map[string]any{"device": "dizustu", "mode": "control"}); code != http.StatusUnauthorized || out["code"] != "os_login_required" {
		t.Fatalf("no account: %d %v", code, out)
	}
	if code, out := connect(map[string]any{"device": "dizustu", "mode": "control", "user": "ayse", "password": []byte("yanlis")}); code != http.StatusUnauthorized || out["code"] != "os_login_failed" {
		t.Fatalf("wrong password: %d %v", code, out)
	}
	code, out := connect(map[string]any{"device": "dizustu", "mode": "control", "channels": []string{"video", "input"},
		"user": "ayse", "password": []byte("windows-parolasi")})
	if code != http.StatusOK || out["session"] == nil || !strings.HasPrefix(out["viewer"].(string), rdeskViewerPrefix) {
		t.Fatalf("connect: %d %v", code, out)
	}
	ticket := out["session"].(string)

	dialWS := func(ticket, origin string) (*websocket.Conn, error) {
		cfg, _ := websocket.NewConfig("ws://"+host+"/api/rdesk/ws?ticket="+ticket, origin)
		cfg.Header = http.Header{"Cookie": {c.Name + "=" + c.Value}}
		return websocket.DialConfig(cfg)
	}
	if ws, err := dialWS(ticket, "http://evil.example"); err == nil {
		ws.Close()
		t.Fatal("cross-origin viewer accepted")
	}
	ws, err := dialWS(ticket, "http://"+host)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if ws2, err := dialWS(ticket, "http://"+host); err == nil {
		ws2.Close()
		t.Fatal("viewer ticket used twice")
	}
	_ = ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	var text string
	var ready rdeskMessage
	if err := websocket.Message.Receive(ws, &text); err != nil || json.Unmarshal([]byte(text), &ready) != nil || ready.Type != "ready" || !ready.Input || ready.Mode != "control" {
		t.Fatalf("ready: %v %q", err, text)
	}
	var frame []byte
	if err := websocket.Message.Receive(ws, &frame); err != nil {
		t.Fatal(err)
	}
	img, err := jpeg.Decode(bytes.NewReader(frame))
	if err != nil || img.Bounds().Dx() == 0 {
		t.Fatalf("frame: %v", err)
	}
	for _, m := range []rdeskMessage{{Type: "pointer", X: 10, Y: 12}, {Type: "key", Code: "KeyA", Down: true}, {Type: "key", Code: "KeyA"}} {
		b, _ := json.Marshal(m)
		if err := websocket.Message.Send(ws, string(b)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		p, k := inj.seen()
		if p > 0 && k > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("input did not reach the target: pointer %d key %d", p, k)
		}
		time.Sleep(20 * time.Millisecond)
	}
	inj.mu.Lock()
	if inj.keys[0] != 0x04 {
		t.Fatalf("key usage %#x", inj.keys[0])
	}
	inj.mu.Unlock()
}

func TestRDeskViewOnlySendsNoInput(t *testing.T) {
	inj := &w1Input{}
	target := startW1Target(t, inj)
	srv := g5Server(t, nil)
	srv.SetRDeskTarget(func(string) (netip.AddrPort, bool) { return target, true })
	// The waiting session is bound to the panel session that opened it.
	srv.w1.viewers = map[string]*rdeskViewer{}
	cli, err := rdesk.Dial(context.Background(), target, rdesk.DialOptions{Mode: rdesk.ModeView, Credentials: func(context.Context, rdesk.LoginRequest) (rdesk.LoginCredentials, error) {
		return rdesk.LoginCredentials{User: "ayse", Password: []byte("windows-parolasi")}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv.w1.viewers["bilet"] = &rdeskViewer{sessionID: "a", client: cli, mode: rdesk.ModeView, until: time.Now().Add(time.Minute)}
	if srv.takeRDeskViewer("bilet", "b") != nil {
		t.Fatal("another panel session took the viewer")
	}
	v := srv.takeRDeskViewer("bilet", "a")
	if v == nil || v.input {
		t.Fatal("view session")
	}
	_ = v.client.Close()
}

func TestHIDUsage(t *testing.T) {
	for code, want := range map[string]uint16{"KeyA": 0x04, "KeyZ": 0x1D, "Digit1": 0x1E, "Digit0": 0x27, "F1": 0x3A, "F12": 0x45,
		"Numpad0": 0x62, "Numpad9": 0x61, "Enter": 0x28, "ArrowUp": 0x52, "MetaRight": 0xE7} {
		if got, ok := hidUsage(code); !ok || got != want {
			t.Errorf("%s = %#x %v", code, got, ok)
		}
	}
	for _, code := range []string{"", "F13", "Fx", "Key", "Keya", "Unidentified"} {
		if _, ok := hidUsage(code); ok {
			t.Errorf("%q mapped", code)
		}
	}
}
