package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/p2psend"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// panelClient signs in to a running service's panel the way the tray does
// (app token, one-time ticket, session cookie) and keeps the CSRF token.
type panelClient struct {
	t      *testing.T
	base   string
	cookie []*http.Cookie
	csrf   string
	hc     *http.Client
}

func newPanelClient(t *testing.T, r *Runtime) *panelClient {
	t.Helper()
	base := "http://127.0.0.1:" + strconv.Itoa(r.cfg.PanelPort)
	hc := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	token, err := ReadToken(r.cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, base+"/api/app/ticket", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var tk struct{ Ticket string }
	_ = json.NewDecoder(res.Body).Decode(&tk)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || tk.Ticket == "" {
		t.Fatalf("ticket: %d", res.StatusCode)
	}
	res, err = hc.Get(base + "/auth/ticket?t=" + url.QueryEscape(tk.Ticket))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	c := &panelClient{t: t, base: base, cookie: res.Cookies(), hc: hc}
	if len(c.cookie) == 0 {
		t.Fatalf("ticket sign-in gave no session: %d", res.StatusCode)
	}
	var sess struct {
		CSRFToken string `json:"csrfToken"`
	}
	if code := c.getJSON("/api/session", &sess); code != http.StatusOK || sess.CSRFToken == "" {
		t.Fatalf("session: %d", code)
	}
	c.csrf = sess.CSRFToken
	return c
}

func (c *panelClient) do(method, path string, body io.Reader, hdr map[string]string) (int, []byte) {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	for _, ck := range c.cookie {
		req.AddCookie(ck)
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", c.base)
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, b
}

func (c *panelClient) getJSON(path string, v any) int {
	c.t.Helper()
	code, b := c.do(http.MethodGet, path, nil, nil)
	if code == http.StatusOK && v != nil {
		if err := json.Unmarshal(b, v); err != nil {
			c.t.Fatalf("%s: %v %s", path, err, b)
		}
	}
	return code
}

func (c *panelClient) postJSON(path string, in any) (int, []byte) {
	c.t.Helper()
	b, _ := json.Marshal(in)
	return c.do(http.MethodPost, path, bytes.NewReader(b), map[string]string{"Content-Type": "application/json"})
}

// TestW5PagesWithRealApp: the endpoints behind /files, /files/quarantine,
// /security and /security/opsec answer from the real desktop service (not
// a test double) with the fields the pages read, on loopback only.
func TestW5PagesWithRealApp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newRuntime(t, ctx, t.TempDir(), "masa")
	c := newPanelClient(t, r)

	pages := []struct {
		path string
		keys []string
	}{
		{"/api/app/e2e", []string{"transfers", "pending", "relay"}},                       // /files
		{"/api/app/e2e/quarantine", []string{"files"}},                                    // /files/quarantine
		{"/api/app/posture/extended", []string{"grade", "disk_encryption", "disclaimer"}}, // /security
		{"/api/app/tpm", []string{"present", "sealed", "supported", "note"}},              // /security
		{"/api/app/tamper", []string{"events"}},                                           // /security
	}
	for _, p := range pages {
		var m map[string]json.RawMessage
		if code := c.getJSON(p.path, &m); code != http.StatusOK {
			t.Errorf("%s: status %d", p.path, code)
			continue
		}
		for _, k := range p.keys {
			if _, ok := m[k]; !ok {
				t.Errorf("%s: field %q missing", p.path, k)
			}
		}
	}
	// /security/opsec: without a tunnel the service has no engine to read;
	// the page shows this 503 as a neutral "connect first" note.
	if code, body := c.do(http.MethodGet, "/api/app/opsec", nil, nil); code != http.StatusServiceUnavailable || !strings.Contains(string(body), "alınamadı") {
		t.Fatalf("opsec without tunnel: %d %s", code, body)
	}
	// Without a tunnel a send is refused with a Turkish reason, not a
	// missing endpoint.
	code, body := c.postJSON("/api/app/e2e/send", p2psend.SendRequest{Device: "nas", Path: filepath.Join(t.TempDir(), "x.txt")})
	if code == http.StatusNotFound || code == http.StatusNotImplemented || code < 400 {
		t.Fatalf("send without tunnel: %d %s", code, body)
	}
	// Writes need the CSRF token.
	req, _ := http.NewRequest(http.MethodPost, c.base+"/api/app/e2e/upload", strings.NewReader("x"))
	for _, ck := range c.cookie {
		req.AddCookie(ck)
	}
	req.Header.Set("Origin", c.base)
	req.Header.Set(panel.E2EFileNameHeader, "a.txt")
	res, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("upload without csrf: %d", res.StatusCode)
	}
}

// TestW5DropSendQuarantineFlow is the whole LocalSend-like path through
// the real service and panel: a file dropped on /files is staged, sent
// end to end with its metadata removed (#658), offered to the receiver,
// accepted, received into the marked quarantine (#659) with progress
// visible in the panel, and released into the inbox. The receiver listens
// on 127.0.0.1; the sender resolves the receiver from the signed document
// and only the address is redirected to loopback.
func TestW5DropSendQuarantineFlow(t *testing.T) {
	if p2psend.DefaultPort != trust.FilesE2EPort {
		t.Fatalf("p2psend port %d, trust port %d", p2psend.DefaultPort, trust.FilesE2EPort)
	}
	stores, secrets := wireNet(t)
	doc := stores["b"].Document()
	if !doc.Allows("a", "b", trust.ProtocolTCP, trust.FilesE2EPort) || doc.Allows("b", "a", trust.ProtocolTCP, trust.FilesE2EPort) {
		t.Fatal("files rule a->b must open 4054 one way")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rb := newIdleRuntime(t)
	rb.wire.listenOverride = netip.MustParseAddrPort("127.0.0.1:0")
	rb.wire.tamperPaths = []string{filepath.Join(t.TempDir(), "yok")}
	selfB, _ := stores["b"].Document().DeviceByName("b")
	rb.startWire(ctx, stores["b"], secrets["b"], selfB)
	rb.wire.mu.Lock()
	listen := rb.wire.listen
	rb.wire.mu.Unlock()
	if !listen.IsValid() {
		t.Fatal("receiver not listening")
	}

	ra := newRuntime(t, ctx, t.TempDir(), "a")
	ra.wire.tamperPaths = []string{filepath.Join(t.TempDir(), "yok")}
	selfA, _ := stores["a"].Document().DeviceByName("a")
	ra.startWire(ctx, stores["a"], secrets["a"], selfA)
	svc, err := ra.e2eService()
	if err != nil {
		t.Fatal(err)
	}
	orig := svc.Resolve
	svc.Resolve = func(name string) (p2psend.Peer, bool) {
		p, ok := orig(name)
		if ok {
			p.Addr = listen.Addr()
		}
		return p, ok
	}
	svc.Port = listen.Port()

	c := newPanelClient(t, ra)
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /Title (Rapor) /Author (Ayse Yilmaz) /Producer (PDFlib) >>\nendobj\n%%EOF\n")
	name := "rapor ğüş.pdf"
	code, body := c.do(http.MethodPost, "/api/app/e2e/upload", bytes.NewReader(pdf),
		map[string]string{panel.E2EFileNameHeader: url.PathEscape(name), "Content-Type": "application/octet-stream"})
	if code != http.StatusOK {
		t.Fatalf("upload: %d %s", code, body)
	}
	var staged panel.E2EStaged
	if err := json.Unmarshal(body, &staged); err != nil || staged.Name != name || filepath.Base(staged.Path) != name {
		t.Fatalf("staged: %s", body)
	}
	if !strings.HasPrefix(staged.Path, ra.path(e2eDirName, e2eStageDir)) {
		t.Fatalf("staged outside the private folder: %s", staged.Path)
	}
	// Unsafe names never reach the disk.
	if code, _ := c.do(http.MethodPost, "/api/app/e2e/upload", strings.NewReader("x"),
		map[string]string{panel.E2EFileNameHeader: url.PathEscape("..\\..\\x.exe")}); code != http.StatusBadRequest {
		t.Fatalf("traversal name: %d", code)
	}

	if code, body := c.postJSON("/api/app/e2e/send", p2psend.SendRequest{Device: "b", Path: staged.Path}); code/100 != 2 {
		t.Fatalf("send: %d %s", code, body)
	}
	waitFor(t, "offer at the receiver", 10*time.Second, func() bool { return len(rb.E2EPending()) > 0 })
	offer := rb.E2EPending()[0]
	if offer.From != "a" || offer.Name != name || !offer.Stripped {
		t.Fatalf("offer: %+v", offer)
	}
	// The sender's panel shows the transfer waiting for approval.
	var st panel.E2EStatus
	if c.getJSON("/api/app/e2e", &st); len(st.Transfers) != 1 || st.Transfers[0].State != p2psend.StateWaiting {
		t.Fatalf("sender view before approval: %+v", st.Transfers)
	}
	if err := rb.E2EDecide(offer.ID, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "transfer done in the panel", 10*time.Second, func() bool {
		var s panel.E2EStatus
		c.getJSON("/api/app/e2e", &s)
		return len(s.Transfers) == 1 && s.Transfers[0].State == p2psend.StateDone && s.Transfers[0].Done == s.Transfers[0].Size
	})

	files, err := rb.E2EQuarantine().List()
	if err != nil || len(files) != 1 || files[0].Name != name {
		t.Fatalf("quarantine: %+v %v", files, err)
	}
	if runtime.GOOS == "windows" && !files[0].Marked {
		t.Fatal("received file has no Mark-of-the-Web")
	}
	got, err := os.ReadFile(filepath.Join(rb.E2EQuarantine().Dir, name))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"Yilmaz", "PDFlib"} {
		if bytes.Contains(got, []byte(leak)) {
			t.Fatalf("metadata %q reached the receiver", leak)
		}
	}
	if !bytes.Contains(got, []byte("(Rapor)")) {
		t.Fatal("document content was damaged")
	}
	dst, err := rb.E2EQuarantine().Release(name)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" && !filesend.IsQuarantined(dst) {
		t.Fatal("mark lost when released to the inbox")
	}
}
