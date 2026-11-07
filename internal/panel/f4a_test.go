package panel

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/fwtemplate"
	"github.com/openscale/openscale/internal/trust"
)

// End-to-end over 127.0.0.1 (ADR-0232): icon, group range, IoT template
// over a routed camera range and the support rule, each signed through the
// panel's dry run and passphrase.

type liveClient struct {
	t      *testing.T
	base   string
	host   string
	cookie *http.Cookie
	csrf   string
}

func startLive(t *testing.T, srv *Server) *liveClient {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.host = ln.Addr().String()
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	c := &liveClient{t: t, base: "http://" + srv.host, host: srv.host}
	resp := c.raw(http.MethodPost, "/api/login", map[string]string{"passphrase": testPass})
	if resp.StatusCode != http.StatusOK || len(resp.Cookies()) == 0 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	c.cookie = resp.Cookies()[0]
	var sess struct{ CSRFToken string }
	c.json(http.MethodGet, "/api/session", nil, &sess)
	c.csrf = sess.CSRFToken
	return c
}

func (c *liveClient) raw(method, path string, body any) *http.Response {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, err := http.NewRequest(method, c.base+path, &buf)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Origin", "http://"+c.host)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

func (c *liveClient) json(method, path string, body, out any) int {
	c.t.Helper()
	resp := c.raw(method, path, body)
	defer resp.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(b.Bytes(), out); err != nil {
			c.t.Fatalf("%s %s: %v: %s", method, path, err, b.String())
		}
	}
	if resp.StatusCode != http.StatusOK {
		c.t.Logf("%s %s: %d %s", method, path, resp.StatusCode, b.String())
	}
	return resp.StatusCode
}

// sign runs the dry run, checks it, then signs.
func (c *liveClient) sign(path string, body map[string]any, want string) changeResponse {
	c.t.Helper()
	body["dryRun"] = true
	var dry changeResponse
	if code := c.json(http.MethodPost, path, body, &dry); code != http.StatusOK {
		c.t.Fatalf("%s dry run: %d", path, code)
	}
	if want != "" && !strings.Contains(strings.Join(dry.Lines, "\n"), want) {
		c.t.Fatalf("%s: diff lacks %q: %v", path, want, dry.Lines)
	}
	body["dryRun"], body["passphrase"] = false, testPass
	var done changeResponse
	if code := c.json(http.MethodPost, path, body, &done); code != http.StatusOK {
		c.t.Fatalf("%s sign: %d", path, code)
	}
	return done
}

func TestF4APanelLive(t *testing.T) {
	srv := newTestServer(t)
	devs := addTestDevices(t, srv, []string{"laptop", "ha", "nvr"}, nil)
	n := srv.network()
	plan, err := n.Prepare(time.Now(), trust.DefaultValidity, func(doc *trust.Document) error {
		return doc.SetDeviceRoutes("nvr", []netip.Prefix{netip.MustParsePrefix("192.168.60.0/24")})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	c := startLive(t, srv)

	// #233: icon, with the minimum client version raised in the same diff.
	c.sign("/api/devices/icon", map[string]any{"name": "nvr", "icon": "camera"}, "simge - -> camera")
	doc, _ := n.Document()
	if d, _ := doc.DeviceByName("nvr"); d.Icon != trust.IconCamera || doc.MinClientVersion != trust.SchemaV2MinClientVersion {
		t.Fatalf("icon %q, min %q", d.Icon, doc.MinClientVersion)
	}
	var list struct {
		Devices []deviceView `json:"devices"`
	}
	if code := c.json(http.MethodGet, "/api/devices", nil, &list); code != http.StatusOK {
		t.Fatal(code)
	}
	found := false
	for _, d := range list.Devices {
		found = found || (d.Name == "nvr" && d.Icon == "camera")
	}
	if !found {
		t.Fatal("the device list must carry the icon")
	}
	if code := c.json(http.MethodPost, "/api/devices/icon", map[string]any{"name": "nvr", "icon": "toaster", "dryRun": true}, nil); code != http.StatusBadRequest {
		t.Fatalf("unknown icon: %d", code)
	}

	// #277: a bare IP becomes a /32 group member.
	c.sign("/api/groups", map[string]any{"name": "yonetim", "members": []string{devs["laptop"].IPv4.String()}}, "")
	doc, _ = n.Document()
	if g, _ := doc.GroupByName("yonetim"); len(g.Members) != 1 || g.Members[0] != devs["laptop"].IPv4.String()+"/32" {
		t.Fatalf("group: %+v", g)
	}

	// #243: cameras behind nvr's route reach only ha.
	req := map[string]any{"kind": string(fwtemplate.IoTIsolation), "subject": "192.168.60.0/26", "targets": []string{"ha"}, "ports": []string{"8123"}, "isolate": true}
	var preview fwtemplate.Plan
	if code := c.json(http.MethodPost, "/api/fwtemplate/preview", req, &preview); code != http.StatusOK {
		t.Fatal(code)
	}
	if len(preview.Added) != 2 || preview.Base == "" || len(preview.Warnings) == 0 {
		t.Fatalf("preview: %+v", preview)
	}
	req["base"] = preview.Base
	c.sign("/api/fwtemplate/apply", req, "192.168.60.0/26")
	doc, _ = n.Document()
	cam := trust.AddrEnd(netip.MustParseAddr("192.168.60.9"))
	if !doc.AllowsRoutedPacketAt(cam, trust.DeviceEnd("ha"), trust.PacketQuery{Proto: 6, Port: 8123, ICMPType: -1}) ||
		doc.AllowsRoutedPacketAt(cam, trust.DeviceEnd("laptop"), trust.PacketQuery{Proto: 6, Port: 8123, ICMPType: -1}) {
		t.Fatal("template not applied as previewed")
	}
	req["base"] = "stale"
	req["dryRun"] = true
	if code := c.json(http.MethodPost, "/api/fwtemplate/apply", req, nil); code == http.StatusOK {
		t.Fatal("a stale preview must be refused")
	}

	// #852: the support rule, read only and then with support.kill.
	c.sign("/api/support/rule", map[string]any{"from": "laptop", "to": "nvr"}, "salt okunur")
	var st supportRuleState
	c.json(http.MethodGet, "/api/support/rule?from=laptop&to=nvr", nil, &st)
	if !st.Read || st.Kill {
		t.Fatalf("support state: %+v", st)
	}
	c.sign("/api/support/rule", map[string]any{"from": "laptop", "to": "nvr", "allowKill": true}, "support.kill")
	c.json(http.MethodGet, "/api/support/rule?from=laptop&to=nvr", nil, &st)
	if !st.Kill {
		t.Fatal("support.kill")
	}
	// Without the desktop service the toolbox is not offered.
	if code := c.json(http.MethodGet, "/api/app/support/local", nil, nil); code != http.StatusNotFound {
		t.Fatalf("toolbox without app: %d", code)
	}
}
