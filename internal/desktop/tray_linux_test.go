//go:build linux

package desktop

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/dbuswire"
	"github.com/openscale/openscale/internal/panel"
)

// TestTrayOnRealBus exports the StatusNotifierItem and the dbusmenu on a
// private dbus-daemon and reads them the way a tray host does
// (OPENSCALE_DBUS_INTEROP=1; needs dbus-daemon). The service is a fake
// HTTP server; nothing outside the test folder is touched.
func TestTrayOnRealBus(t *testing.T) {
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

	var mu sync.Mutex
	var connects []bool
	now := time.Now()
	status := panel.AppStatus{Device: &panel.DeviceStatus{Name: "dizüstü", IPv4: "100.64.0.2", Connected: true, Running: true, LastSync: &now}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/app/tray":
			_ = json.NewEncoder(w).Encode(status)
		case "/api/app/tray/connect":
			var body map[string]bool
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			connects = append(connects, body["connected"])
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(status)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bus, err := dbuswire.Dial(ctx, dbuswire.Endpoint{Path: sock}, dbuswire.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	client := newTrayClient(dir)
	client.base, client.gateway = srv.URL, true
	tr := &linuxTray{
		app: &linuxApp{client: client, settingDir: filepath.Join(dir, "cfg")},
		ctx: ctx, cancel: cancel, bus: bus, menu: newDBusMenu(), notes: newDesktopNotifier(bus),
		exits: map[int]string{}, shownIcon: -1, icons: map[trayIconState][]dbuswire.Struct{},
	}
	for state, png := range makeTrayIcons(trayIconPNG) {
		pm, err := sniPixmaps(png, sniIconSizes)
		if err != nil {
			t.Fatal(err)
		}
		tr.icons[state] = pm
	}
	if err := tr.export(); err != nil {
		t.Fatal(err)
	}
	host, err := dbuswire.Dial(ctx, dbuswire.Endpoint{Path: sock}, dbuswire.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	sub, err := host.Subscribe(ctx, dbuswire.Match{Path: menuPath, Interface: menuIface, Member: "LayoutUpdated"}, 4)
	if err != nil {
		t.Fatal(err)
	}
	tr.refresh()
	select {
	case <-sub.C:
	case <-time.After(5 * time.Second):
		t.Fatal("LayoutUpdated gelmedi")
	}

	m, err := host.Call(ctx, tr.name, sniPath, dbuswire.PropertiesInterface, "GetAll", "s", sniIface)
	if err != nil {
		t.Fatal(err)
	}
	props := map[string]any{}
	for _, e := range m.Body[0].([]dbuswire.DictEntry) {
		props[e.Key.(string)] = e.Value.(dbuswire.Variant).Value
	}
	if props["Id"] != "openscale" || props["Menu"] != menuPath || props["Status"] != "Active" || props["ItemIsMenu"] != false {
		t.Fatalf("SNI özellikleri: %v", props)
	}
	if pm := props["IconPixmap"].([]any); len(pm) != len(sniIconSizes) {
		t.Fatalf("%d pixmap", len(pm))
	}
	if tip := props["ToolTip"].(dbuswire.Struct); tip[3] != "Bağlı" {
		t.Fatalf("tooltip %v", tip)
	}

	m, err = host.Call(ctx, tr.name, menuPath, menuIface, "GetLayout", "iias", int32(0), int32(-1), []string{})
	if err != nil {
		t.Fatal(err)
	}
	root := m.Body[1].(dbuswire.Struct)
	var toggle int32 = -1
	for _, c := range root[2].([]any) {
		n := c.(dbuswire.Variant).Value.(dbuswire.Struct)
		p := n[1].([]dbuswire.DictEntry)
		for _, e := range p {
			if e.Key == "label" && e.Value.(dbuswire.Variant).Value == "Bağlantıyı kes" {
				toggle = n[0].(int32)
			}
		}
	}
	if toggle != mbToggle {
		t.Fatalf("toggle item %d", toggle)
	}
	if _, err := host.Call(ctx, tr.name, menuPath, menuIface, "Event", "isvu", toggle, "clicked", dbuswire.MakeVariant(int32(0)), uint32(0)); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Call(ctx, tr.name, menuPath, menuIface, "Event", "isvu", int32(424242), "clicked", dbuswire.MakeVariant(int32(0)), uint32(0)); err == nil {
		t.Fatal("bilinmeyen öğe kabul edildi")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(connects)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(connects) != 1 || connects[0] != false {
		t.Fatalf("bağlantı isteği %v", connects)
	}
	m, err = host.Call(ctx, tr.name, menuPath, dbuswire.IntrospectableInterface, "Introspect", "")
	if err != nil || !strings.Contains(m.Body[0].(string), `<method name="GetLayout">`) {
		t.Fatalf("introspection %v", err)
	}
}
