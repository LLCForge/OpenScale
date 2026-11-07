package desktop

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/dbuswire"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/winapp"
)

func TestDBusMenuLayout(t *testing.T) {
	now := time.Now()
	st := menuBarState{reachable: true, autostart: true, status: panel.AppStatus{Device: &panel.DeviceStatus{
		Name: "dizüstü", IPv4: "100.64.0.2", Connected: true, Running: true, LastSync: &now,
		ExitNodes: []panel.PeerInfo{{Name: "ev_sunucu", IPv4: "100.64.0.9", Online: true}},
	}}}
	exits := map[int]string{}
	items := menuBarItems(st, exits)
	m := newDBusMenu()
	rev, changed := m.set(items)
	if !changed || rev != 2 {
		t.Fatalf("rev %d changed %v", rev, changed)
	}
	if rev2, changed := m.set(menuBarItems(st, exits)); changed || rev2 != rev {
		t.Fatal("same layout bumped the revision")
	}
	r, root, err := m.layout(0, -1, nil)
	if err != nil || r != rev {
		t.Fatal(err)
	}
	// Round trip through the wire format, as a host would read it.
	if _, err := encodeForTest(root); err != nil {
		t.Fatal(err)
	}
	children := root[2].([]any)
	if len(children) != len(items) {
		t.Fatalf("%d children for %d items", len(children), len(items))
	}
	var sawToggle, sawExitSub, sawSep, sawAutostart bool
	for i, c := range children {
		n := c.(dbuswire.Variant).Value.(dbuswire.Struct)
		props := n[1].(map[string]dbuswire.Variant)
		it := items[i]
		switch {
		case it.Separator:
			sawSep = props["type"].Value == "separator"
		case it.ID == mbToggle:
			sawToggle = n[0] == int32(mbToggle) && props["label"].Value == "Bağlantıyı kes"
		case it.ID == mbAutostart:
			sawAutostart = props["toggle-type"].Value == "checkmark" && props["toggle-state"].Value == int32(1)
		case it.Label == "Çıkış düğümü":
			sawExitSub = props["children-display"].Value == "submenu" && len(n[2].([]any)) > 0 && n[0].(int32) >= dbusMenuSynthetic
			sub := n[2].([]any)
			for _, sc := range sub {
				sn := sc.(dbuswire.Variant).Value.(dbuswire.Struct)
				sp := sn[1].(map[string]dbuswire.Variant)
				if l, _ := sp["label"].Value.(string); l == "ev__sunucu · 100.64.0.9" {
					if a, ok := m.action(sn[0].(int32)); !ok || exits[a] != "ev_sunucu" {
						t.Fatalf("exit action %v %v", a, ok)
					}
				}
			}
		}
	}
	if !sawToggle || !sawExitSub || !sawSep || !sawAutostart {
		t.Fatalf("toggle %v exit %v sep %v autostart %v", sawToggle, sawExitSub, sawSep, sawAutostart)
	}
	// Depth 0: the item without children; filtered properties.
	_, top, err := m.layout(0, 0, []string{"label"})
	if err != nil || len(top[2].([]any)) != 0 {
		t.Fatalf("depth 0: %v", top)
	}
	if _, _, err := m.layout(424242, -1, nil); err == nil {
		t.Fatal("unknown parent")
	}
	gp := m.groupProperties([]int32{int32(mbToggle), 999}, []string{"label"})
	if len(gp) != 1 {
		t.Fatalf("group properties %v", gp)
	}
	if v, err := m.property(int32(mbToggle), "label"); err != nil || v.Value != "Bağlantıyı kes" {
		t.Fatalf("%v %v", v, err)
	}
	if _, ok := m.action(dbusMenuSynthetic); ok {
		t.Fatal("label item has an action")
	}
	// The layout changes when the state does.
	st.status.Device.Connected = false
	if _, changed := m.set(menuBarItems(st, exits)); !changed {
		t.Fatal("changed layout not noticed")
	}
}

func encodeForTest(root dbuswire.Struct) ([]byte, error) {
	// GetLayout's reply signature.
	return dbuswire.MarshalBody("u"+layoutSig, uint32(1), root)
}

func TestSNIPixmaps(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			if x < 32 {
				img.SetNRGBA(x, y, color.NRGBA{R: 255, A: 255})
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	pms, err := sniPixmaps(buf.Bytes(), []int{16, 22, 0, 9999})
	if err != nil {
		t.Fatal(err)
	}
	if len(pms) != 2 {
		t.Fatalf("%d pixmaps", len(pms))
	}
	px := pms[0][2].([]byte)
	if pms[0][0] != int32(16) || len(px) != 16*16*4 {
		t.Fatalf("size %v len %d", pms[0][0], len(px))
	}
	// Left pixel: opaque red in A, R, G, B order; right: transparent.
	if px[0] != 255 || px[1] != 255 || px[2] != 0 || px[3] != 0 {
		t.Fatalf("left pixel %v", px[:4])
	}
	if px[15*4] != 0 {
		t.Fatalf("right pixel %v", px[15*4:16*4])
	}
	if _, err := sniPixmaps([]byte("png değil"), sniIconSizes); err == nil {
		t.Fatal("bad png accepted")
	}
	// The real tray icons convert.
	for state, data := range makeTrayIcons(trayIconPNG) {
		if _, err := sniPixmaps(data, sniIconSizes); err != nil {
			t.Fatalf("state %d: %v", state, err)
		}
	}
}

func TestSNIHelpers(t *testing.T) {
	if sniStatus(iconError) != "NeedsAttention" || sniStatus(iconConnected) != "Active" {
		t.Fatal("status")
	}
	if a, b := trayLabelText("OpenScale - Ev: Bağlı"); a != "OpenScale - Ev" || b != "Bağlı" {
		t.Fatalf("%q %q", a, b)
	}
	if menuLabel(winapp.MenuItem{Label: "a_b", Detail: "c"}) != "a__b · c" {
		t.Fatal("label")
	}
}

func TestMenuCommandLineService(t *testing.T) {
	items := menuBarItems(menuBarState{service: serviceCommandLine}, map[int]string{})
	for _, it := range items {
		if it.ID == mbReleaseKillSwitch || it.ID == mbInstall {
			t.Fatalf("item %d offered with the command line service", it.ID)
		}
	}
	if unreachableLabel(serviceCommandLine) == unreachableLabel(serviceInstalled) {
		t.Fatal("label")
	}
}
