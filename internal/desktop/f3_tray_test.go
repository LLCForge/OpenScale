package desktop

import (
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/p2psend"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/winapp"
)

func lineText(m winapp.UIModel) string {
	var b strings.Builder
	for _, l := range m.Lines {
		b.WriteString(l.Text + "=" + l.Value + "\n")
	}
	return b.String()
}

func TestFlyoutModel(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	ms := func(v float64) *float64 { return &v }
	st := panel.AppStatus{NetworkName: "Ev", Device: &panel.DeviceStatus{Name: "laptop", IPv4: "100.64.0.2", Connected: true,
		ExitNode: "ev-sunucu", ExitNodeWanted: "ev-sunucu"},
		Health: []panel.HealthAlert{{Level: panel.LevelWarning, Message: "x"}, {Level: panel.LevelInfo, Message: "y"}}}
	diag := &panel.DiagStatus{Peers: []panel.DiagPeer{
		{Name: "eski", Online: false, Path: panel.PathNone, LastHandshake: ago(time.Hour)},
		{Name: "telefon", Online: true, Path: panel.PathRelay, LastHandshake: ago(time.Second)},
		{Name: "nas", Online: true, Path: panel.PathDirect, LastHandshake: ago(time.Minute), LatencyMS: ms(12.4)},
		{Name: "hiç", Online: false},
		{Name: "a", Online: true, Path: panel.PathDirect, LastHandshake: ago(2 * time.Minute)},
		{Name: "b", Online: true, Path: panel.PathDirect, LastHandshake: ago(3 * time.Minute)},
		{Name: "c", Online: true, Path: panel.PathDirect, LastHandshake: ago(4 * time.Minute)},
	}}
	for _, tr := range []bool{true, false} {
		m := flyoutModel(flyoutData{st: st, ok: true, diag: diag, offers: 2}, tr)
		txt := lineText(m)
		if !strings.Contains(txt, "ev-sunucu") || !strings.Contains(txt, "100.64.0.2") {
			t.Fatalf("exit or address missing:\n%s", txt)
		}
		// The five latest handshakes, newest first; never-seen peers left out.
		order := []string{"telefon", "nas", "a", "b", "c"}
		last := -1
		for _, name := range order {
			i := strings.Index(txt, "\n"+name+"=")
			if i < 0 || i < last {
				t.Fatalf("peer %q missing or out of order:\n%s", name, txt)
			}
			last = i
		}
		if strings.Contains(txt, "eski=") || strings.Contains(txt, "hiç=") {
			t.Fatalf("old peers listed:\n%s", txt)
		}
		if !strings.Contains(txt, "12 ms") {
			t.Fatalf("latency missing:\n%s", txt)
		}
		want := map[bool][]string{true: {"Bağlı", "Sunucu üzerinden", "Bekleyen uyarılar=1", "Paneli aç"}, false: {"Connected", "Relayed", "Open alerts=1", "Open panel"}}[tr]
		all := txt + m.Buttons[0].Label + m.Buttons[1].Label
		for _, w := range want {
			if !strings.Contains(all, w) {
				t.Fatalf("tr=%v: %q missing:\n%s", tr, w, all)
			}
		}
	}
	if m := flyoutModel(flyoutData{ok: false}, false); !strings.Contains(lineText(m), "cannot be reached") {
		t.Fatalf("unreachable: %s", lineText(m))
	}
	// Without diagnostics the online peers of the tray status are used.
	st.Device.Peers = []panel.PeerInfo{{Name: "x", Online: true, Relayed: true}, {Name: "y", Online: false}}
	if txt := lineText(flyoutModel(flyoutData{st: st, ok: true}, false)); !strings.Contains(txt, "x=Relayed") || strings.Contains(txt, "y=") {
		t.Fatalf("fallback peers:\n%s", txt)
	}
}

func TestOfferNoticeHidesNameWhenLocked(t *testing.T) {
	o := p2psend.Offer{ID: "1", From: "telefon", Name: "maaş-bordrosu.pdf", Size: 1536}
	for _, tr := range []bool{true, false} {
		_, msg := offerNotice(o, true, tr)
		if strings.Contains(msg, "maaş") || strings.Contains(msg, ".pdf") || !strings.Contains(msg, "telefon") {
			t.Fatalf("locked notice shows the file: %q", msg)
		}
		_, msg = offerNotice(o, false, tr)
		if !strings.Contains(msg, "maaş-bordrosu.pdf") {
			t.Fatalf("unlocked notice lacks the name: %q", msg)
		}
	}
	tv := p2psend.TransferView{Name: "maaş.pdf", State: p2psend.StateDone, Peer: "telefon"}
	if msg, ok := transferNotice(tv, true, true); !ok || strings.Contains(msg, "maaş") {
		t.Fatalf("locked transfer notice: %q", msg)
	}
}

func TestOfferAndProgressModels(t *testing.T) {
	at := time.Now()
	o := p2psend.Offer{ID: "1", From: "telefon", Name: "kur.exe", Size: 1000, Executable: true, At: at}
	m := offerModel(o, false, true)
	if len(m.Buttons) != 2 || m.Buttons[1].ID != btnAccept || !m.Buttons[1].Primary || m.Buttons[0].ID != btnReject {
		t.Fatalf("buttons %+v", m.Buttons)
	}
	if !strings.Contains(lineText(m), "kod çalıştırabilir") {
		t.Fatal("executable warning missing")
	}
	if g := offerModel(o, true, false); len(g.Buttons) != 1 || g.Buttons[0].ID != btnClose {
		t.Fatalf("gone offer buttons %+v", g.Buttons)
	}
	list := []p2psend.TransferView{
		{Outgoing: true, Peer: "telefon", Name: "kur.exe", Started: at},
		{Peer: "telefon", Name: "kur.exe", Started: at.Add(time.Second), Done: 250, Size: 1000, State: p2psend.StateReceiving},
	}
	tv, ok := findIncoming(list, o)
	if !ok || tv.Outgoing || tv.Done != 250 {
		t.Fatalf("findIncoming = %+v %v", tv, ok)
	}
	p := progressModel(o, tv, true, false)
	if p.Progress < 0.24 || p.Progress > 0.26 {
		t.Fatalf("progress %v", p.Progress)
	}
	tv.State = p2psend.StateDone
	if p := progressModel(o, tv, true, false); p.Progress != 1 || !strings.Contains(lineText(p), "quarantine") {
		t.Fatalf("done: %+v", p)
	}
}

func TestPickerModel(t *testing.T) {
	st := panel.AppStatus{Device: &panel.DeviceStatus{Name: "laptop", Peers: []panel.PeerInfo{
		{Name: "nas", Online: true}, {Name: "kapalı", Online: false}, {Name: "laptop", Online: true}, {Name: "telefon", Online: true}}}}
	peers := sendTargets(st)
	if strings.Join(peers, ",") != "nas,telefon" {
		t.Fatalf("targets %v", peers)
	}
	m := pickerModel([]sendFile{{Name: "a.txt", Size: 10}, {Name: "b.txt", Size: 20}}, peers, true)
	if m.Selected != 0 || len(m.List) != 2 || !strings.Contains(lineText(m), "2 dosya") {
		t.Fatalf("picker %+v", m)
	}
	if e := pickerModel([]sendFile{{Name: "a"}}, nil, false); e.Selected != -1 || len(e.Buttons) != 1 {
		t.Fatalf("empty picker %+v", e)
	}
	if formatSize(1536, true) != "1,5 KB" || formatSize(1536, false) != "1.5 KB" || formatSize(12, false) != "12 B" {
		t.Fatalf("formatSize: %q %q", formatSize(1536, true), formatSize(1536, false))
	}
}
