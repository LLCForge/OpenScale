//go:build windows

package desktop

import (
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/winapp"
)

func TestTrayMenuLayout(t *testing.T) {
	now := time.Now()
	st := panel.AppStatus{Mode: panel.ModeAdmin, Device: &panel.DeviceStatus{
		Name: "ali", IPv4: "100.80.0.2", Running: true, Connected: true, LastSync: &now,
		Peers:     []panel.PeerInfo{{Name: "laptop", IPv4: "100.80.0.3", Online: true}, {Name: "nas", IPv4: "100.80.0.4"}},
		ExitNodes: []panel.PeerInfo{{Name: "vps", IPv4: "100.80.0.9"}},
	}}
	copies, choices := map[int]string{}, map[int]string{}
	items, tip := buildTrayMenu(st, true, copies, choices)
	if items[0].ID != idToggle || !items[0].Checked || !items[0].Default || items[0].Detail != "Bağlı" {
		t.Fatalf("first item %+v", items[0])
	}
	if tip != "OpenScale: Bağlı - ali (100.80.0.2)" {
		t.Fatalf("tooltip %q", tip)
	}
	if copies[idThisDevice] != "100.80.0.2" || copies[peerIDBase] != "100.80.0.3" || copies[peerIDBase+1] != "100.80.0.4" {
		t.Fatalf("copy targets %v", copies)
	}
	var peers, exits []string
	for _, it := range items {
		switch it.Label {
		case "Ağdaki cihazlar":
			for _, c := range it.Children {
				peers = append(peers, c.Label)
			}
		case "Çıkış düğümleri":
			for _, c := range it.Children {
				exits = append(exits, c.Label)
			}
		}
	}
	if len(peers) != 2 || peers[1] != "nas (çevrimdışı)" || len(exits) != 2 {
		t.Fatalf("peers %v exits %v", peers, exits)
	}
	if choices[exitIDBase] != "vps" || choices[idExitNone] != "" {
		t.Fatalf("exit choices %v", choices)
	}

	st.Device.Connected = false
	items, _ = buildTrayMenu(st, true, copies, choices)
	if items[0].Checked || items[0].Detail != "Bağlantı kapalı" {
		t.Fatalf("disconnected item %+v", items[0])
	}
	if items, _ := buildTrayMenu(panel.AppStatus{}, false, copies, choices); items[0].Detail != "Servise ulaşılamıyor" || len(copies) != 0 {
		t.Fatalf("unreachable menu %+v", items)
	}
}

func TestTrayShowsNetworkName(t *testing.T) {
	now := time.Now()
	st := panel.AppStatus{Mode: panel.ModeMember, NetworkName: "Ev ağı", Device: &panel.DeviceStatus{
		Name: "ali", IPv4: "100.80.0.2", Running: true, Connected: true, LastSync: &now,
	}}
	items, tip := buildTrayMenu(st, true, map[int]string{}, map[int]string{})
	if items[0].Label != "OpenScale - Ev ağı" || !strings.HasPrefix(tip, "OpenScale - Ev ağı: Bağlı") {
		t.Fatalf("title %q tip %q", items[0].Label, tip)
	}
	st.NetworkName = strings.Repeat("ş", 64)
	if got := []rune(trayTitle(st)); len(got) != len("OpenScale - ")+maxTrayNameRunes || got[len(got)-1] != '…' {
		t.Fatalf("long name not shortened: %q", string(got))
	}
	if trayTitle(panel.AppStatus{}) != "OpenScale" {
		t.Fatal("title without a name")
	}
}

func TestTrayKillSwitchItem(t *testing.T) {
	st := panel.AppStatus{Mode: panel.ModeMember, Device: &panel.DeviceStatus{
		Name: "ali", IPv4: "100.80.0.2", Connected: true,
		ExitNodes:  []panel.PeerInfo{{Name: "vps", IPv4: "100.80.0.9"}},
		KillSwitch: true, KillSwitchSupported: true,
	}}
	find := func(items []winapp.MenuItem) *winapp.MenuItem {
		for _, it := range items {
			if it.Label != "Çıkış düğümleri" {
				continue
			}
			for i := range it.Children {
				if it.Children[i].ID == idKillSwitch {
					return &it.Children[i]
				}
			}
		}
		return nil
	}
	items, _ := buildTrayMenu(st, true, map[int]string{}, map[int]string{})
	ks := find(items)
	if ks == nil || ks.Label != "Kill switch" || !ks.Checked {
		t.Fatalf("kill switch item %+v", ks)
	}
	st.Device.KillSwitch = false
	items, _ = buildTrayMenu(st, true, map[int]string{}, map[int]string{})
	if ks := find(items); ks == nil || ks.Checked {
		t.Fatalf("kill switch must be unchecked: %+v", ks)
	}
	st.Device.KillSwitchSupported = false
	items, _ = buildTrayMenu(st, true, map[int]string{}, map[int]string{})
	if find(items) != nil {
		t.Fatal("kill switch item shown on a system without one")
	}
}

func findItem(items []winapp.MenuItem, label string) *winapp.MenuItem {
	for i := range items {
		if items[i].Label == label {
			return &items[i]
		}
	}
	return nil
}

func TestTrayMenuFeatures(t *testing.T) {
	now := time.Now()
	st := panel.AppStatus{Mode: panel.ModeMember, Device: &panel.DeviceStatus{
		Name: "ali", IPv4: "100.80.0.2", Running: true, Connected: true, LastSync: &now,
		Peers: []panel.PeerInfo{
			{Name: "nas", IPv4: "100.80.0.4", Pinned: true, Online: true},
			{Name: "laptop", IPv4: "100.80.0.3", Online: true},
		},
		ExitNodes:    []panel.PeerInfo{{Name: "vps", IPv4: "100.80.0.9", Country: "DE"}},
		LastExitNode: "vps",
	}, Health: []panel.HealthAlert{
		{Code: panel.HealthCoordinatorUnreachable, Level: panel.LevelWarning, Message: "Koordinatöre ulaşılamıyor"},
		{Code: panel.HealthTunnelPaused, Level: panel.LevelInfo, Message: "bilgi"},
	}}
	copies, choices := map[int]string{}, map[int]string{}
	items, tip := buildTrayMenu(st, true, copies, choices)

	timed := findItem(items, "Bağlantıyı süreli kes")
	if timed == nil || len(timed.Children) != 3 || disconnectChoices[timed.Children[2].ID] != panel.DisconnectMorning {
		t.Fatalf("timed disconnect submenu %+v", timed)
	}
	problems := findItem(items, "Sorunlar (1)")
	if problems == nil || problems.Children[0].Label != "Koordinatöre ulaşılamıyor" || !problems.Children[0].Disabled {
		t.Fatalf("problems submenu %+v", items)
	}
	if tip != "OpenScale: Bağlı - ali (100.80.0.2) - 1 sorun" {
		t.Fatalf("tooltip %q", tip)
	}
	peers := findItem(items, "Ağdaki cihazlar")
	if peers == nil || len(peers.Children) != 3 || peers.Children[0].Label != "nas" || !peers.Children[1].Separator {
		t.Fatalf("pinned device must come first, set apart: %+v", peers)
	}
	exits := findItem(items, "Çıkış düğümleri")
	if exits == nil || exits.Children[0].ID != idExitLast || choices[idExitLast] != "vps" || exits.Children[0].Detail != "DE" {
		t.Fatalf("last used exit node: %+v", exits)
	}
	var vps *winapp.MenuItem
	for i := range exits.Children {
		if exits.Children[i].ID == exitIDBase {
			vps = &exits.Children[i]
		}
	}
	if vps == nil || vps.Detail != "DE  100.80.0.9" {
		t.Fatalf("country code missing: %+v", vps)
	}

	// While an exit node is in use there is no "last used" shortcut, and a
	// turned-off tunnel offers no timed disconnect.
	st.Device.ExitNodeWanted, st.Device.Connected = "vps", false
	until := now.Add(time.Hour)
	st.Device.DisconnectedUntil = &until
	items, _ = buildTrayMenu(st, true, copies, choices)
	if findItem(items, "Bağlantıyı süreli kes") != nil {
		t.Fatal("timed disconnect offered while off")
	}
	if exits := findItem(items, "Çıkış düğümleri"); exits.Children[0].ID == idExitLast {
		t.Fatal("last used shown while an exit node is chosen")
	}
	if items[0].Detail == "Bağlantı kapalı" || items[0].Checked {
		t.Fatalf("timed disconnect label %+v", items[0])
	}

	// With the service gone, the tray offers the way back to the internet.
	items, _ = buildTrayMenu(panel.AppStatus{}, false, copies, choices)
	found := false
	for _, it := range items {
		found = found || it.ID == idReleaseKillSwitch
	}
	if !found {
		t.Fatalf("unreachable menu without the kill switch release: %+v", items)
	}
}

func TestQuitPromptMentionsKillSwitch(t *testing.T) {
	st := panel.AppStatus{Device: &panel.DeviceStatus{ExitNodeWanted: "vps", KillSwitchActive: true}}
	if !strings.Contains(quitPrompt(st, true), "Kill switch filtreleri de kaldırılır") {
		t.Fatal("the full exit must say it removes the filters")
	}
	if strings.Contains(quitPrompt(panel.AppStatus{Device: &panel.DeviceStatus{}}, true), "Kill switch") {
		t.Fatal("no exit node, no kill switch talk")
	}
}
