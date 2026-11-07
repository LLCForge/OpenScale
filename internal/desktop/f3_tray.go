package desktop

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/p2psend"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/winapp"
)

// Phase 3 tray windows (#802, #803, #813): what they show, built from the
// service's answers. The Windows wiring is in f3_tray_windows.go; this
// file has no system calls so it is tested everywhere. Every text exists
// in Turkish and English; the tray follows the Windows display language
// (the panel keeps its language choice in the browser).

// Window button IDs.
const (
	btnOpenPanel = winapp.FlyoutOpenPanel
	btnClose     = 2
	btnAccept    = 3
	btnReject    = 4
	btnSend      = 5
)

const flyoutPeers = 5

func pick(tr bool, t, e string) string {
	if tr {
		return t
	}
	return e
}

// flyoutData is what the flyout is built from.
type flyoutData struct {
	st     panel.AppStatus
	ok     bool
	diag   *panel.DiagStatus
	offers int
}

// flyoutModel is the status flyout (#802): connection, this device, exit
// node, the five most recently active peers with their path and latency,
// open alerts and pending file offers.
func flyoutModel(d flyoutData, tr bool) winapp.UIModel {
	title := "OpenScale"
	if d.ok && d.st.NetworkName != "" {
		title += " · " + trimRunes(d.st.NetworkName, maxTrayNameRunes)
	}
	m := winapp.UIModel{Title: title, Progress: -1, Selected: -1,
		Buttons: []winapp.UIButton{{ID: btnClose, Label: pick(tr, "Kapat", "Close")}, {ID: btnOpenPanel, Label: pick(tr, "Paneli aç", "Open panel"), Primary: true}}}
	m.Lines = append(m.Lines, winapp.UILine{Text: title, Style: winapp.LineTitle})
	if !d.ok {
		m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Servise ulaşılamıyor", "The service cannot be reached"), Style: winapp.LineWarn})
		return m
	}
	dev := d.st.Device
	if dev == nil || dev.Name == "" {
		m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Bu bilgisayar henüz bir ağa katılmadı", "This computer has not joined a network yet"), Style: winapp.LineMuted})
		return m
	}
	conn := pick(tr, "Bağlı değil", "Disconnected")
	if dev.Connected {
		conn = pick(tr, "Bağlı", "Connected")
	}
	m.Lines = append(m.Lines,
		winapp.UILine{Text: pick(tr, "Bağlantı", "Connection"), Value: conn},
		winapp.UILine{Text: pick(tr, "Bu cihaz", "This device"), Value: dev.Name + "  " + dev.IPv4},
	)
	exit := pick(tr, "Yok (doğrudan internet)", "None (direct internet)")
	switch {
	case dev.ExitNodeWanted != "" && dev.ExitNode != dev.ExitNodeWanted:
		exit = dev.ExitNodeWanted + pick(tr, " (bağlanıyor)", " (connecting)")
	case dev.ExitNode != "":
		exit = dev.ExitNode
	}
	m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Çıkış düğümü", "Exit node"), Value: exit})
	m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "SON EŞLER", "RECENT PEERS"), Style: winapp.LineHeading})
	peers := recentPeers(d.diag, dev.Peers, flyoutPeers, tr)
	if len(peers) == 0 {
		m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Ulaşılabilen cihaz yok", "No device is reachable"), Style: winapp.LineMuted})
	}
	m.Lines = append(m.Lines, peers...)
	alerts := openAlerts(d.st.Health)
	style := winapp.LineBody
	if alerts > 0 {
		style = winapp.LineWarn
	}
	m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Bekleyen uyarılar", "Open alerts"), Value: fmt.Sprint(alerts), Style: style})
	if d.offers > 0 {
		m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Bekleyen dosya teklifleri", "Pending file offers"), Value: fmt.Sprint(d.offers), Style: winapp.LineWarn})
	}
	return m
}

// recentPeers lists the n peers with the latest handshake from the
// diagnostics answer; without it the tray's online peers are used and
// latency is unknown.
func recentPeers(diag *panel.DiagStatus, fallback []panel.PeerInfo, n int, tr bool) []winapp.UILine {
	var out []winapp.UILine
	if diag != nil && len(diag.Peers) > 0 {
		ps := slices.Clone(diag.Peers)
		slices.SortStableFunc(ps, func(a, b panel.DiagPeer) int {
			return handshake(b).Compare(handshake(a))
		})
		for _, p := range ps {
			if len(out) >= n {
				break
			}
			if handshake(p).IsZero() {
				continue
			}
			out = append(out, winapp.UILine{Text: trimRunes(p.Name, 28), Value: pathText(p.Path, p.Online, p.LatencyMS, tr)})
		}
		return out
	}
	for _, p := range fallback {
		if len(out) >= n {
			break
		}
		if !p.Online {
			continue
		}
		path := panel.PathDirect
		if p.Relayed {
			path = panel.PathRelay
		}
		out = append(out, winapp.UILine{Text: trimRunes(p.Name, 28), Value: pathText(path, true, nil, tr)})
	}
	return out
}

// openAlerts counts the warning and danger alerts (countProblems of the
// Windows menu, which is not built elsewhere).
func openAlerts(alerts []panel.HealthAlert) int {
	n := 0
	for _, a := range alerts {
		if a.Level != panel.LevelInfo {
			n++
		}
	}
	return n
}

func handshake(p panel.DiagPeer) time.Time {
	if p.LastHandshake == nil {
		return time.Time{}
	}
	return *p.LastHandshake
}

func pathText(path string, online bool, latency *float64, tr bool) string {
	if !online {
		return pick(tr, "Çevrimdışı", "Offline")
	}
	s := pick(tr, "Doğrudan", "Direct")
	switch path {
	case panel.PathRelay:
		s = pick(tr, "Sunucu üzerinden", "Relayed")
	case panel.PathNone:
		s = pick(tr, "Yol yok", "No path")
	}
	if latency != nil && *latency >= 0 {
		s += fmt.Sprintf(" · %.0f ms", *latency)
	}
	return s
}

func trimRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// formatSize is a short size ("12,4 MB" / "12.4 MB").
func formatSize(n int64, tr bool) string {
	units := []string{"B", "KB", "MB", "GB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	var s string
	if i == 0 {
		s = fmt.Sprintf("%d %s", n, units[0])
	} else {
		s = fmt.Sprintf("%.1f %s", v, units[i])
	}
	if tr {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s
}

// offerNotice is the notification of an incoming offer (#813). On the
// lock screen it names neither the file nor its type: only that a device
// offers a file.
func offerNotice(o p2psend.Offer, locked, tr bool) (title, msg string) {
	title = pick(tr, "Gelen dosya", "Incoming file")
	if locked {
		return title, fmt.Sprintf(pick(tr, "%s bir dosya göndermek istiyor. Yanıtlamak için kilidi açın.", "%s wants to send a file. Unlock to answer."), o.From)
	}
	msg = fmt.Sprintf(pick(tr, "%s göndermek istiyor: %s (%s). Kabul etmek veya reddetmek için tıklayın.", "%s wants to send %s (%s). Click to accept or reject."),
		o.From, trimRunes(o.Name, 60), formatSize(o.Size, tr))
	return title, msg
}

// offerModel is the accept/reject window of an offer; gone is true when
// the offer stopped waiting (answered elsewhere or timed out).
func offerModel(o p2psend.Offer, gone, tr bool) winapp.UIModel {
	m := winapp.UIModel{Title: pick(tr, "Gelen dosya", "Incoming file"), Progress: -1, Selected: -1}
	m.Lines = append(m.Lines,
		winapp.UILine{Text: pick(tr, "Gelen dosya", "Incoming file"), Style: winapp.LineTitle},
		winapp.UILine{Text: pick(tr, "Gönderen", "From"), Value: o.From},
		winapp.UILine{Text: pick(tr, "Dosya", "File"), Value: trimRunes(o.Name, 40)},
		winapp.UILine{Text: pick(tr, "Boyut", "Size"), Value: formatSize(o.Size, tr)},
	)
	if o.Executable {
		m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Bu dosya açıldığında kod çalıştırabilir.", "This file can run code when it is opened."), Style: winapp.LineWarn})
	}
	m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Kabul edilen dosya karantinaya iner.", "An accepted file lands in quarantine."), Style: winapp.LineMuted})
	if gone {
		m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Bu teklif artık beklemiyor.", "This offer is no longer waiting."), Style: winapp.LineWarn})
		m.Buttons = []winapp.UIButton{{ID: btnClose, Label: pick(tr, "Kapat", "Close"), Primary: true}}
		return m
	}
	m.Buttons = []winapp.UIButton{{ID: btnReject, Label: pick(tr, "Reddet", "Reject")}, {ID: btnAccept, Label: pick(tr, "Kabul et", "Accept"), Primary: true}}
	return m
}

// findIncoming returns the transfer of an accepted offer.
func findIncoming(list []p2psend.TransferView, o p2psend.Offer) (p2psend.TransferView, bool) {
	var best p2psend.TransferView
	found := false
	for _, t := range list {
		if t.Outgoing || t.Peer != o.From || t.Name != o.Name || t.Started.Before(o.At.Add(-time.Minute)) {
			continue
		}
		if !found || t.Started.After(best.Started) {
			best, found = t, true
		}
	}
	return best, found
}

// progressModel is the receiving window after an offer was accepted.
func progressModel(o p2psend.Offer, t p2psend.TransferView, found, tr bool) winapp.UIModel {
	m := winapp.UIModel{Title: pick(tr, "Dosya alınıyor", "Receiving a file"), Progress: 0, Selected: -1,
		Buttons: []winapp.UIButton{{ID: btnClose, Label: pick(tr, "Kapat", "Close")}, {ID: btnOpenPanel, Label: pick(tr, "Paneli aç", "Open panel"), Primary: true}}}
	m.Lines = append(m.Lines,
		winapp.UILine{Text: pick(tr, "Dosya alınıyor", "Receiving a file"), Style: winapp.LineTitle},
		winapp.UILine{Text: pick(tr, "Gönderen", "From"), Value: o.From},
		winapp.UILine{Text: pick(tr, "Dosya", "File"), Value: trimRunes(o.Name, 40)},
	)
	size := o.Size
	if found && t.Size > 0 {
		size = t.Size
	}
	switch {
	case !found:
		m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Bağlantı bekleniyor...", "Waiting for the connection..."), Style: winapp.LineMuted})
	case t.State == p2psend.StateDone:
		m.Progress = 1
		m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Alındı. Dosya karantinada; Gelen Dosyalar sayfasından serbest bırakın.", "Received. The file is in quarantine; release it on the Received Files page."), Style: winapp.LineMuted})
	case t.State == p2psend.StateFailed:
		m.Progress = -1
		m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Aktarım tamamlanamadı.", "The transfer did not complete."), Style: winapp.LineWarn})
	default:
		if size > 0 {
			m.Progress = min(float64(t.Done)/float64(size), 1)
		}
		m.Lines = append(m.Lines, winapp.UILine{Text: formatSize(t.Done, tr) + " / " + formatSize(size, tr), Style: winapp.LineMuted})
	}
	return m
}

// sendFile is one file of a Send to request.
type sendFile struct {
	Name string
	Size int64
}

// pickerModel asks for the recipient of a Send to request (#803). peers
// are the names of the reachable devices.
func pickerModel(files []sendFile, peers []string, tr bool) winapp.UIModel {
	var total int64
	for _, f := range files {
		total += f.Size
	}
	what := ""
	if len(files) == 1 {
		what = trimRunes(files[0].Name, 40)
	} else {
		what = fmt.Sprintf(pick(tr, "%d dosya", "%d files"), len(files))
	}
	m := winapp.UIModel{Title: pick(tr, "OpenScale ile gönder", "Send with OpenScale"), Progress: -1, List: peers, Selected: 0}
	m.Lines = append(m.Lines,
		winapp.UILine{Text: pick(tr, "OpenScale ile gönder", "Send with OpenScale"), Style: winapp.LineTitle},
		winapp.UILine{Text: what, Value: formatSize(total, tr)},
		winapp.UILine{Text: pick(tr, "Uçtan uca şifreli gider; alıcı kabul etmelidir.", "It travels end-to-end encrypted; the recipient must accept it."), Style: winapp.LineMuted},
		winapp.UILine{Text: pick(tr, "ALICI", "RECIPIENT"), Style: winapp.LineHeading},
	)
	if len(peers) == 0 {
		m.Selected = -1
		m.Lines = append(m.Lines, winapp.UILine{Text: pick(tr, "Şu an ulaşılabilen cihaz yok.", "No device is reachable right now."), Style: winapp.LineWarn})
		m.Buttons = []winapp.UIButton{{ID: btnClose, Label: pick(tr, "Kapat", "Close"), Primary: true}}
		return m
	}
	m.Buttons = []winapp.UIButton{{ID: btnClose, Label: pick(tr, "Vazgeç", "Cancel")}, {ID: btnSend, Label: pick(tr, "Gönder", "Send"), Primary: true}}
	return m
}

// sendTargets are the reachable devices other than this one, pinned first
// as the service sorts them.
func sendTargets(st panel.AppStatus) []string {
	if st.Device == nil {
		return nil
	}
	var out []string
	for _, p := range st.Device.Peers {
		if p.Online && p.Name != "" && p.Name != st.Device.Name {
			out = append(out, p.Name)
		}
	}
	return out
}

// transferNotice is the notification when a transfer the tray follows
// ends; locked hides the file name.
func transferNotice(t p2psend.TransferView, locked, tr bool) (string, bool) {
	name := trimRunes(t.Name, 60)
	if locked {
		name = pick(tr, "Bir dosya", "A file")
	}
	switch t.State {
	case p2psend.StateDone:
		if t.Outgoing {
			return fmt.Sprintf(pick(tr, "%s, %s cihazına gönderildi.", "%s was sent to %s."), name, t.Peer), true
		}
		return fmt.Sprintf(pick(tr, "%s alındı ve karantinada bekliyor.", "%s was received and waits in quarantine."), name), true
	case p2psend.StateFailed:
		if t.Outgoing {
			return fmt.Sprintf(pick(tr, "%s, %s cihazına gönderilemedi.", "%s could not be sent to %s."), name, t.Peer), true
		}
		return fmt.Sprintf(pick(tr, "%s alınamadı.", "%s could not be received."), name), true
	}
	return "", false
}
