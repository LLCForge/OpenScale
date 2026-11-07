//go:build windows

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/p2psend"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/winapp"
)

// Windows wiring of the phase 3 tray windows (f3_tray.go): the status
// flyout on a left click (#802), "Send with OpenScale" (#803) and file
// offers answered from the notification (#813). runTray calls
// f3LeftClick, withF3Items, f3MenuClick and startF3.

const (
	idLeftClickPref = 5000
	flyoutFetch     = 1500 * time.Millisecond
	offerPoll       = 3 * time.Second
	stageTimeout    = 30 * time.Minute
	maxFollowed     = 64
)

// --- service requests ---

func (c *trayClient) diagStatus(ctx context.Context) (*panel.DiagStatus, error) {
	var st panel.DiagStatus
	if err := c.do(ctx, http.MethodGet, panel.LocalAPIPrefix+"/status", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (c *trayClient) trayE2E(ctx context.Context) (panel.TrayE2EView, error) {
	var v panel.TrayE2EView
	err := c.do(ctx, http.MethodGet, "/api/app/tray/e2e", nil, &v)
	return v, err
}

func (c *trayClient) trayDecide(ctx context.Context, id string, accept bool) error {
	var out map[string]bool
	return c.do(ctx, http.MethodPost, "/api/app/tray/e2e/decide", panel.E2EDecision{ID: id, Accept: accept}, &out)
}

func (c *trayClient) traySend(ctx context.Context, device, path string) error {
	var out map[string]bool
	err := c.do(ctx, http.MethodPost, "/api/app/tray/e2e/send", panel.TrayE2ESend{Device: device, Path: path}, &out)
	// The service answers 202 Accepted, which do() reports as an error
	// without a message.
	if err != nil && strings.Contains(err.Error(), "202") {
		return nil
	}
	return err
}

// trayStage streams one file to the service's staging folder.
func (c *trayClient) trayStage(ctx context.Context, name string, body io.Reader, size int64) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, stageTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiBase()+"/api/app/tray/e2e/stage", body)
	if err != nil {
		return "", err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(panel.E2EFileNameHeader, url.PathEscape(name))
	if err := c.authorize(req); err != nil {
		return "", err
	}
	hc := &http.Client{CheckRedirect: c.http.CheckRedirect, Transport: c.http.Transport}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxReplySize))
	if err != nil {
		return "", err
	}
	var out struct {
		Path  string `json:"path"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(reply, &out)
	if resp.StatusCode != http.StatusOK || out.Path == "" {
		if out.Error != "" {
			return "", errors.New(out.Error)
		}
		return "", fmt.Errorf("servis yanıtı: %s", resp.Status)
	}
	return out.Path, nil
}

// --- flyout (#802) ---

func fetchFlyout(ctx context.Context, client *trayClient) flyoutData {
	ctx, cancel := context.WithTimeout(ctx, flyoutFetch)
	defer cancel()
	var d flyoutData
	var wg sync.WaitGroup
	wg.Go(func() {
		st, err := client.status(ctx)
		d.st, d.ok = st, err == nil
	})
	var diag *panel.DiagStatus
	wg.Go(func() { diag, _ = client.diagStatus(ctx) })
	offers := 0
	wg.Go(func() {
		if v, err := client.trayE2E(ctx); err == nil {
			offers = len(v.Pending)
		}
	})
	wg.Wait()
	d.diag, d.offers = diag, offers
	return d
}

// f3LeftClick is the icon's left click: the flyout, or the panel when
// the owner chose so.
func f3LeftClick(ctx context.Context, client *trayClient, open func()) func() {
	return func() {
		if winapp.TrayLeftClick() == winapp.LeftClickPanel {
			open()
			return
		}
		winapp.ToggleFlyout(ctx, func() winapp.UIModel {
			return flyoutModel(fetchFlyout(ctx, client), winapp.UITurkish())
		}, open)
	}
}

// withF3Items adds the left click choice to the Preferences submenu.
func withF3Items(items []winapp.MenuItem) []winapp.MenuItem {
	for i, it := range items {
		if it.Label != "Tercihler" || len(it.Children) == 0 {
			continue
		}
		children := append([]winapp.MenuItem(nil), it.Children...)
		children = append(children, winapp.MenuItem{Separator: true}, winapp.MenuItem{ID: idLeftClickPref,
			Label:   winapp.Tr("Sol tık durum penceresini açsın", "Left click opens the status window"),
			Checked: winapp.TrayLeftClick() == winapp.LeftClickFlyout})
		out := append([]winapp.MenuItem(nil), items...)
		out[i].Children = children
		return out
	}
	return items
}

// f3MenuClick handles the items withF3Items added.
func f3MenuClick(id int) bool {
	if id != idLeftClickPref {
		return false
	}
	next := winapp.LeftClickFlyout
	if winapp.TrayLeftClick() == winapp.LeftClickFlyout {
		next = winapp.LeftClickPanel
	}
	_ = winapp.SetTrayLeftClick(next)
	return true
}

// --- send to (#803) and offers (#813) ---

type followKey struct {
	outgoing bool
	peer     string
	name     string
}

type f3Tray struct {
	client *trayClient
	tray   *winapp.Tray

	mu       sync.Mutex
	notified map[string]bool
	dialogs  map[string]bool
	followed map[followKey]time.Time
}

// startF3 adds the Send to entry, listens for Send to requests and
// watches file offers until ctx ends.
func startF3(ctx context.Context, client *trayClient, tray *winapp.Tray) {
	f := &f3Tray{client: client, tray: tray, notified: map[string]bool{}, dialogs: map[string]bool{}, followed: map[followKey]time.Time{}}
	installed := filepath.Join(winapp.InstallDir(), "openscale.exe")
	if self, err := os.Executable(); err == nil && strings.EqualFold(filepath.Clean(self), installed) {
		// Only the installed program is named in the menu; a copy run
		// from elsewhere must not point it at itself.
		_ = winapp.EnsureSendToShortcut(installed)
	}
	go func() { _ = winapp.ServeSendTo(ctx, func(files []winapp.SendToFile) { f.sendTo(ctx, files) }) }()
	go f.watch(ctx)
}

func closeFiles(files []winapp.SendToFile) {
	for _, x := range files {
		_ = x.File.Close()
	}
}

func (f *f3Tray) note(msg string) { f.tray.Notify("OpenScale", msg) }

func (f *f3Tray) follow(k followKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.followed) >= maxFollowed {
		for old := range f.followed {
			delete(f.followed, old)
			break
		}
	}
	f.followed[k] = time.Now()
}

func (f *f3Tray) sendTo(ctx context.Context, files []winapp.SendToFile) {
	defer closeFiles(files)
	tr := winapp.UITurkish()
	st, err := f.client.status(ctx)
	if err != nil {
		f.note(winapp.Tr("Servise ulaşılamıyor; dosyalar gönderilmedi.", "The service cannot be reached; the files were not sent."))
		return
	}
	peers := sendTargets(st)
	list := make([]sendFile, 0, len(files))
	for _, x := range files {
		list = append(list, sendFile{Name: x.Name, Size: x.Size})
	}
	res, err := winapp.ShowUI(ctx, winapp.UIDialog, pickerModel(list, peers, tr), nil)
	if err != nil || res.Button != btnSend || res.Selected < 0 || res.Selected >= len(peers) {
		return
	}
	device := peers[res.Selected]
	sent := 0
	for _, x := range files {
		path, err := f.client.trayStage(ctx, x.Name, x.File, x.Size)
		if err == nil {
			err = f.client.traySend(ctx, device, path)
		}
		if err != nil {
			f.note(fmt.Sprintf(winapp.Tr("%s gönderilemedi: %s", "%s could not be sent: %s"), trimRunes(x.Name, 60), err.Error()))
			continue
		}
		f.follow(followKey{outgoing: true, peer: device, name: x.Name})
		sent++
	}
	if sent > 0 {
		f.note(fmt.Sprintf(winapp.Tr("%d dosya %s cihazına gönderiliyor; alıcının kabul etmesi bekleniyor.", "Sending %d file(s) to %s; waiting for the recipient to accept."), sent, device))
	}
}

func (f *f3Tray) watch(ctx context.Context) {
	t := time.NewTicker(offerPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		v, err := f.client.trayE2E(ctx)
		if err != nil {
			continue
		}
		f.announceOffers(ctx, v.Pending)
		f.announceTransfers(v.Transfers)
	}
}

func (f *f3Tray) announceOffers(ctx context.Context, pending []p2psend.Offer) {
	tr := winapp.UITurkish()
	waiting := map[string]bool{}
	for _, o := range pending {
		waiting[o.ID] = true
		f.mu.Lock()
		seen := f.notified[o.ID]
		f.notified[o.ID] = true
		f.mu.Unlock()
		if seen {
			continue
		}
		title, msg := offerNotice(o, winapp.SessionLocked(), tr)
		f.tray.NotifyAction(title, msg, func() { f.offerDialog(ctx, o) })
	}
	f.mu.Lock()
	for id := range f.notified {
		if !waiting[id] {
			delete(f.notified, id)
		}
	}
	f.mu.Unlock()
}

func (f *f3Tray) announceTransfers(list []p2psend.TransferView) {
	tr := winapp.UITurkish()
	f.mu.Lock()
	var done []p2psend.TransferView
	for k, since := range f.followed {
		for _, t := range list {
			if t.Outgoing != k.outgoing || t.Peer != k.peer || t.Name != k.name || t.Started.Before(since.Add(-time.Minute)) {
				continue
			}
			if t.State == p2psend.StateDone || t.State == p2psend.StateFailed {
				done = append(done, t)
				delete(f.followed, k)
			}
			break
		}
		if time.Since(since) > 24*time.Hour {
			delete(f.followed, k)
		}
	}
	f.mu.Unlock()
	locked := winapp.SessionLocked()
	for _, t := range done {
		if msg, ok := transferNotice(t, locked, tr); ok {
			f.note(msg)
		}
	}
}

func (f *f3Tray) stillPending(ctx context.Context, id string) bool {
	v, err := f.client.trayE2E(ctx)
	if err != nil {
		return true
	}
	for _, o := range v.Pending {
		if o.ID == id {
			return true
		}
	}
	return false
}

// offerDialog asks about one offer; a second click on the notification
// while it is open does not open another one.
func (f *f3Tray) offerDialog(ctx context.Context, o p2psend.Offer) {
	f.mu.Lock()
	if f.dialogs[o.ID] {
		f.mu.Unlock()
		return
	}
	f.dialogs[o.ID] = true
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.dialogs, o.ID)
		f.mu.Unlock()
	}()
	tr := winapp.UITurkish()
	if winapp.SessionLocked() {
		return // answered after unlocking, from the panel or a new click
	}
	gone := !f.stillPending(ctx, o.ID)
	res, err := winapp.ShowUI(ctx, winapp.UIDialog, offerModel(o, gone, tr), func() (winapp.UIModel, bool) {
		if gone {
			return winapp.UIModel{}, false
		}
		if !f.stillPending(ctx, o.ID) {
			gone = true
			return offerModel(o, true, tr), true
		}
		return winapp.UIModel{}, false
	})
	if err != nil {
		return
	}
	switch res.Button {
	case btnReject:
		if err := f.client.trayDecide(ctx, o.ID, false); err != nil {
			f.note(winapp.Tr("Bu dosya teklifi artık beklemiyor.", "This file offer is no longer waiting."))
		}
		return
	case btnAccept:
	default:
		return
	}
	if err := f.client.trayDecide(ctx, o.ID, true); err != nil {
		f.note(winapp.Tr("Bu dosya teklifi artık beklemiyor.", "This file offer is no longer waiting."))
		return
	}
	f.follow(followKey{outgoing: false, peer: o.From, name: o.Name})
	progress := func() (winapp.UIModel, bool) {
		v, err := f.client.trayE2E(ctx)
		if err != nil {
			return winapp.UIModel{}, false
		}
		t, found := findIncoming(v.Transfers, o)
		return progressModel(o, t, found, tr), true
	}
	first, _ := progress()
	if first.Title == "" {
		first = progressModel(o, p2psend.TransferView{}, false, tr)
	}
	res, err = winapp.ShowUI(ctx, winapp.UIDialog, first, progress)
	if err == nil && res.Button == btnOpenPanel {
		if err := openPanel(ctx, f.client); err != nil {
			f.note(err.Error())
		}
	}
}
