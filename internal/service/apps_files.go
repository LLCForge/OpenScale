package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// File inbox (ADR-0031). The service runs as LocalSystem, so received
// files go to the data directory's inbox, not to a user's Downloads; the
// panel lists them and lets the owner download or delete them.

type receivedEntry struct {
	Name       string    `json:"name"`
	From       string    `json:"from"`
	Size       int64     `json:"size"`
	At         time.Time `json:"at"`
	Executable bool      `json:"exec,omitempty"`
}

type autoAcceptFile struct {
	Devices []string `json:"devices"`
}

func loadJSON(path string, v any) error {
	data, err := securefile.ReadLimited(path, maxStateFile)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func saveJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return securefile.Replace(path, data)
}

// LoadAutoAccept returns the devices whose files are accepted without
// asking. A missing file is an empty list.
func LoadAutoAccept(dir string) ([]string, error) {
	var f autoAcceptFile
	if err := loadJSON(filepath.Join(dir, AppsDir, autoAcceptFn), &f); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return f.Devices, nil
}

// SetAutoAccept adds or removes device on the auto-accept list under dir.
func SetAutoAccept(dir, device string, on bool) error {
	device = normalizeDevice(device)
	if device == "" || len(device) > 63 {
		return errors.New("geçersiz cihaz adı")
	}
	list, err := LoadAutoAccept(dir)
	if err != nil {
		return err
	}
	list = slices.DeleteFunc(list, func(s string) bool { return s == device })
	if on {
		if len(list) >= maxAutoAccept {
			return errors.New("otomatik kabul listesi dolu")
		}
		list = append(list, device)
		slices.Sort(list)
	}
	return saveJSON(filepath.Join(dir, AppsDir, autoAcceptFn), autoAcceptFile{Devices: list})
}

// LoadWakeMACs returns the stored Wake-on-LAN addresses by device name.
func LoadWakeMACs(dir string) (map[string]string, error) {
	m := map[string]string{}
	if err := loadJSON(filepath.Join(dir, AppsDir, wakeMACsFn), &m); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, err
	}
	return m, nil
}

// WakeMACFor returns the MAC address to wake device with: one the owner
// set, otherwise the last one the device reported.
func WakeMACFor(macs map[string]string, device string) string {
	if m := macs[manualKey(device)]; m != "" {
		return m
	}
	return macs[device]
}

func (a *Apps) loadReceived() []receivedEntry {
	var list []receivedEntry
	_ = loadJSON(a.appsPath(receivedFn), &list)
	return list
}

// ListInbox lists the files in the inbox under dir, newest first.
func ListInbox(dir string) ([]panel.InboxFile, error) {
	var meta []receivedEntry
	_ = loadJSON(filepath.Join(dir, AppsDir, receivedFn), &meta)
	byName := make(map[string]receivedEntry, len(meta))
	for _, m := range meta {
		byName[m.Name] = m
	}
	entries, err := os.ReadDir(filepath.Join(dir, InboxDir))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []panel.InboxFile{}, nil
		}
		return nil, err
	}
	out := []panel.InboxFile{}
	for _, e := range entries {
		if !e.Type().IsRegular() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		f := panel.InboxFile{Name: e.Name(), Size: info.Size(), ReceivedAt: info.ModTime().UTC(), Executable: filesend.IsExecutable(e.Name())}
		if m, ok := byName[e.Name()]; ok {
			f.From, f.ReceivedAt = m.From, m.At
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt.After(out[j].ReceivedAt) })
	return out, nil
}

// inboxFilePath validates a file name from a request and returns its path.
func inboxFilePath(dir, name string) (string, error) {
	if name == "" || len(name) > 255 || filepath.Base(name) != name || !filepath.IsLocal(name) || strings.HasPrefix(name, ".") || strings.ContainsAny(name, `/\:`) {
		return "", errors.New("geçersiz dosya adı")
	}
	p := filepath.Join(dir, InboxDir, name)
	info, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", errors.New("dosya bulunamadı")
		}
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("dosya bulunamadı")
	}
	return p, nil
}

// DeleteInboxFile removes a received file from the inbox under dir.
func DeleteInboxFile(dir, name string) error {
	p, err := inboxFilePath(dir, name)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

// --- receiving ---

func (a *Apps) acceptFile(from netip.Addr, name string, size int64) bool {
	doc, self, dev, ok := a.peer(from)
	if !ok || !doc.AllowsFileSend(dev.Name, self.Name) {
		a.log.Info("file offer refused: no rule allows it")
		return false
	}
	if list, err := LoadAutoAccept(a.cfg.Dir); err == nil && containsName(list, dev.Name) {
		a.log.Info("file accepted automatically", "from", dev.Name, "size", size)
		return true
	}
	if !a.cfg.Interactive {
		a.log.Info("file offer refused: sender is not on the auto-accept list", "from", dev.Name)
		return false
	}
	now := a.cfg.Now()
	p := &pendingOffer{
		view:   panel.PendingOffer{ID: newID(), From: dev.Name, Name: name, Size: size, At: now.UTC(), ExpiresAt: now.Add(offerTimeout).UTC()},
		decide: make(chan bool, 1),
	}
	a.mu.Lock()
	if len(a.pending) >= maxPendingOffers {
		a.mu.Unlock()
		return false
	}
	a.pending[p.view.ID] = p
	ctx := a.runCtx
	a.mu.Unlock()
	a.log.Info("file offer waits for the owner", "from", dev.Name, "size", size)
	defer func() {
		a.mu.Lock()
		delete(a.pending, p.view.ID)
		a.mu.Unlock()
	}()
	t := time.NewTimer(offerTimeout)
	defer t.Stop()
	select {
	case ok := <-p.decide:
		if !ok {
			return false
		}
	case <-t.C:
		a.log.Info("file offer expired")
		return false
	case <-ctx.Done():
		return false
	}
	// The rules may have changed while the owner decided.
	doc, self, dev2, ok := a.peer(from)
	return ok && dev2.Name == dev.Name && doc.AllowsFileSend(dev.Name, self.Name)
}

func (a *Apps) received(f filesend.Received) {
	from := ""
	if _, _, d, ok := a.peer(f.From); ok {
		from = d.Name
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	list := a.loadReceived()
	list = slices.DeleteFunc(list, func(e receivedEntry) bool { return e.Name == f.Name })
	list = append(list, receivedEntry{Name: f.Name, From: from, Size: f.Size, At: a.cfg.Now().UTC(), Executable: f.Executable})
	if len(list) > maxReceived {
		list = list[len(list)-maxReceived:]
	}
	if err := saveJSON(a.appsPath(receivedFn), list); err != nil {
		a.log.Warn("save inbox list", "error", err.Error())
	}
	go a.scanReceived(f) // #458, files_p07.go
}

// Inbox implements panel.RemoteApps.
func (a *Apps) Inbox() panel.InboxView {
	files, err := ListInbox(a.cfg.Dir)
	if err != nil {
		a.log.Warn("list inbox", "error", err.Error())
		files = []panel.InboxFile{}
	}
	auto, _ := LoadAutoAccept(a.cfg.Dir)
	if auto == nil {
		auto = []string{}
	}
	return panel.InboxView{Files: files, Pending: a.pendingList(), AutoAccept: auto}
}

func (a *Apps) pendingList() []panel.PendingOffer {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]panel.PendingOffer, 0, len(a.pending))
	for _, p := range a.pending {
		out = append(out, p.view)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// DecideOffer accepts or rejects a pending file offer.
func (a *Apps) DecideOffer(id string, accept bool) error {
	a.mu.Lock()
	p, ok := a.pending[id]
	a.mu.Unlock()
	if !ok {
		return errors.New("bekleyen teklif bulunamadı (süresi dolmuş olabilir)")
	}
	select {
	case p.decide <- accept:
	default:
	}
	return nil
}

// SetAutoAccept implements panel.RemoteApps.
func (a *Apps) SetAutoAccept(device string, on bool) error {
	device = normalizeDevice(device)
	if on {
		doc, _, ok := a.current()
		if !ok {
			return errNoTunnel()
		}
		if _, ok := doc.DeviceByName(device); !ok {
			return errors.New("böyle bir cihaz yok")
		}
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return SetAutoAccept(a.cfg.Dir, device, on)
}

// DeleteInboxFile implements panel.RemoteApps.
func (a *Apps) DeleteInboxFile(name string) error {
	if err := DeleteInboxFile(a.cfg.Dir, name); err != nil {
		return err
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	list := a.loadReceived()
	kept := slices.DeleteFunc(list, func(e receivedEntry) bool { return e.Name == name })
	return saveJSON(a.appsPath(receivedFn), kept)
}

// OpenInboxFile implements panel.RemoteApps.
func (a *Apps) OpenInboxFile(name string) (io.ReadSeekCloser, panel.InboxFile, error) {
	p, err := inboxFilePath(a.cfg.Dir, name)
	if err != nil {
		return nil, panel.InboxFile{}, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, panel.InboxFile{}, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, panel.InboxFile{}, errors.New("dosya açılamadı")
	}
	return f, panel.InboxFile{Name: name, Size: info.Size(), Executable: filesend.IsExecutable(name)}, nil
}

// --- sending ---

// SendFile implements panel.RemoteApps: it stores the upload and sends it
// in the background.
func (a *Apps) SendFile(device, name string, body io.Reader, size int64) (string, error) {
	doc, self, ok := a.current()
	if !ok {
		return "", errNoTunnel()
	}
	target, ok := doc.DeviceByName(normalizeDevice(device))
	if !ok {
		return "", errors.New("böyle bir cihaz yok")
	}
	if !doc.AllowsFileSend(self.Name, target.Name) {
		return "", errors.New("bu cihaza dosya göndermeye izin veren bir kural yok")
	}
	clean, err := filesend.SanitizeName(name)
	if err != nil {
		return "", errors.New("dosya adı güvenli değil")
	}
	if size <= 0 || size > maxPanelUpload {
		return "", fmt.Errorf("dosya 1 bayt ile %d GiB arasında olmalı", maxPanelUpload>>30)
	}
	a.mu.Lock()
	if a.sending >= maxActiveSends {
		a.mu.Unlock()
		return "", errors.New("aynı anda en fazla iki gönderim yapılabilir")
	}
	a.sending++
	a.mu.Unlock()
	release := func() {
		a.mu.Lock()
		a.sending--
		a.mu.Unlock()
	}
	id := newID()
	dir := a.appsPath(outboxDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		release()
		return "", err
	}
	path := filepath.Join(dir, id+".part")
	if err := writeUpload(path, body, size); err != nil {
		_ = os.Remove(path)
		release()
		return "", err
	}
	job := &transferJob{status: panel.TransferStatus{ID: id, Device: target.Name, Name: clean, Size: size, State: panel.TransferSending, StartedAt: a.cfg.Now().UTC()}}
	a.mu.Lock()
	a.transfers = append(a.transfers, job)
	if len(a.transfers) > maxTransfers {
		a.transfers = a.transfers[len(a.transfers)-maxTransfers:]
	}
	ctx := a.runCtx
	a.mu.Unlock()
	dst := netip.AddrPortFrom(target.IPv4, trust.FilesPort)
	go func() {
		defer release()
		defer os.Remove(path)
		_, err := filesend.Send(ctx, dst, path, &filesend.SendOptions{
			Name: clean,
			Progress: func(done, _ int64) {
				a.mu.Lock()
				job.status.Sent = done
				a.mu.Unlock()
			},
		})
		a.mu.Lock()
		defer a.mu.Unlock()
		if err != nil {
			job.status.State, job.status.Error = panel.TransferFailed, err.Error()
			return
		}
		job.status.State, job.status.Sent = panel.TransferDone, size
	}()
	return id, nil
}

func writeUpload(path string, body io.Reader, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(body, size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("dosya alınamadı: %w", err)
	}
	if n != size {
		return errors.New("yüklenen dosyanın boyutu bildirilenle aynı değil")
	}
	return nil
}

// Transfers implements panel.RemoteApps.
func (a *Apps) Transfers() []panel.TransferStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]panel.TransferStatus, 0, len(a.transfers))
	for i := len(a.transfers) - 1; i >= 0; i-- {
		out = append(out, a.transfers[i].status)
	}
	return out
}

// cleanOutbox removes uploads left behind by a crash.
func (a *Apps) cleanOutbox() {
	_ = os.RemoveAll(a.appsPath(outboxDir))
}
