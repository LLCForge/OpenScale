package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/containers"
	"github.com/openscale/openscale/internal/edgenet"
	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// Time-limited single file links (#460), local antivirus scan of received
// files (#458) and the subnet device inventory (#442); P07.

const (
	linksFn         = "links.json"
	avscanFn        = "avscan.json"
	avscanResultsFn = "avscan-results.json"
	maxScanResults  = 200
	scanTimeout     = 5 * time.Minute
)

type avscanSettings struct {
	Enabled bool `json:"enabled,omitempty"`
}

type filesP07 struct {
	mu      sync.Mutex
	links   *filesend.LinkStore
	scanMu  sync.Mutex // one scan at a time
	scanner func() (filesend.Scanner, bool)
}

var filesP07States sync.Map // *Apps -> *filesP07

func (a *Apps) filesP07() *filesP07 {
	if v, ok := filesP07States.Load(a); ok {
		return v.(*filesP07)
	}
	v, _ := filesP07States.LoadOrStore(a, &filesP07{scanner: filesend.FindScanner})
	return v.(*filesP07)
}

// linkStore opens the link store.
func (a *Apps) linkStore() (*filesend.LinkStore, error) {
	st := a.filesP07()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.links != nil {
		return st.links, nil
	}
	s, err := filesend.OpenLinkStore(a.appsPath(linksFn), a.cfg.Now)
	if err != nil {
		return nil, err
	}
	s.OnDownload = func(l filesend.Link) {
		a.log.Info("file link downloaded", "link", l.ID, "device", l.Device, "downloads", l.Downloads, "max", l.MaxDownloads)
	}
	st.links = s
	return s, nil
}

// linksForServe returns the store while some link is live (the serve
// port then also serves links), or nil.
func (a *Apps) linksForServe() *filesend.LinkStore {
	if _, err := os.Stat(a.appsPath(linksFn)); err != nil {
		return nil
	}
	s, err := a.linkStore()
	if err != nil || !s.Active() {
		return nil
	}
	return s
}

func linkView(l filesend.Link) panel.FileLinkView {
	return panel.FileLinkView{ID: l.ID, Name: l.Name, Path: l.Path, Device: l.Device, Size: l.Size, Created: l.Created,
		Expires: l.Expires, MaxDownloads: l.MaxDownloads, Downloads: l.Downloads}
}

func (a *Apps) fileLinks() (panel.FileLinksStatus, error) {
	out := panel.FileLinksStatus{Links: []panel.FileLinkView{}}
	s, err := a.linkStore()
	if err != nil {
		return out, err
	}
	for _, l := range s.List() {
		out.Links = append(out.Links, linkView(l))
	}
	if doc, self, ok := a.current(); ok {
		out.Served = doc.HostsService(self.Name, trust.ServiceServe)
	}
	if !out.Served {
		out.Note = "Bağlantıların indirilebilmesi için bu cihaza yayın (serve) kuralı gerekir; kural kök anahtarla imzalanır."
	}
	return out, nil
}

func (a *Apps) createFileLink(req panel.FileLinkRequest) (panel.FileLinkCreated, error) {
	path := filepath.Clean(strings.TrimSpace(req.Path))
	if !filepath.IsAbs(path) {
		return panel.FileLinkCreated{}, errors.New("dosya yolu mutlak olmalı")
	}
	if a.cfg.Dir != "" && within(path, filepath.Clean(a.cfg.Dir)) {
		// SECURITY: the data directory holds the keys.
		return panel.FileLinkCreated{}, errors.New("OpenScale veri klasöründeki dosyalar paylaşılamaz")
	}
	if req.Hours < 1 || req.Hours > int(filesend.MaxLinkTTL/time.Hour) {
		return panel.FileLinkCreated{}, fmt.Errorf("geçerlilik 1 ile %d saat arasında olmalı", int(filesend.MaxLinkTTL/time.Hour))
	}
	doc, self, ok := a.current()
	if !ok {
		return panel.FileLinkCreated{}, errNoTunnel()
	}
	device := normalizeDevice(req.Device)
	dev, ok := doc.DeviceByName(device)
	if !ok || dev.Name == self.Name {
		return panel.FileLinkCreated{}, errors.New("böyle bir cihaz yok")
	}
	s, err := a.linkStore()
	if err != nil {
		return panel.FileLinkCreated{}, err
	}
	l, token, err := s.Create(path, dev.Name, time.Duration(req.Hours)*time.Hour, req.Downloads)
	if err != nil {
		return panel.FileLinkCreated{}, err
	}
	host := self.IPv4.String()
	if doc.DNSDomain != "" {
		host = self.Name + "." + doc.DNSDomain
	}
	url := "http://" + host + ":" + strconv.Itoa(int(trust.ServePort)) + filesend.LinkPrefix + token
	a.log.Info("file link created", "link", l.ID, "device", l.Device, "hours", req.Hours, "downloads", req.Downloads)
	return panel.FileLinkCreated{Link: linkView(l), URL: url}, nil
}

func (a *Apps) revokeFileLink(id string) error {
	s, err := a.linkStore()
	if err != nil {
		return err
	}
	ok, err := s.Revoke(id)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("böyle bir bağlantı yok")
	}
	return nil
}

// --- antivirus scan (#458) ---

func (a *Apps) scanSettings() avscanSettings {
	var s avscanSettings
	_ = loadJSON(a.appsPath(avscanFn), &s)
	return s
}

type scanRecord struct {
	Name string `json:"name"`
	filesend.ScanResult
}

func (a *Apps) loadScanResults() []scanRecord {
	var r []scanRecord
	_ = loadJSON(a.appsPath(avscanResultsFn), &r)
	return r
}

// scanReceived scans a newly received file when the owner turned it on.
func (a *Apps) scanReceived(f filesend.Received) {
	if !a.scanSettings().Enabled {
		return
	}
	ctx, cancel := context.WithTimeout(a.runContext(), scanTimeout)
	defer cancel()
	if _, err := a.scanInbox(ctx, f.Name); err != nil {
		a.log.Warn("received file scan failed", "error", err.Error())
	}
}

// inboxFile resolves a plain inbox name.
func (a *Apps) inboxFile(name string) (string, error) {
	clean, err := filesend.SanitizeName(name)
	if err != nil || clean != name || strings.ContainsAny(name, `/\`) {
		return "", errors.New("dosya adı geçersiz")
	}
	p := filepath.Join(a.inboxPath(), name)
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("gelen kutusunda böyle bir dosya yok")
	}
	return p, nil
}

func (a *Apps) scanInbox(ctx context.Context, name string) (filesend.ScanResult, error) {
	p, err := a.inboxFile(name)
	if err != nil {
		return filesend.ScanResult{}, err
	}
	st := a.filesP07()
	sc, ok := st.scanner()
	if !ok {
		return filesend.ScanResult{}, errors.New("bu cihazda desteklenen bir antivirüs (Defender veya ClamAV) bulunamadı")
	}
	st.scanMu.Lock()
	res := sc.Scan(ctx, p)
	st.scanMu.Unlock()
	a.stateMu.Lock()
	list := slices.DeleteFunc(a.loadScanResults(), func(r scanRecord) bool { return r.Name == name })
	list = append(list, scanRecord{Name: name, ScanResult: res})
	if len(list) > maxScanResults {
		list = list[len(list)-maxScanResults:]
	}
	err = saveJSON(a.appsPath(avscanResultsFn), list)
	a.stateMu.Unlock()
	if res.Verdict == filesend.VerdictInfected {
		a.log.Warn("antivirus found a threat in a received file", "scanner", res.Scanner, "threat", res.Detail)
	}
	return res, err
}

func (a *Apps) fileScanStatus() panel.FileScanStatus {
	out := panel.FileScanStatus{Enabled: a.scanSettings().Enabled, Results: []panel.FileScanView{}}
	if sc, ok := a.filesP07().scanner(); ok {
		out.Available, out.Scanner, out.CloudNote = true, sc.Name(), sc.CloudNote()
	}
	inbox := a.inboxPath()
	for _, r := range a.loadScanResults() {
		if _, err := os.Lstat(filepath.Join(inbox, r.Name)); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		out.Results = append(out.Results, panel.FileScanView{Name: r.Name, Scanner: r.Scanner, Verdict: r.Verdict, Detail: r.Detail, At: r.At})
	}
	return out
}

func (a *Apps) setFileScan(req panel.FileScanRequest) error {
	if req.Enabled {
		if _, ok := a.filesP07().scanner(); !ok {
			return errors.New("bu cihazda desteklenen bir antivirüs (Defender veya ClamAV) bulunamadı")
		}
	}
	return saveJSON(a.appsPath(avscanFn), avscanSettings{Enabled: req.Enabled})
}

// --- subnet inventory (#442) ---

// knownOUI is a small local table of hardware vendors whose prefixes are
// common on home networks and in labs. Nothing is looked up online.
var knownOUI = map[string]string{
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
	"00:50:56": "VMware",
	"00:0c:29": "VMware",
	"08:00:27": "VirtualBox",
	"52:54:00": "QEMU/KVM",
	"00:15:5d": "Hyper-V",
	"00:16:3e": "Xen",
}

// subnetInventory lists neighbours inside the subnets this device routes.
func subnetInventory(own []netip.Prefix, neigh []edgenet.Neighbor) panel.SubnetInventory {
	out := panel.SubnetInventory{Routed: []string{}, Devices: []panel.SubnetDevice{}}
	for _, p := range own {
		out.Routed = append(out.Routed, p.String())
	}
	for _, n := range neigh {
		i := slices.IndexFunc(own, func(p netip.Prefix) bool { return p.Contains(n.Addr) })
		if i < 0 {
			continue
		}
		mac := strings.ToLower(n.MAC)
		d := panel.SubnetDevice{Addr: n.Addr.String(), MAC: mac, Prefix: own[i].String(), Rule: netip.PrefixFrom(n.Addr, n.Addr.BitLen()).String()}
		if len(mac) >= 8 {
			d.Vendor = knownOUI[mac[:8]]
			if b, err := strconv.ParseUint(mac[:2], 16, 8); err == nil && b&2 != 0 {
				d.RandomMAC = true
			}
		}
		out.Devices = append(out.Devices, d)
	}
	slices.SortFunc(out.Devices, func(x, y panel.SubnetDevice) int {
		return netip.MustParseAddr(x.Addr).Compare(netip.MustParseAddr(y.Addr))
	})
	if len(own) == 0 {
		out.Note = "Bu cihaz alt ağ yönlendirmiyor; envanter yalnızca yönlendirilen alt ağlar için çıkarılır."
	}
	return out
}

// --- Runtime: panel.P07FileControl ---

var _ panel.P07FileControl = (*Runtime)(nil)

// neighborsP07 reads the neighbour table (tests replace it).
var neighborsP07 = edgenet.Neighbors

// FileLinks implements panel.P07FileControl.
func (r *Runtime) FileLinks() (panel.FileLinksStatus, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.FileLinksStatus{}, err
	}
	return a.fileLinks()
}

// CreateFileLink implements panel.P07FileControl.
func (r *Runtime) CreateFileLink(req panel.FileLinkRequest) (panel.FileLinkCreated, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.FileLinkCreated{}, err
	}
	res, err := a.createFileLink(req)
	if err == nil {
		r.auditLocal("file_link_created", fmt.Sprintf("Süreli dosya bağlantısı: %s -> %s (%d saat, %d indirme)", res.Link.Name, res.Link.Device, req.Hours, req.Downloads))
	}
	return res, err
}

// RevokeFileLink implements panel.P07FileControl.
func (r *Runtime) RevokeFileLink(id string) (panel.FileLinksStatus, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.FileLinksStatus{}, err
	}
	if err := a.revokeFileLink(id); err != nil {
		return panel.FileLinksStatus{}, err
	}
	return a.fileLinks()
}

// FileScanStatus implements panel.P07FileControl.
func (r *Runtime) FileScanStatus() (panel.FileScanStatus, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.FileScanStatus{}, err
	}
	return a.fileScanStatus(), nil
}

// SetFileScan implements panel.P07FileControl.
func (r *Runtime) SetFileScan(req panel.FileScanRequest) (panel.FileScanStatus, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.FileScanStatus{}, err
	}
	if err := a.setFileScan(req); err != nil {
		return panel.FileScanStatus{}, err
	}
	return a.fileScanStatus(), nil
}

// ScanInboxFile implements panel.P07FileControl.
func (r *Runtime) ScanInboxFile(ctx context.Context, name string) (panel.FileScanStatus, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.FileScanStatus{}, err
	}
	if _, err := a.scanInbox(ctx, name); err != nil {
		return panel.FileScanStatus{}, err
	}
	return a.fileScanStatus(), nil
}

// SubnetInventory implements panel.P07FileControl.
func (r *Runtime) SubnetInventory() (panel.SubnetInventory, error) {
	e := r.currentEngine()
	if e == nil {
		return panel.SubnetInventory{}, errNoTunnel()
	}
	inv := subnetInventory(e.Routing().Own, neighborsP07())
	if len(inv.Routed) > 0 && len(inv.Devices) == 0 {
		inv.Note = "Komşu tablosunda bu alt ağlardan cihaz yok (tablo yalnızca son konuşulan cihazları tutar)."
	}
	return inv, nil
}

// discoverContainers lists container suggestions (tests replace it).
var discoverContainers = containers.Discover

// ServeSuggestions implements panel.P07FileControl (#441): containers
// with an "openscale.serve" label, as suggestions only.
func (r *Runtime) ServeSuggestions(ctx context.Context) (panel.ServeSuggestions, error) {
	out := panel.ServeSuggestions{Suggestions: []panel.ServeSuggestion{}}
	list, socket, err := discoverContainers(ctx)
	if errors.Is(err, containers.ErrUnsupported) {
		out.Error = "Bu bilgisayarda Docker veya Podman API soketi bulunamadı (Windows'ta desteklenmiyor)."
		return out, nil
	}
	out.Socket = socket
	if err != nil {
		out.Error = err.Error()
		return out, nil
	}
	out.Available = true
	published := map[string]bool{}
	if cfg, err := LoadServeConfig(r.cfg.DataDir); err == nil {
		for _, s := range cfg.Services {
			published[s.Name] = true
		}
	}
	for _, s := range list {
		out.Suggestions = append(out.Suggestions, panel.ServeSuggestion{Container: s.Container, Image: s.Image, Name: s.Name, Type: s.Type,
			Target: s.Target, Problem: s.Problem, Published: published[s.Name]})
	}
	return out, nil
}
