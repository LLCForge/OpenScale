package sysinfo

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Detailed inventory (ADR-0143). The base report (Info) must fit one
// control datagram, so the detailed inventory travels separately: the base
// report only announces its format version (Info.DetailVer) and content
// identifier (Info.DetailID); an admin device that understands the version
// fetches the gzip-compressed JSON in chunks ("infod" control messages)
// and keeps it until the identifier changes. Old admins ignore both
// fields; old devices never announce them.
//
// Privacy (ADR-0008): no serial numbers, UUIDs, full MAC addresses, Wi-Fi
// network names, volume labels or user names are collected. MAC addresses
// are reduced to the vendor prefix (OUI), IPv6 addresses whose interface
// identifier embeds the MAC (EUI-64) to their /64 prefix, and mount points
// under home or removable-media folders lose the folder name.

// DetailVersion is the detailed inventory format this build reads and
// writes. Compatible additions (new omitempty fields) keep the version;
// readers ignore unknown fields. An incompatible change bumps it and older
// readers stop fetching.
const DetailVersion = 1

const (
	// MaxDetailJSON bounds the decompressed detailed inventory.
	MaxDetailJSON = 32 << 10
	// MaxDetailBlob bounds the compressed form fetched in chunks.
	MaxDetailBlob = 16 << 10
	// detailIDLen is the length of DetailID: 96 bits of SHA-256 in hex.
	detailIDLen = 24

	detailHeavyTTL = 15 * time.Minute
	detailLightTTL = 30 * time.Second
	detailStuck    = 5 * time.Minute
	detailBlobKeep = 4

	maxGPUs     = 8
	maxDisks    = 16
	maxVolumes  = 32
	maxNICs     = 16
	maxAddrs    = 8
	maxDisplays = 16
	maxModules  = 32
	maxShort    = 24
)

// Detail is the detailed inventory. Empty strings and zero numbers mean
// "could not be read" unless a field says otherwise.
type Detail struct {
	// Ver is the format version (DetailVersion).
	Ver int `json:"v"`
	// At is when the hardware part was collected (Unix seconds).
	At       int64       `json:"at"`
	OS       OSDetail    `json:"os"`
	CPU      CPUDetail   `json:"cpu"`
	Mem      MemDetail   `json:"mem"`
	Board    BoardDetail `json:"board"`
	GPUs     []GPU       `json:"gpus,omitempty"`
	Disks    []Disk      `json:"disks,omitempty"`
	Volumes  []Volume    `json:"vols,omitempty"`
	NICs     []NIC       `json:"nics,omitempty"`
	Battery  *Battery    `json:"bat,omitempty"`
	Displays []Display   `json:"displays,omitempty"`
	// Users is the number of distinct users with a logon session; -1 when
	// unknown. Names are never collected.
	Users int `json:"users"`
	// Shares are the SMB disk shares this computer offers (ADR-0226):
	// names and comments only. Older readers ignore the field.
	Shares []Share `json:"shares,omitempty"`
}

// OSDetail describes the operating system.
type OSDetail struct {
	// Name is the product name ("Windows 11 Pro", "Ubuntu 24.04.1 LTS",
	// "macOS").
	Name string `json:"name,omitempty"`
	// Version is the release ("26H2", "24.04", "15.1").
	Version string `json:"ver,omitempty"`
	// Build is the build number ("26300.9818", "24B83").
	Build string `json:"build,omitempty"`
	// Edition is the edition ("Professional") and InstallType the
	// installation type ("Client", "Server"); Windows only.
	Edition     string `json:"edition,omitempty"`
	InstallType string `json:"install_type,omitempty"`
	// Channel is the Windows Insider channel, "" for a retail build.
	Channel string `json:"channel,omitempty"`
	// Kernel is the kernel release.
	Kernel string `json:"kernel,omitempty"`
	// Arch is the machine's native architecture (GOARCH names).
	Arch string `json:"arch,omitempty"`
	// Installed and Boot are Unix seconds; Installed is approximate on
	// Linux (root file system creation time).
	Installed int64 `json:"installed,omitempty"`
	Boot      int64 `json:"boot,omitempty"`
	// TZ is the time zone name ("Europe/Istanbul", "Turkey Standard
	// Time"), TZOffset its current offset east of UTC in seconds.
	TZ       string `json:"tz,omitempty"`
	TZOffset int    `json:"tz_offset"`
}

// CPUDetail describes the processor(s).
type CPUDetail struct {
	Model   string `json:"model,omitempty"`
	Sockets int    `json:"sockets,omitempty"`
	// Cores is the number of physical cores, Threads of logical ones.
	Cores   int `json:"cores,omitempty"`
	Threads int `json:"threads,omitempty"`
	BaseMHz int `json:"base_mhz,omitempty"`
	MaxMHz  int `json:"max_mhz,omitempty"`
	// Virt is hardware virtualization: "on" (available to this system),
	// "off" (missing or disabled in firmware), "hv" (a hypervisor runs;
	// this system is its guest or root partition), "" unknown.
	Virt string `json:"virt,omitempty"`
}

// MemDetail describes the installed memory. Used memory is in the base
// report (MemTotal, MemFree), which is refreshed on every query.
type MemDetail struct {
	Total uint64 `json:"total,omitempty"`
	// Slots is the number of memory slots, Modules the populated ones.
	Slots   int         `json:"slots,omitempty"`
	Modules []MemModule `json:"modules,omitempty"`
}

// MemModule is one installed memory module.
type MemModule struct {
	Size uint64 `json:"size,omitempty"`
	// Type is the memory technology ("DDR5", "LPDDR5").
	Type string `json:"type,omitempty"`
	// MHz is the configured speed in MT/s.
	MHz  int    `json:"mhz,omitempty"`
	Form string `json:"form,omitempty"`
}

// BoardDetail describes the system, board and firmware.
type BoardDetail struct {
	Vendor      string `json:"vendor,omitempty"`
	Model       string `json:"model,omitempty"`
	BoardVendor string `json:"board_vendor,omitempty"`
	BoardModel  string `json:"board_model,omitempty"`
	BIOSVendor  string `json:"bios_vendor,omitempty"`
	BIOSVersion string `json:"bios_ver,omitempty"`
	// BIOSDate is "YYYY-MM-DD".
	BIOSDate string `json:"bios_date,omitempty"`
	// Firmware is "uefi" or "bios".
	Firmware string `json:"fw,omitempty"`
	// SecureBoot is "on", "off" or "unsupported" (legacy BIOS).
	SecureBoot string `json:"secure_boot,omitempty"`
	// TPM is "2.0", "1.2" or "none"; TPMVendor the manufacturer code
	// ("INTC", "AMD", "IFX").
	TPM       string `json:"tpm,omitempty"`
	TPMVendor string `json:"tpm_vendor,omitempty"`
}

// GPU is one display adapter.
type GPU struct {
	Model  string `json:"model,omitempty"`
	Driver string `json:"driver,omitempty"`
	// VRAM is the dedicated video memory in bytes.
	VRAM uint64 `json:"vram,omitempty"`
}

// Disk is one physical (or virtual) disk.
type Disk struct {
	// Index is the system's disk number (PhysicalDriveN on Windows, the
	// order of /sys/block on Linux); volumes refer to it.
	Index int    `json:"idx"`
	Model string `json:"model,omitempty"`
	// Type is "nvme", "ssd" or "hdd".
	Type string `json:"type,omitempty"`
	// Bus is the attachment ("nvme", "sata", "usb", "virtual", ...).
	Bus       string `json:"bus,omitempty"`
	Size      uint64 `json:"size,omitempty"`
	Removable bool   `json:"removable,omitempty"`
}

// Volume is one mounted file system.
type Volume struct {
	// Mount is the drive letter ("C:") or mount point ("/", "/home/*").
	Mount string `json:"mount"`
	FS    string `json:"fs,omitempty"`
	Size  uint64 `json:"size,omitempty"`
	Free  uint64 `json:"free,omitempty"`
	// Encrypted is "on" (BitLocker, LUKS), "off" or "" unknown.
	Encrypted string `json:"enc,omitempty"`
	Removable bool   `json:"removable,omitempty"`
	// Disk is the Disk.Index holding the volume, -1 when unknown.
	Disk int `json:"disk"`
}

// NIC is one network adapter.
type NIC struct {
	Name  string `json:"name,omitempty"`
	Model string `json:"model,omitempty"`
	// Type is "wifi", "ethernet", "virtual", "cellular", "bluetooth" or
	// "other".
	Type string `json:"type,omitempty"`
	// OUI is the MAC address's vendor prefix ("aa:bb:cc"); the rest of the
	// address is never sent. RandomMAC is true for a locally administered
	// (randomized) address, whose prefix names no vendor.
	OUI       string `json:"oui,omitempty"`
	RandomMAC bool   `json:"mac_random,omitempty"`
	Up        bool   `json:"up,omitempty"`
	// Speed is the link speed in Mbit/s.
	Speed uint64   `json:"speed,omitempty"`
	IPv4  []string `json:"ipv4,omitempty"`
	// IPv6 lists addresses, or "prefix::/64" when the address embeds the
	// MAC (EUI-64). Link-local addresses are left out.
	IPv6 []string `json:"ipv6,omitempty"`
	// Gateway is true when a default route uses this adapter.
	Gateway bool `json:"gw,omitempty"`
	// Signal is the Wi-Fi signal quality in percent (0 unknown); WiFiStd
	// the PHY standard ("802.11ax"). The network name is never sent.
	Signal  int    `json:"signal,omitempty"`
	WiFiStd string `json:"wifi_std,omitempty"`
}

// Battery is the system battery.
type Battery struct {
	Percent int `json:"pct"`
	// State is "charging", "discharging", "full" or "ac" (plugged in,
	// not charging).
	State string `json:"state,omitempty"`
	// DesignMWh and FullMWh are the design and current full-charge
	// capacities in mWh (0 when only a ratio is known).
	DesignMWh uint64 `json:"design_mwh,omitempty"`
	FullMWh   uint64 `json:"full_mwh,omitempty"`
	// Health is the full-charge capacity as a percentage of the design.
	Health int `json:"health,omitempty"`
	Cycles int `json:"cycles,omitempty"`
}

// Display is one connected monitor with its native (preferred) mode.
type Display struct {
	Name string `json:"name,omitempty"`
	W    int    `json:"w"`
	H    int    `json:"h"`
	Hz   int    `json:"hz,omitempty"`
}

// newDetail returns a detail with the values every platform knows.
func newDetail(now time.Time) *Detail {
	_, off := now.Zone()
	d := &Detail{Ver: DetailVersion, At: now.Unix(), Users: -1}
	d.OS.Arch = runtime.GOARCH
	d.OS.TZOffset = off
	d.CPU.Threads = runtime.NumCPU()
	return d
}

// CollectDetail gathers the detailed inventory now. It may take seconds
// (Windows disk queries, macOS system_profiler) and never fails: parts
// that cannot be read stay empty, and a panic in a collector only empties
// that part.
func CollectDetail(now time.Time) *Detail {
	d := newDetail(now)
	safely(func() { collectDetail(d) })
	safely(func() { collectShares(d) })
	safely(func() { collectLight(d) })
	d.sanitize()
	return d
}

// safely runs fn and swallows a panic: the inventory is display data and
// must never take the service down.
func safely(fn func()) {
	defer func() { _ = recover() }()
	fn()
}

type detailBlob struct {
	id   string
	json []byte
	gz   []byte
}

var detailState struct {
	mu           sync.Mutex
	heavy        *Detail
	heavyAt      time.Time
	refreshing   bool
	refreshStart time.Time
	light        Detail
	lightAt      time.Time
	blobs        []detailBlob
}

// cachedDetail returns a copy of the cached inventory with fresh light
// fields (battery charge, logged-on users) and its identifier. It never
// blocks on the slow collectors: the first call starts a background
// collection and returns nil.
func cachedDetail(now time.Time) (*Detail, string) {
	st := &detailState
	st.mu.Lock()
	stale := st.heavy == nil || now.Sub(st.heavyAt) > detailHeavyTTL || now.Before(st.heavyAt)
	if stale && (!st.refreshing || now.Sub(st.refreshStart) > detailStuck) {
		st.refreshing, st.refreshStart = true, now
		go refreshDetail()
	}
	heavy := st.heavy
	needLight := heavy != nil && (st.lightAt.IsZero() || now.Sub(st.lightAt) > detailLightTTL || now.Before(st.lightAt))
	st.mu.Unlock()
	if heavy == nil {
		return nil, ""
	}
	if needLight {
		l := Detail{Users: -1}
		safely(func() { collectLight(&l) })
		st.mu.Lock()
		st.light, st.lightAt = l, now
		st.mu.Unlock()
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	d := *st.heavy
	d.Users = st.light.Users
	if b := st.light.Battery; b != nil && d.Battery != nil {
		bat := *d.Battery
		bat.Percent, bat.State = b.Percent, b.State
		d.Battery = &bat
	} else if b != nil {
		bat := *b
		d.Battery = &bat
	}
	return publishDetailLocked(&d)
}

// publishDetailLocked encodes d, keeps it for DetailChunk unless it equals
// the newest kept snapshot, and returns an independent copy and its
// identifier. detailState.mu must be held.
func publishDetailLocked(d *Detail) (*Detail, string) {
	st := &detailState
	d.sanitize()
	data, err := json.Marshal(d)
	if err == nil && len(data) > MaxDetailJSON && len(d.Shares) > 0 {
		// The share list is the most optional part (ADR-0226).
		d.Shares = nil
		data, err = json.Marshal(d)
	}
	if err != nil || len(data) > MaxDetailJSON {
		return nil, ""
	}
	if len(st.blobs) == 0 || !bytes.Equal(st.blobs[0].json, data) {
		gz, err := gzipBytes(data)
		if err == nil && len(gz) > MaxDetailBlob && len(d.Shares) > 0 {
			d.Shares = nil
			if data, err = json.Marshal(d); err == nil {
				gz, err = gzipBytes(data)
			}
		}
		if err != nil || len(gz) > MaxDetailBlob {
			return nil, ""
		}
		b := detailBlob{id: detailID(data), json: data, gz: gz}
		st.blobs = append([]detailBlob{b}, st.blobs...)
		if len(st.blobs) > detailBlobKeep {
			st.blobs = st.blobs[:detailBlobKeep]
		}
	}
	out := new(Detail)
	if json.Unmarshal(st.blobs[0].json, out) != nil {
		return nil, ""
	}
	return out, st.blobs[0].id
}

func refreshDetail() {
	var d *Detail
	defer func() {
		_ = recover()
		st := &detailState
		st.mu.Lock()
		if d != nil {
			st.heavy, st.heavyAt = d, time.Now()
		}
		st.refreshing = false
		st.mu.Unlock()
	}()
	now := time.Now()
	h := newDetail(now)
	safely(func() { collectDetail(h) })
	safely(func() { collectShares(h) })
	h.sanitize()
	d = h
}

func detailID(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:detailIDLen]
}

func gzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DetailChunk returns up to size bytes at offset of the compressed
// inventory identified by id, its total length and its identifier. When id
// is no longer held (the inventory changed), the newest one is served and
// the returned identifier tells the caller to start over. ok is false when
// there is nothing to serve or the offset is out of range.
func DetailChunk(id string, offset, size int) (chunk []byte, total int, cur string, ok bool) {
	st := &detailState
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.blobs) == 0 || size <= 0 || offset < 0 {
		return nil, 0, "", false
	}
	b := st.blobs[0]
	for _, x := range st.blobs {
		if x.id == id {
			b = x
			break
		}
	}
	if b.id != id {
		offset = 0
	}
	if offset > len(b.gz) {
		return nil, 0, "", false
	}
	end := min(offset+size, len(b.gz))
	return bytes.Clone(b.gz[offset:end]), len(b.gz), b.id, true
}

// DecodeDetail decompresses and checks an inventory fetched from another
// computer. The identifier must match the content, so chunks of two
// different snapshots are never mixed. Text is cleaned like the base
// report's.
func DecodeDetail(blob []byte, id string) (*Detail, error) {
	if len(blob) > MaxDetailBlob {
		return nil, errors.New("detailed inventory too large")
	}
	if !ValidDetailID(id) {
		return nil, errors.New("bad inventory identifier")
	}
	zr, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(zr, MaxDetailJSON+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxDetailJSON {
		return nil, errors.New("detailed inventory too large")
	}
	if detailID(data) != id {
		return nil, errors.New("detailed inventory does not match its identifier")
	}
	var d Detail
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	if d.Ver < 1 {
		return nil, fmt.Errorf("unsupported inventory version %d", d.Ver)
	}
	d.sanitize()
	return &d, nil
}

// ValidDetailID reports whether s has the form of Info.DetailID.
func ValidDetailID(s string) bool {
	if len(s) != detailIDLen {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// DetailCache keeps the inventories an admin device fetched, by peer, so
// an unchanged inventory is not fetched again.
type DetailCache struct {
	mu      sync.Mutex
	max     int
	entries map[string]detailCacheEntry
}

type detailCacheEntry struct {
	id string
	d  *Detail
	at time.Time
}

// NewDetailCache returns a cache holding at most max peers.
func NewDetailCache(max int) *DetailCache {
	return &DetailCache{max: max, entries: map[string]detailCacheEntry{}}
}

// Get returns the cached inventory of key and whether its identifier is id.
func (c *DetailCache) Get(key, id string) (*Detail, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	return e.d, e.id == id
}

// Put stores key's inventory, evicting the oldest entry when full.
func (c *DetailCache) Put(key, id string, d *Detail, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok && len(c.entries) >= c.max {
		oldest := ""
		var at time.Time
		for k, e := range c.entries {
			if oldest == "" || e.at.Before(at) {
				oldest, at = k, e.at
			}
		}
		delete(c.entries, oldest)
	}
	c.entries[key] = detailCacheEntry{id: id, d: d, at: now}
}

// ---- sanitizing ----

func (d *Detail) sanitize() {
	if d.Ver < 0 || d.Ver > 1000 {
		d.Ver = 0
	}
	d.At = clampTime(d.At)
	if d.Users < -1 || d.Users > 100000 {
		d.Users = -1
	}
	o := &d.OS
	for _, p := range []*string{&o.Name, &o.Version, &o.Build, &o.Edition, &o.InstallType, &o.Channel, &o.Kernel, &o.TZ} {
		*p = cleanText(*p)
	}
	o.Arch = shortText(o.Arch)
	o.Installed, o.Boot = clampTime(o.Installed), clampTime(o.Boot)
	if o.TZOffset < -14*3600 || o.TZOffset > 14*3600 {
		o.TZOffset = 0
	}
	c := &d.CPU
	c.Model = cleanText(c.Model)
	c.Sockets = clampInt(c.Sockets, 0, 1024)
	c.Cores = clampInt(c.Cores, 0, 1<<16)
	c.Threads = clampInt(c.Threads, 0, 1<<16)
	c.BaseMHz = clampInt(c.BaseMHz, 0, 20000)
	c.MaxMHz = clampInt(c.MaxMHz, 0, 20000)
	c.Virt = oneOf(c.Virt, "on", "off", "hv")
	m := &d.Mem
	m.Total = min(m.Total, 1<<52)
	m.Slots = clampInt(m.Slots, 0, 1024)
	m.Modules = m.Modules[:min(len(m.Modules), maxModules)]
	for i := range m.Modules {
		x := &m.Modules[i]
		x.Size = min(x.Size, 1<<44)
		x.Type, x.Form = shortText(x.Type), shortText(x.Form)
		x.MHz = clampInt(x.MHz, 0, 100000)
	}
	b := &d.Board
	for _, p := range []*string{&b.Vendor, &b.Model, &b.BoardVendor, &b.BoardModel, &b.BIOSVendor, &b.BIOSVersion} {
		*p = cleanText(*p)
	}
	if !validDate(b.BIOSDate) {
		b.BIOSDate = ""
	}
	b.Firmware = oneOf(b.Firmware, "uefi", "bios")
	b.SecureBoot = oneOf(b.SecureBoot, "on", "off", "unsupported")
	b.TPM = oneOf(b.TPM, "2.0", "1.2", "none")
	b.TPMVendor = shortText(b.TPMVendor)
	d.GPUs = d.GPUs[:min(len(d.GPUs), maxGPUs)]
	for i := range d.GPUs {
		g := &d.GPUs[i]
		g.Model, g.Driver = cleanText(g.Model), shortText(g.Driver)
		g.VRAM = min(g.VRAM, 1<<44)
	}
	d.Disks = d.Disks[:min(len(d.Disks), maxDisks)]
	for i := range d.Disks {
		k := &d.Disks[i]
		k.Index = clampInt(k.Index, 0, 1<<16)
		k.Model = cleanText(k.Model)
		k.Type = oneOf(k.Type, "nvme", "ssd", "hdd")
		k.Bus = oneOf(k.Bus, "nvme", "sata", "ata", "usb", "sas", "scsi", "raid", "mmc", "sd", "virtual", "virtio", "spaces", "ufs", "firewire", "iscsi", "fibre", "other")
		k.Size = min(k.Size, 1<<56)
	}
	d.Volumes = d.Volumes[:min(len(d.Volumes), maxVolumes)]
	for i := range d.Volumes {
		v := &d.Volumes[i]
		v.Mount = cleanText(MaskMount(v.Mount))
		v.FS = shortText(v.FS)
		v.Size = min(v.Size, 1<<56)
		v.Free = min(v.Free, v.Size)
		v.Encrypted = oneOf(v.Encrypted, "on", "off")
		v.Disk = clampInt(v.Disk, -1, 1<<16)
	}
	d.NICs = d.NICs[:min(len(d.NICs), maxNICs)]
	for i := range d.NICs {
		n := &d.NICs[i]
		n.Name, n.Model = cleanText(n.Name), cleanText(n.Model)
		n.Type = oneOf(n.Type, "wifi", "ethernet", "virtual", "cellular", "bluetooth", "other")
		if !validOUI(n.OUI) {
			n.OUI = ""
		}
		n.Speed = min(n.Speed, 10_000_000)
		n.IPv4 = cleanAddrs(n.IPv4, true)
		n.IPv6 = cleanAddrs(n.IPv6, false)
		n.Signal = clampInt(n.Signal, 0, 100)
		n.WiFiStd = oneOf(n.WiFiStd, "802.11a", "802.11b", "802.11g", "802.11n", "802.11ac", "802.11ad", "802.11ax", "802.11be")
	}
	if t := d.Battery; t != nil {
		t.Percent = clampInt(t.Percent, 0, 100)
		t.State = oneOf(t.State, "charging", "discharging", "full", "ac")
		t.DesignMWh, t.FullMWh = min(t.DesignMWh, 1<<32), min(t.FullMWh, 1<<32)
		t.Health = clampInt(t.Health, 0, 200)
		t.Cycles = clampInt(t.Cycles, 0, 1000000)
	}
	d.Shares = normalizeShares(d.Shares)
	d.Displays = d.Displays[:min(len(d.Displays), maxDisplays)]
	for i := range d.Displays {
		p := &d.Displays[i]
		p.Name = cleanText(p.Name)
		p.W, p.H = clampInt(p.W, 0, 1<<15), clampInt(p.H, 0, 1<<15)
		p.Hz = clampInt(p.Hz, 0, 1000)
	}
}

func clampInt(v, lo, hi int) int {
	if v < lo || v > hi {
		if lo < 0 {
			return lo
		}
		return 0
	}
	return v
}

func clampTime(t int64) int64 {
	if t < 0 || t > 1<<40 {
		return 0
	}
	return t
}

func oneOf(s string, allowed ...string) string {
	for _, a := range allowed {
		if s == a {
			return s
		}
	}
	return ""
}

func shortText(s string) string {
	s = cleanText(s)
	if len(s) > maxShort {
		s = s[:maxShort]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

func validDate(s string) bool {
	if s == "" {
		return true
	}
	t, err := time.Parse("2006-01-02", s)
	return err == nil && t.Year() >= 1980 && t.Year() < 2200
}

func validOUI(s string) bool {
	if len(s) != 8 || s[2] != ':' || s[5] != ':' {
		return false
	}
	for i, r := range s {
		if i == 2 || i == 5 {
			continue
		}
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// OUI returns the vendor prefix of a 48-bit MAC address and whether the
// address is locally administered (randomized). Only the first three
// octets ever leave the computer (ADR-0008).
func OUI(mac []byte) (string, bool) {
	if len(mac) != 6 {
		return "", false
	}
	zero := true
	for _, b := range mac {
		if b != 0 {
			zero = false
		}
	}
	if zero || mac[0]&0x01 != 0 {
		return "", false
	}
	return fmt.Sprintf("%02x:%02x:%02x", mac[0], mac[1], mac[2]), mac[0]&0x02 != 0
}

// PrivateIPv6 returns the form of an IPv6 address that may be reported:
// "" for link-local, loopback and unspecified addresses, the /64 prefix
// when the interface identifier is EUI-64 (it embeds the MAC), the address
// otherwise.
func PrivateIPv6(a netip.Addr) string {
	a = a.WithZone("")
	if !a.Is6() || a.Is4In6() || a.IsLinkLocalUnicast() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
		return ""
	}
	b := a.As16()
	if b[11] == 0xff && b[12] == 0xfe {
		return netip.PrefixFrom(a, 64).Masked().String()
	}
	return a.String()
}

func cleanAddrs(in []string, v4 bool) []string {
	var out []string
	for _, s := range in {
		if len(out) >= maxAddrs {
			break
		}
		if v4 {
			if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
				out = append(out, a.String())
			}
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is6() && p.Bits() == 64 && p.Masked() == p {
			out = append(out, p.String())
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			if r := PrivateIPv6(a); r != "" {
				out = append(out, r)
			}
		}
	}
	return out
}

// MaskMount hides the folder name of mount points under home and
// removable-media folders, which are usually user or volume names.
func MaskMount(m string) string {
	for _, p := range []string{"/run/media/", "/media/", "/home/", "/Users/", "/Volumes/"} {
		if strings.HasPrefix(m, p) && len(m) > len(p) {
			return p + "*"
		}
	}
	return m
}

// virtualDiskModel recognises the disk models hypervisors present.
func virtualDiskModel(model string) bool {
	m := strings.ToLower(model)
	for _, s := range []string{"virtual disk", "qemu", "vbox", "vmware", "virtio"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// EncodeDetail returns the compressed form of a (sanitized copy of) d and
// its identifier, as DetailChunk serves it and DecodeDetail reads it.
func EncodeDetail(d Detail) ([]byte, string, error) {
	d.sanitize()
	data, err := json.Marshal(&d)
	if err != nil {
		return nil, "", err
	}
	if len(data) > MaxDetailJSON {
		return nil, "", errors.New("detailed inventory too large")
	}
	gz, err := gzipBytes(data)
	if err != nil {
		return nil, "", err
	}
	if len(gz) > MaxDetailBlob {
		return nil, "", errors.New("detailed inventory too large")
	}
	return gz, detailID(data), nil
}
