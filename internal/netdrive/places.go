package netdrive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/sysinfo"
)

// Network locations (ADR-0226): the SMB shares other devices list in their
// detailed inventory appear in Windows Explorer under "Ağdaki konumlar"
// ("Network locations") on an admin device, without a drive letter. A
// network location is a folder in the user's Network Shortcuts folder
// holding a desktop.ini that marks it as a folder shortcut and a
// target.lnk pointing at \\<device>.<network domain>\<share>, the
// device's MagicDNS name, so the connection goes through the tunnel.
// Credentials never pass through OpenScale: Windows asks for them itself
// when the share is opened.
//
// OpenScale manages only the locations it made. Each one is recorded with
// the SHA-256 of the target.lnk it wrote; a folder is removed only when it
// still holds exactly the two files OpenScale wrote, with the same
// contents. A location the user made, renamed, changed or deleted is
// never touched (a deleted one is not made again until the feature is
// turned off and on).

// MaxPlaces bounds the locations OpenScale makes.
const MaxPlaces = 256

// File names inside a network location folder.
const (
	placeIni  = "desktop.ini"
	placeLink = "target.lnk"
)

// placeIniText marks the folder as a folder shortcut (CLSID_FolderShortcut)
// exactly as Explorer writes it for "Add a network location".
const placeIniText = "[.ShellClassInfo]\r\nCLSID2={0AFACED1-E828-11D1-9187-B532F1E9575D}\r\nFlags=2\r\n"

const (
	maxPlaceRecord  = 256 << 10
	placeRecordVer  = 1
	maxPlaceHostLen = 253
)

// PlaceDevice is one device of the signed document with the shares its
// last detailed inventory listed.
type PlaceDevice struct {
	// Name is the device name (a lowercase DNS label).
	Name string `json:"name"`
	// Host is its MagicDNS name, device.domain.
	Host string `json:"host"`
	// Known is true when an inventory of the device is at hand; the
	// locations of a device that is not known are kept as they are.
	Known  bool            `json:"known"`
	Shares []sysinfo.Share `json:"shares,omitempty"`
}

// PlaceEntry is one location OpenScale made.
type PlaceEntry struct {
	Folder string `json:"folder"`
	Device string `json:"device"`
	Share  string `json:"share"`
	Target string `json:"target"`
	// LinkSHA256 is the digest of the target.lnk OpenScale wrote.
	LinkSHA256 string `json:"link_sha256"`
	// Dismissed is true when the user deleted the location: it is not
	// made again.
	Dismissed bool `json:"dismissed,omitempty"`
}

type placeRecord struct {
	Schema  int          `json:"schema"`
	Entries []PlaceEntry `json:"entries"`
}

// PlaceResult says what one run changed.
type PlaceResult struct {
	Added   []string
	Removed []string
	// Conflicts are folders that exist but are not OpenScale's.
	Conflicts []string
	Errors    []error
}

// Places manages the network locations of one user.
type Places struct {
	// Dir is the user's Network Shortcuts folder.
	Dir string
	// RecordPath is the file listing the locations OpenScale made.
	RecordPath string
	// WriteLink writes a shell link at path to target (winapp.WriteLink
	// on Windows).
	WriteLink func(path, target, description string) error
	// SetAttrs and ClearAttrs set and remove the attributes Explorer
	// needs (read-only folder, hidden system desktop.ini); nil uses the
	// platform's.
	SetAttrs   func(dir, ini string) error
	ClearAttrs func(dir string)
	// Changed tells Explorer the folder changed; nil uses the
	// platform's.
	Changed func(dir string)
}

// validLabel reports whether s is a lowercase DNS label (RFC 1123).
func validLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func validHost(s string) bool {
	if len(s) > maxPlaceHostLen {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 3 { // device.network.domain at least
		return false
	}
	return !slices.ContainsFunc(labels, func(l string) bool { return !validLabel(l) })
}

// PlaceTarget returns \\host\share after checking both parts. The host
// must be a lowercase DNS name with the device as its first label.
func PlaceTarget(device, host, share string) (string, error) {
	if !validLabel(device) {
		return "", fmt.Errorf("cihaz adı geçersiz: %q", device)
	}
	if !validHost(host) || !strings.HasPrefix(host, device+".") {
		return "", fmt.Errorf("cihazın ağ adı geçersiz: %q", host)
	}
	if !sysinfo.ValidShareName(share) {
		return "", fmt.Errorf("paylaşım adı geçersiz: %q", share)
	}
	return `\\` + host + `\` + share, nil
}

// PlaceFolder returns the folder name "<share> (<device>)".
func PlaceFolder(share, device string) (string, error) {
	if !validLabel(device) || !sysinfo.ValidShareName(share) {
		return "", errors.New("ağ konumu adı geçersiz")
	}
	return share + " (" + device + ")", nil
}

// folderPath joins name to p.Dir and makes sure the result is a direct
// child of it.
func (p *Places) folderPath(name string) (string, error) {
	if p.Dir == "" || !filepath.IsAbs(p.Dir) {
		return "", errors.New("ağ konumları klasörü bilinmiyor")
	}
	dir := filepath.Clean(p.Dir)
	full := filepath.Join(dir, name)
	if filepath.Dir(full) != dir || filepath.Base(full) != name {
		return "", fmt.Errorf("ağ konumu adı geçersiz: %q", name)
	}
	return full, nil
}

func placeKey(device, share string) string { return device + "\x00" + strings.ToLower(share) }

type wantedPlace struct {
	device, share, comment, target, folder string
}

// Sync makes the locations of devs that do not exist yet and removes the
// ones OpenScale made whose device left the document or whose share is
// no longer listed.
func (p *Places) Sync(devs []PlaceDevice) (PlaceResult, error) {
	var res PlaceResult
	rec, err := p.load()
	if err != nil {
		return res, err
	}
	byDev := map[string]PlaceDevice{}
	want := map[string]wantedPlace{}
	for _, d := range devs {
		if !validLabel(d.Name) {
			continue
		}
		byDev[d.Name] = d
		if !d.Known {
			continue
		}
		for _, s := range d.Shares {
			target, err := PlaceTarget(d.Name, d.Host, s.Name)
			if err != nil {
				continue
			}
			folder, err := PlaceFolder(s.Name, d.Name)
			if err != nil {
				continue
			}
			want[placeKey(d.Name, s.Name)] = wantedPlace{device: d.Name, share: s.Name, comment: s.Comment, target: target, folder: folder}
		}
	}
	changed := false
	var kept []PlaceEntry
	for _, e := range rec.Entries {
		d, inDoc := byDev[e.Device]
		w, wanted := want[placeKey(e.Device, e.Share)]
		keep := inDoc && (!d.Known || (wanted && w.target == e.Target && w.folder == e.Folder))
		state := p.inspect(e)
		if !keep {
			changed = true
			if state == placeOurs {
				if err := p.remove(e); err != nil {
					res.Errors = append(res.Errors, err)
					kept = append(kept, e) // try again next time
					continue
				}
				res.Removed = append(res.Removed, e.Folder)
			}
			continue
		}
		delete(want, placeKey(e.Device, e.Share))
		switch {
		case e.Dismissed:
		case state == placeMissing:
			e.Dismissed, changed = true, true
		case state == placeForeign:
			// The user changed it; it is theirs now.
			changed = true
			continue
		}
		kept = append(kept, e)
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		w := want[k]
		if len(kept) >= MaxPlaces {
			break
		}
		if slices.ContainsFunc(kept, func(e PlaceEntry) bool { return strings.EqualFold(e.Folder, w.folder) }) {
			continue
		}
		e, err := p.create(w)
		switch {
		case errors.Is(err, fs.ErrExist):
			res.Conflicts = append(res.Conflicts, w.folder)
		case err != nil:
			res.Errors = append(res.Errors, err)
		default:
			kept = append(kept, e)
			res.Added = append(res.Added, e.Folder)
			changed = true
		}
	}
	if changed {
		rec.Entries = kept
		if err := p.save(rec); err != nil {
			res.Errors = append(res.Errors, err)
		}
	}
	if len(res.Added)+len(res.Removed) > 0 {
		p.changed()
	}
	return res, nil
}

// RemoveAll removes every location OpenScale made and still owns, and
// forgets the record (the feature was turned off).
func (p *Places) RemoveAll() (PlaceResult, error) {
	var res PlaceResult
	rec, err := p.load()
	if err != nil {
		return res, err
	}
	var left []PlaceEntry
	for _, e := range rec.Entries {
		if e.Dismissed || p.inspect(e) != placeOurs {
			continue
		}
		if err := p.remove(e); err != nil {
			res.Errors = append(res.Errors, err)
			left = append(left, e)
			continue
		}
		res.Removed = append(res.Removed, e.Folder)
	}
	if len(left) > 0 {
		rec.Entries = left
		if err := p.save(rec); err != nil {
			res.Errors = append(res.Errors, err)
		}
	} else if err := os.Remove(p.RecordPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		res.Errors = append(res.Errors, err)
	}
	if len(res.Removed) > 0 {
		p.changed()
	}
	return res, nil
}

// Owned lists the locations OpenScale made.
func (p *Places) Owned() ([]PlaceEntry, error) {
	rec, err := p.load()
	return rec.Entries, err
}

type placeState int

const (
	placeMissing placeState = iota
	placeOurs
	placeForeign
)

// inspect tells whether e's folder is gone, still exactly what OpenScale
// wrote, or something else.
func (p *Places) inspect(e PlaceEntry) placeState {
	full, err := p.folderPath(e.Folder)
	if err != nil {
		return placeForeign
	}
	fi, err := os.Lstat(full)
	if errors.Is(err, fs.ErrNotExist) {
		return placeMissing
	}
	if err != nil || !fi.IsDir() || fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return placeForeign
	}
	entries, err := os.ReadDir(full)
	if err != nil || len(entries) != 2 {
		return placeForeign
	}
	for _, x := range entries {
		if !x.Type().IsRegular() || (x.Name() != placeIni && x.Name() != placeLink) {
			return placeForeign
		}
	}
	ini, err := readSmall(filepath.Join(full, placeIni), 4<<10)
	if err != nil || string(ini) != placeIniText {
		return placeForeign
	}
	lnk, err := readSmall(filepath.Join(full, placeLink), 64<<10)
	if err != nil || digest(lnk) != e.LinkSHA256 {
		return placeForeign
	}
	return placeOurs
}

func (p *Places) create(w wantedPlace) (PlaceEntry, error) {
	if p.WriteLink == nil {
		return PlaceEntry{}, ErrUnsupported
	}
	full, err := p.folderPath(w.folder)
	if err != nil {
		return PlaceEntry{}, err
	}
	if err := os.MkdirAll(filepath.Clean(p.Dir), 0o700); err != nil {
		return PlaceEntry{}, err
	}
	if err := os.Mkdir(full, 0o700); err != nil {
		return PlaceEntry{}, err // fs.ErrExist: the user's folder
	}
	ini := filepath.Join(full, placeIni)
	lnk := filepath.Join(full, placeLink)
	undo := func() {
		p.clearAttrs(full)
		_ = os.Remove(ini)
		_ = os.Remove(lnk)
		_ = os.Remove(full)
	}
	f, err := os.OpenFile(ini, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		undo()
		return PlaceEntry{}, err
	}
	_, werr := f.WriteString(placeIniText)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		undo()
		return PlaceEntry{}, werr
	}
	desc := "OpenScale: " + w.device
	if w.comment != "" {
		desc += " - " + w.comment
	}
	if err := p.WriteLink(lnk, w.target, desc); err != nil {
		undo()
		return PlaceEntry{}, fmt.Errorf("%s kısayolu yazılamadı: %w", w.folder, err)
	}
	data, err := readSmall(lnk, 64<<10)
	if err != nil {
		undo()
		return PlaceEntry{}, err
	}
	if err := p.setAttrs(full, ini); err != nil {
		undo()
		return PlaceEntry{}, err
	}
	return PlaceEntry{Folder: w.folder, Device: w.device, Share: w.share, Target: w.target, LinkSHA256: digest(data)}, nil
}

// remove deletes the two files OpenScale wrote and the folder; nothing
// else is ever deleted (no RemoveAll).
func (p *Places) remove(e PlaceEntry) error {
	full, err := p.folderPath(e.Folder)
	if err != nil {
		return err
	}
	p.clearAttrs(full)
	for _, name := range []string{placeIni, placeLink} {
		if err := os.Remove(filepath.Join(full, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s kaldırılamadı: %w", e.Folder, err)
		}
	}
	if err := os.Remove(full); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s kaldırılamadı: %w", e.Folder, err)
	}
	return nil
}

func (p *Places) setAttrs(dir, ini string) error {
	if p.SetAttrs != nil {
		return p.SetAttrs(dir, ini)
	}
	return setPlaceAttrs(dir, ini)
}

func (p *Places) clearAttrs(dir string) {
	if p.ClearAttrs != nil {
		p.ClearAttrs(dir)
		return
	}
	clearPlaceAttrs(dir)
}

func (p *Places) changed() {
	if p.Changed != nil {
		p.Changed(p.Dir)
		return
	}
	shellChanged(p.Dir)
}

func (p *Places) load() (placeRecord, error) {
	rec := placeRecord{Schema: placeRecordVer}
	if p.RecordPath == "" {
		return rec, errors.New("ağ konumu kaydı bilinmiyor")
	}
	data, err := readSmall(p.RecordPath, maxPlaceRecord)
	if errors.Is(err, fs.ErrNotExist) {
		return rec, nil
	}
	if err != nil {
		return rec, fmt.Errorf("ağ konumu kaydı okunamadı: %w", err)
	}
	if err := json.Unmarshal(data, &rec); err != nil || rec.Schema != placeRecordVer || len(rec.Entries) > MaxPlaces {
		return placeRecord{Schema: placeRecordVer}, errors.New("ağ konumu kaydı bozuk")
	}
	// A record entry must name a folder this code could have made.
	rec.Entries = slices.DeleteFunc(rec.Entries, func(e PlaceEntry) bool {
		f, err := PlaceFolder(e.Share, e.Device)
		return err != nil || f != e.Folder
	})
	return rec, nil
}

func (p *Places) save(rec placeRecord) error {
	rec.Schema = placeRecordVer
	if rec.Entries == nil {
		rec.Entries = []PlaceEntry{}
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.RecordPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".netplaces-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	if serr := tmp.Sync(); werr == nil {
		werr = serr
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(name)
		return werr
	}
	if err := os.Rename(name, p.RecordPath); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

func readSmall(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // paths are built by Places
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("dosya çok büyük")
	}
	return data, nil
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
