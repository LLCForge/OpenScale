package syncdir

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

// Ransomware guard (#453, ADR-0159). Every scan of a folder is compared
// with the previous one. When a large part of the files changed in one
// step and the changed content looks encrypted (high entropy where the
// file type is not compressed, or a known file type whose first bytes no
// longer match it), the folder is suspended: it is no longer served to
// peers, it pulls nothing and no backup snapshot is taken, so encrypted
// files never replace the good copies on other devices or in the backup.
// The suspension is stored in the folder's state directory and survives
// a restart; only the owner ends it (ClearAlarm), after checking the
// files. Restoring kept versions stays possible while suspended.
//
// The guard reads at most guardSampleBytes of at most guardMaxSamples
// changed files per scan and only when the change ratio or the
// extension pattern already looks suspicious.

const (
	guardFile        = "guard.json"
	guardSampleBytes = 64 << 10
	guardMaxSamples  = 32
	guardMinSample   = 512
	guardExamples    = 5

	// DefaultGuardMinFiles: smaller folders are not judged.
	DefaultGuardMinFiles = 20
	// DefaultGuardChangeRatio is the share of files that must change
	// (modified or deleted) between two scans.
	DefaultGuardChangeRatio = 0.3
	// guardEntropyBits is the Shannon entropy (bits per byte) above which
	// a sample of a normally uncompressed file looks encrypted.
	guardEntropyBits = 7.5
)

// ErrSuspended is returned while the folder is suspended by the guard.
var ErrSuspended = errors.New("syncdir: klasörde fidye yazılımı belirtisi görüldü; eşitleme ve yedek sahibin onayına kadar durduruldu")

// GuardConfig tunes the ransomware guard of a folder.
type GuardConfig struct {
	// Off disables the guard (for example a folder of encrypted
	// containers, which always looks encrypted).
	Off bool
	// MinFiles is the smallest previous file count the guard judges
	// (default 20).
	MinFiles int
	// ChangeRatio is the share of changed or deleted files (0-1) that
	// counts as a mass change (default 0.3).
	ChangeRatio float64
}

func (g GuardConfig) withDefaults() GuardConfig {
	if g.MinFiles <= 0 {
		g.MinFiles = DefaultGuardMinFiles
	}
	if g.ChangeRatio <= 0 || g.ChangeRatio > 1 {
		g.ChangeRatio = DefaultGuardChangeRatio
	}
	return g
}

// Alarm describes why a folder was suspended.
type Alarm struct {
	Since time.Time `json:"since"`
	// Source is "local" (this device's files) or "peer:<name>" (a peer's
	// index announced the pattern).
	Source string `json:"source"`
	Reason string `json:"reason"`
	// Files is the file count of the previous scan.
	Files       int `json:"files"`
	Modified    int `json:"modified"`
	Deleted     int `json:"deleted"`
	Added       int `json:"added"`
	ExtChanged  int `json:"ext_changed"`
	Sampled     int `json:"sampled"`
	HighEntropy int `json:"high_entropy"`
	BadMagic    int `json:"bad_magic"`
	// Examples are up to five changed paths (local information only).
	Examples []string `json:"examples,omitempty"`
}

// compressedExt are types whose content is normally high entropy.
var compressedExt = map[string]bool{
	".zip": true, ".gz": true, ".tgz": true, ".bz2": true, ".xz": true, ".zst": true, ".7z": true, ".rar": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".heic": true, ".avif": true,
	".mp3": true, ".mp4": true, ".m4a": true, ".m4v": true, ".mkv": true, ".webm": true, ".mov": true, ".avi": true,
	".ogg": true, ".opus": true, ".flac": true, ".aac": true, ".pdf": true, ".docx": true, ".xlsx": true,
	".pptx": true, ".odt": true, ".ods": true, ".odp": true, ".epub": true, ".jar": true, ".apk": true,
	".gpg": true, ".age": true, ".kdbx": true, ".enc": true, ".iso": true, ".dmg": true, ".msi": true, ".cab": true,
	".woff": true, ".woff2": true,
}

// magicOf are the first bytes a file of the type must start with.
var magicOf = map[string][][]byte{
	".zip":    {[]byte("PK")},
	".docx":   {[]byte("PK")},
	".xlsx":   {[]byte("PK")},
	".pptx":   {[]byte("PK")},
	".odt":    {[]byte("PK")},
	".ods":    {[]byte("PK")},
	".odp":    {[]byte("PK")},
	".epub":   {[]byte("PK")},
	".jar":    {[]byte("PK")},
	".apk":    {[]byte("PK")},
	".pdf":    {[]byte("%PDF")},
	".png":    {[]byte("\x89PNG")},
	".jpg":    {[]byte("\xff\xd8\xff")},
	".jpeg":   {[]byte("\xff\xd8\xff")},
	".gif":    {[]byte("GIF8")},
	".gz":     {[]byte("\x1f\x8b")},
	".tgz":    {[]byte("\x1f\x8b")},
	".7z":     {[]byte("7z\xbc\xaf")},
	".rar":    {[]byte("Rar!")},
	".bz2":    {[]byte("BZh")},
	".xz":     {[]byte("\xfd7zXZ")},
	".doc":    {[]byte("\xd0\xcf\x11\xe0")},
	".xls":    {[]byte("\xd0\xcf\x11\xe0")},
	".ppt":    {[]byte("\xd0\xcf\x11\xe0")},
	".sqlite": {[]byte("SQLite format 3")},
}

// Entropy returns the Shannon entropy of b in bits per byte.
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	h := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func lowerExt(p string) string { return strings.ToLower(path.Ext(p)) }

// stemKey is the path without its last extension.
func stemKey(p string) string { return strings.TrimSuffix(p, path.Ext(p)) }

// sampleVerdict classifies one sample: 1 high entropy, 2 bad magic, 0
// normal, -1 too small to judge.
func sampleVerdict(p string, data []byte) int {
	ext := lowerExt(p)
	if magics, ok := magicOf[ext]; ok && len(data) >= 8 {
		for _, m := range magics {
			if bytes.HasPrefix(data, m) {
				return 0
			}
		}
		return 2
	}
	if len(data) < guardMinSample || compressedExt[ext] {
		return -1
	}
	if Entropy(data) >= guardEntropyBits {
		return 1
	}
	return 0
}

// extChanges counts deleted paths that reappear under another extension
// in the same scan ("a.docx" -> "a.docx.locked" or "a.locked").
func extChanges(deleted, added []string) int {
	if len(deleted) == 0 || len(added) == 0 {
		return 0
	}
	del := make(map[string]bool, len(deleted))
	delStem := make(map[string]string, len(deleted))
	for _, d := range deleted {
		del[d] = true
		delStem[strings.ToLower(stemKey(d))] = d
	}
	matched := map[string]bool{}
	for _, a := range added {
		if base := stemKey(a); base != a && del[base] {
			matched[base] = true
			continue
		}
		if d, ok := delStem[strings.ToLower(stemKey(a))]; ok && lowerExt(d) != lowerExt(a) {
			matched[d] = true
		}
	}
	return len(matched)
}

// Assess compares two scans of a folder and returns an alarm when the
// change looks like ransomware, or nil. sample reads the first bytes of a
// path of cur; it may be nil (content is then not judged and only a
// matching extension pattern on a mass change is reported by
// AssessIndexes).
func Assess(cfg GuardConfig, prev, cur Index, sample func(p string) ([]byte, error)) *Alarm {
	cfg = cfg.withDefaults()
	if cfg.Off || len(prev) < cfg.MinFiles {
		return nil
	}
	a := &Alarm{Files: len(prev), Source: "local"}
	var deleted, added, changed []string
	for p, e := range prev {
		c, ok := cur[p]
		switch {
		case !ok:
			deleted = append(deleted, p)
		case c.Hash != e.Hash:
			changed = append(changed, p)
		}
	}
	for p := range cur {
		if _, ok := prev[p]; !ok {
			added = append(added, p)
		}
	}
	a.Modified, a.Deleted, a.Added = len(changed), len(deleted), len(added)
	a.ExtChanged = extChanges(deleted, added)
	ratio := float64(a.Modified+a.Deleted) / float64(a.Files)
	mass := ratio >= cfg.ChangeRatio
	extPattern := a.ExtChanged >= max(5, a.Files/5)
	if !mass && !extPattern {
		return nil
	}
	if sample == nil {
		return nil
	}
	cands := append(append([]string{}, changed...), added...)
	slices.Sort(cands)
	for _, p := range cands {
		if a.Sampled >= guardMaxSamples {
			break
		}
		data, err := sample(p)
		if err != nil {
			continue
		}
		switch sampleVerdict(p, data) {
		case -1:
			continue
		case 1:
			a.HighEntropy++
		case 2:
			a.BadMagic++
		}
		a.Sampled++
		if len(a.Examples) < guardExamples {
			a.Examples = append(a.Examples, p)
		}
	}
	content := a.Sampled >= 5 && 2*(a.HighEntropy+a.BadMagic) >= a.Sampled
	if !content {
		return nil
	}
	var why []string
	if mass {
		why = append(why, fmt.Sprintf("son taramadan bu yana dosyaların %%%d'i değişti veya silindi", int(math.Round(ratio*100))))
	}
	if extPattern {
		why = append(why, fmt.Sprintf("%d dosyanın uzantısı toplu değişti", a.ExtChanged))
	}
	why = append(why, fmt.Sprintf("incelenen %d değişmiş dosyanın %d'i şifrelenmiş görünüyor", a.Sampled, a.HighEntropy+a.BadMagic))
	a.Reason = strings.Join(why, "; ")
	return a
}

// AssessIndexes judges a peer's announced index against the state both
// devices last agreed on, without content: a mass change in which many
// files reappear under another extension. It returns nil otherwise.
func AssessIndexes(cfg GuardConfig, base, remote Index) *Alarm {
	cfg = cfg.withDefaults()
	if cfg.Off || len(base) < cfg.MinFiles {
		return nil
	}
	var deleted, added []string
	changed := 0
	for p, e := range base {
		r, ok := remote[p]
		switch {
		case !ok:
			deleted = append(deleted, p)
		case r.Hash != e.Hash:
			changed++
		}
	}
	for p := range remote {
		if _, ok := base[p]; !ok {
			added = append(added, p)
		}
	}
	ext := extChanges(deleted, added)
	ratio := float64(changed+len(deleted)) / float64(len(base))
	if ratio < cfg.ChangeRatio || ext < max(5, len(base)/5) {
		return nil
	}
	return &Alarm{Files: len(base), Modified: changed, Deleted: len(deleted), Added: len(added), ExtChanged: ext,
		Reason: fmt.Sprintf("eşin dizininde dosyaların %%%d'i değişmiş ve %d dosyanın uzantısı toplu değişmiş", int(math.Round(ratio*100)), ext)}
}

// --- folder integration ---

type guardState struct {
	V     int    `json:"v"`
	Alarm *Alarm `json:"alarm,omitempty"`
}

func (f *Folder) loadGuard() {
	data, err := f.root.ReadFile(MetaDir + "/" + guardFile)
	if err != nil || len(data) > 1<<20 {
		return
	}
	var st guardState
	if json.Unmarshal(data, &st) == nil && st.V == 1 && st.Alarm != nil {
		f.alarm = st.Alarm
	}
}

// setAlarmLocked records the alarm; f.mu must be held.
func (f *Folder) setAlarmLocked(a *Alarm, now time.Time) {
	a.Since = now.UTC()
	f.alarm = a
	if data, err := json.Marshal(guardState{V: 1, Alarm: a}); err == nil {
		_ = f.writeState(guardFile, data)
	}
	if f.cfg.OnAlarm != nil {
		cp := *a
		go f.cfg.OnAlarm(f.cfg.ID, cp)
	}
}

// Alarm returns the folder's active alarm, or nil.
func (f *Folder) Alarm() *Alarm {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.alarm == nil {
		return nil
	}
	cp := *f.alarm
	cp.Examples = slices.Clone(f.alarm.Examples)
	return &cp
}

// ClearAlarm ends the suspension: the owner checked the folder (and
// restored versions where needed). The current content becomes the new
// baseline without being judged.
func (f *Folder) ClearAlarm() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.alarm == nil {
		return nil
	}
	f.alarm = nil
	if err := f.root.Remove(MetaDir + "/" + guardFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_, err := f.scanLocked(false)
	return err
}

// SetGuard replaces the guard settings of an open folder.
func (f *Folder) SetGuard(g GuardConfig) {
	f.mu.Lock()
	f.cfg.Guard = g
	f.mu.Unlock()
}

// sampleFile reads the first bytes of p.
func (f *Folder) sampleFile(p string) ([]byte, error) {
	r, err := f.root.Open(p)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, guardSampleBytes))
}

// --- pause reasons ---

// Pauser collects the reasons that hold scheduled synchronization and
// backups: the owner's pause, a device mode (game #447, metered #385) or
// anything else that registers one. The zero value is ready to use and
// it is safe for concurrent use.
type Pauser struct {
	mu      sync.Mutex
	reasons map[string]time.Time
}

// Set adds (on) or removes a reason.
func (p *Pauser) Set(reason string, on bool, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !on {
		delete(p.reasons, reason)
		return
	}
	if p.reasons == nil {
		p.reasons = map[string]time.Time{}
	}
	if _, ok := p.reasons[reason]; !ok {
		p.reasons[reason] = now.UTC()
	}
}

// Reasons returns the active reasons, sorted.
func (p *Pauser) Reasons() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.reasons))
	for r := range p.reasons {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}

// Since returns when a reason was added.
func (p *Pauser) Since(reason string) (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.reasons[reason]
	return t, ok
}

// Paused reports whether any reason is active.
func (p *Pauser) Paused() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.reasons) > 0
}
