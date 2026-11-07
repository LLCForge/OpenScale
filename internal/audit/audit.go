// Package audit is the local security event log (#187) kept as an
// append-only file whose records are chained with SHA-256 (#188): every
// record carries the hash of the one before it, so changing, removing or
// reordering a record breaks the chain and "openscale audit verify" finds
// it. A separate head file remembers the last record, so cutting records
// off the end is found as well.
//
// The log never leaves the computer (ADR-0008, ADR-0105). Messages are
// masked like the service log: IP addresses are shortened and key-like
// values are removed before they are written.
//
// The chain proves that the file was not edited partially. Someone who can
// write the data directory can still rewrite the whole file and the head
// together; the log is evidence for the owner, not a defence against an
// administrator of the same computer.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/privacy"
	"github.com/openscale/openscale/internal/securefile"
)

const (
	// FileName is the current log file in the data directory.
	FileName = "audit.jsonl"
	// HeadName holds the sequence number and hash of the last record.
	HeadName = "audit.head"
	// rotatedSuffix is appended to the previous file after rotation.
	rotatedSuffix = ".1"
	// MaxFileSize rotates the file; one previous file is kept, so the log
	// uses at most about twice this much space.
	MaxFileSize = 4 << 20
	// MaxMessage bounds one record's message.
	MaxMessage = 512
	// maxLine bounds one line when reading.
	maxLine = 8 << 10
	// maxHead bounds the head file.
	maxHead = 1 << 10
	// MaxList bounds the records returned by Tail.
	MaxList = 1000
)

// Severities of a record.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Genesis is the "previous hash" of the first record.
var Genesis = strings.Repeat("0", sha256.Size*2)

// maxFileSize is MaxFileSize; tests lower it.
var maxFileSize int64 = MaxFileSize

var kindRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// Record is one security event.
type Record struct {
	Seq      uint64    `json:"seq"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Message  string    `json:"message"`
	// Prev is the hash of the record before this one (Genesis for the
	// first).
	Prev string `json:"prev"`
	// Hash is the SHA-256 of this record's JSON as written to the file.
	Hash string `json:"hash"`
}

// line is how a record is stored: the hash next to the exact bytes it
// covers, so verifying never depends on re-encoding.
type line struct {
	Hash   string          `json:"hash"`
	Record json.RawMessage `json:"record"`
}

type body struct {
	Seq      uint64    `json:"seq"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Message  string    `json:"message"`
	Prev     string    `json:"prev"`
}

type head struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Log appends records; it is safe for concurrent use.
type Log struct {
	mu   sync.Mutex
	dir  string
	now  func() time.Time
	seq  uint64
	last string
	size int64
	// onAppend is called after each record is written (outside the lock).
	onAppend func(Record)
}

// Open opens (or starts) the log in dir. A torn last line left by a crash
// is cut off and the cut is itself recorded.
func Open(dir string, now func() time.Time) (*Log, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &Log{dir: dir, now: now, last: Genesis}
	torn, err := l.load()
	if err != nil {
		return nil, err
	}
	if torn > 0 {
		if err := l.Append("audit_torn_record", SeverityWarning,
			fmt.Sprintf("Denetim kaydının sonunda yarım kalmış %d baytlık bir satır vardı (beklenmedik kapanma); satır çıkarıldı.", torn)); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// OnAppend registers fn to be told about every new record.
func (l *Log) OnAppend(fn func(Record)) {
	l.mu.Lock()
	l.onAppend = fn
	l.mu.Unlock()
}

// Dir returns the directory of the log.
func (l *Log) Dir() string { return l.dir }

func (l *Log) path() string { return filepath.Join(l.dir, FileName) }

// load finds the last record of the current file (or of the rotated one
// when the current is empty) and cuts a torn tail. It returns the number
// of bytes cut.
func (l *Log) load() (int64, error) {
	data, err := os.ReadFile(l.path())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		data = nil
	case err != nil:
		return 0, err
	}
	var torn int64
	if n := len(data); n > 0 && data[n-1] != '\n' {
		cut := bytes.LastIndexByte(data, '\n') + 1
		torn = int64(n - cut)
		if err := os.Truncate(l.path(), int64(cut)); err != nil {
			return 0, fmt.Errorf("denetim kaydının yarım satırı kesilemedi: %w", err)
		}
		data = data[:cut]
	}
	l.size = int64(len(data))
	if rec, ok := lastRecord(data); ok {
		l.seq, l.last = rec.Seq, rec.Hash
		return torn, nil
	}
	if old, err := os.ReadFile(l.path() + rotatedSuffix); err == nil {
		if rec, ok := lastRecord(old); ok {
			l.seq, l.last = rec.Seq, rec.Hash
		}
	}
	return torn, nil
}

// lastRecord parses the last non-empty line of data.
func lastRecord(data []byte) (Record, bool) {
	data = bytes.TrimRight(data, "\n")
	if len(data) == 0 {
		return Record{}, false
	}
	i := bytes.LastIndexByte(data, '\n')
	rec, err := parseLine(data[i+1:])
	return rec, err == nil
}

// Clean prepares a message: secrets removed, addresses masked, control
// characters replaced and the length bounded.
func Clean(msg string) string {
	msg = privacy.RedactSecrets(privacy.MaskText(msg))
	msg = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return ' '
		}
		return r
	}, msg)
	msg = strings.TrimSpace(msg)
	if len(msg) > MaxMessage {
		msg = msg[:MaxMessage]
		for !utf8.ValidString(msg) {
			msg = msg[:len(msg)-1]
		}
		msg += "…"
	}
	return msg
}

// Append writes one record. kind is a short snake_case code.
func (l *Log) Append(kind, severity, message string) error {
	if !kindRe.MatchString(kind) {
		return fmt.Errorf("geçersiz denetim olayı türü %q", kind)
	}
	switch severity {
	case SeverityInfo, SeverityWarning, SeverityCritical:
	default:
		return fmt.Errorf("geçersiz önem %q", severity)
	}
	l.mu.Lock()
	b := body{Seq: l.seq + 1, At: l.now().UTC().Truncate(time.Millisecond), Kind: kind, Severity: severity, Message: Clean(message), Prev: l.last}
	raw, err := json.Marshal(b)
	if err != nil {
		l.mu.Unlock()
		return err
	}
	h := digest(raw)
	out, err := json.Marshal(line{Hash: h, Record: raw})
	if err != nil {
		l.mu.Unlock()
		return err
	}
	out = append(out, '\n')
	if l.size > 0 && l.size+int64(len(out)) > maxFileSize {
		if err := os.Rename(l.path(), l.path()+rotatedSuffix); err != nil {
			l.mu.Unlock()
			return fmt.Errorf("denetim kaydı döndürülemedi: %w", err)
		}
		l.size = 0
	}
	if err := appendSync(l.path(), out); err != nil {
		l.mu.Unlock()
		return err
	}
	l.size += int64(len(out))
	l.seq, l.last = b.Seq, h
	hd, _ := json.Marshal(head{Seq: b.Seq, Hash: h})
	herr := securefile.Replace(filepath.Join(l.dir, HeadName), hd)
	fn := l.onAppend
	l.mu.Unlock()
	if fn != nil {
		fn(Record{Seq: b.Seq, At: b.At, Kind: b.Kind, Severity: b.Severity, Message: b.Message, Prev: b.Prev, Hash: h})
	}
	if herr != nil {
		return fmt.Errorf("denetim kaydının baş dosyası yazılamadı: %w", herr)
	}
	return nil
}

func appendSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// parseLine decodes and checks one stored line.
func parseLine(raw []byte) (Record, error) {
	var ln line
	if err := json.Unmarshal(raw, &ln); err != nil {
		return Record{}, errors.New("satır JSON değil")
	}
	if len(ln.Record) == 0 {
		return Record{}, errors.New("satırda kayıt yok")
	}
	var b body
	if err := json.Unmarshal(ln.Record, &b); err != nil {
		return Record{}, errors.New("kayıt çözülemedi")
	}
	rec := Record{Seq: b.Seq, At: b.At, Kind: b.Kind, Severity: b.Severity, Message: b.Message, Prev: b.Prev, Hash: ln.Hash}
	if got := digest(ln.Record); got != ln.Hash {
		return rec, errors.New("kaydın özeti tutmuyor (kayıt değiştirilmiş)")
	}
	return rec, nil
}

// Report is the result of Verify.
type Report struct {
	OK       bool   `json:"ok"`
	Records  int    `json:"records"`
	FirstSeq uint64 `json:"first_seq"`
	LastSeq  uint64 `json:"last_seq"`
	LastHash string `json:"last_hash"`
	// Problems are signs of tampering or damage; OK is false when any.
	Problems []string `json:"problems"`
	// Notes explain expected gaps (records removed by rotation).
	Notes []string `json:"notes"`
}

// files returns the rotated and the current file, oldest first.
func files(dir string) []string {
	return []string{filepath.Join(dir, FileName+rotatedSuffix), filepath.Join(dir, FileName)}
}

// Verify checks the whole chain in dir.
func Verify(dir string) (Report, error) {
	rep := Report{Problems: []string{}, Notes: []string{}}
	prev, prevSeq, started := "", uint64(0), false
	hashes := map[uint64]string{}
	problem := func(format string, args ...any) {
		if len(rep.Problems) < 50 {
			rep.Problems = append(rep.Problems, fmt.Sprintf(format, args...))
		}
	}
	for _, p := range files(dir) {
		f, err := os.Open(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return rep, err
		}
		name := filepath.Base(p)
		err = scanLines(f, func(n int, raw []byte) {
			rec, err := parseLine(raw)
			if err != nil {
				problem("%s satır %d: %v", name, n, err)
				// Continue from this record so later breaks are found too.
				if rec.Hash == "" {
					return
				}
			}
			switch {
			case !started:
				if rec.Prev != Genesis {
					rep.Notes = append(rep.Notes, fmt.Sprintf("Zincir %d numaralı kayıttan başlıyor; daha eski kayıtlar dosya döndürülürken silinmiş.", rec.Seq))
				}
				rep.FirstSeq = rec.Seq
			case rec.Prev != prev:
				problem("%s satır %d (kayıt %d): önceki kaydın özeti tutmuyor (araya kayıt eklenmiş, silinmiş veya sıra değişmiş)", name, n, rec.Seq)
			case rec.Seq != prevSeq+1:
				problem("%s satır %d: sıra numarası %d, beklenen %d", name, n, rec.Seq, prevSeq+1)
			}
			started = true
			prev, prevSeq = rec.Hash, rec.Seq
			hashes[rec.Seq] = rec.Hash
			rep.Records++
		})
		_ = f.Close()
		if err != nil {
			return rep, err
		}
	}
	rep.LastSeq, rep.LastHash = prevSeq, prev
	data, err := securefile.ReadPrivate(filepath.Join(dir, HeadName), maxHead)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if rep.Records > 0 {
			problem("baş dosyası (%s) yok; kayıtların sondan silinip silinmediği anlaşılamıyor", HeadName)
		}
	case err != nil:
		problem("baş dosyası okunamadı: %v", err)
	default:
		var h head
		if json.Unmarshal(data, &h) != nil {
			problem("baş dosyası bozuk")
			break
		}
		switch {
		case h.Seq > rep.LastSeq:
			problem("baş dosyası %d numaralı kaydı gösteriyor ama dosyada son kayıt %d: kayıtlar sondan silinmiş", h.Seq, rep.LastSeq)
		case h.Seq+1 < rep.LastSeq:
			problem("baş dosyası %d numaralı kayıtta kalmış ama dosyada %d kayıt var", h.Seq, rep.LastSeq)
		case hashes[h.Seq] != h.Hash:
			problem("baş dosyasındaki özet %d numaralı kayıtla tutmuyor", h.Seq)
		}
	}
	rep.OK = len(rep.Problems) == 0
	return rep, nil
}

func scanLines(r io.Reader, fn func(n int, raw []byte)) error {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64<<10), maxLine)
	n := 0
	for s.Scan() {
		n++
		if raw := bytes.TrimSpace(s.Bytes()); len(raw) > 0 {
			fn(n, raw)
		}
	}
	if errors.Is(s.Err(), bufio.ErrTooLong) {
		return fmt.Errorf("satır %d çok uzun", n+1)
	}
	return s.Err()
}

// Tail returns up to n of the newest readable records, newest first.
func Tail(dir string, n int) ([]Record, error) {
	if n <= 0 || n > MaxList {
		n = MaxList
	}
	var all []Record
	for _, p := range files(dir) {
		f, err := os.Open(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		err = scanLines(f, func(_ int, raw []byte) {
			if rec, err := parseLine(raw); err == nil || rec.Hash != "" {
				all = append(all, rec)
				if len(all) > 2*n {
					all = append(all[:0], all[len(all)-n:]...)
				}
			}
		})
		_ = f.Close()
		if err != nil {
			return nil, err
		}
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	out := make([]Record, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		out = append(out, all[i])
	}
	return out, nil
}
