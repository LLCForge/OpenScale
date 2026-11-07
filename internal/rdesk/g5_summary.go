package rdesk

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// Signed session summaries (#667, ADR-0201).
//
// When a session ends the server builds a summary: who connected, as
// which account, when, for how long, in which mode, whether it was
// recorded, whether the clipboard or the curtain was used and which
// files were fetched (path, size, SHA-256). Config.Summary receives it;
// the service appends it to a local log with SummaryLog and sends a copy
// to the owner's devices. Each line of the log is signed with the
// device's summary key (Ed25519) and names the SHA-256 of the previous
// line, so a removed or edited entry breaks the chain. The optional
// encrypted screen recording stays the job of Config.Recording (#128).

// SummaryVersion is the summary format version.
const SummaryVersion = 1

// maxSummaryFiles bounds the files listed in one summary.
const maxSummaryFiles = 200

// FileTransfer is one file a session fetched.
type FileTransfer struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// SessionSummary describes one finished session.
type SessionSummary struct {
	Version    int            `json:"v"`
	ID         uint64         `json:"id"`
	Peer       string         `json:"peer"`
	OSUser     string         `json:"os_user,omitempty"`
	Mode       string         `json:"mode"`
	Unattended bool           `json:"unattended"`
	Start      time.Time      `json:"start"`
	End        time.Time      `json:"end"`
	Seconds    int64          `json:"seconds"`
	Reason     string         `json:"reason,omitempty"`
	Recording  bool           `json:"recording,omitempty"`
	Clipboard  bool           `json:"clipboard,omitempty"`
	Curtain    bool           `json:"curtain,omitempty"`
	Files      []FileTransfer `json:"files,omitempty"`
	// FilesOmitted counts transfers beyond maxSummaryFiles.
	FilesOmitted int `json:"files_omitted,omitempty"`
}

// summaryState collects the summary while the session runs.
type summaryState struct {
	mu        sync.Mutex
	files     []FileTransfer
	omitted   int
	clipboard bool
	curtain   bool
}

func (st *summaryState) addFile(path string, size int64, sum [sha256.Size]byte) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.files) >= maxSummaryFiles {
		st.omitted++
		return
	}
	st.files = append(st.files, FileTransfer{Path: path, Size: size, SHA256: hex.EncodeToString(sum[:])})
}

func (st *summaryState) mark(clipboard, curtain bool) {
	st.mu.Lock()
	st.clipboard = st.clipboard || clipboard
	st.curtain = st.curtain || curtain
	st.mu.Unlock()
}

// summary builds the session's summary.
func (sess *session) summary(start, end time.Time, reason string) SessionSummary {
	st := &sess.sum
	st.mu.Lock()
	defer st.mu.Unlock()
	return SessionSummary{
		Version: SummaryVersion, ID: sess.id, Peer: sess.peer, OSUser: sess.osUser, Mode: sess.mode.String(),
		Unattended: !sess.consented, Start: start.UTC(), End: end.UTC(), Seconds: int64(end.Sub(start) / time.Second),
		Reason: reason, Recording: sess.rec != nil, Clipboard: st.clipboard, Curtain: st.curtain,
		Files: append([]FileTransfer(nil), st.files...), FilesOmitted: st.omitted,
	}
}

// SignedSummary is one line of a summary log.
type SignedSummary struct {
	// Summary is the summary's JSON, signed together with Prev.
	Summary json.RawMessage `json:"summary"`
	// Prev is the hex SHA-256 of the previous line ("" for the first).
	Prev string `json:"prev"`
	// Key is the signer's Ed25519 public key (base64).
	Key string `json:"key"`
	// Sig is the Ed25519 signature (base64) of signedBytes.
	Sig string `json:"sig"`
}

var summaryContext = []byte("openscale-rdesk-summary-v1\x00")

func summarySignedBytes(summary []byte, prev string) []byte {
	b := append([]byte(nil), summaryContext...)
	b = append(b, prev...)
	b = append(b, 0)
	return append(b, summary...)
}

// SignSummary signs s after the line whose hash is prev.
func SignSummary(key ed25519.PrivateKey, s SessionSummary, prev string) (SignedSummary, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedSummary{}, errors.New("rdesk: özet anahtarı geçersiz")
	}
	body, err := json.Marshal(s)
	if err != nil {
		return SignedSummary{}, err
	}
	sig := ed25519.Sign(key, summarySignedBytes(body, prev))
	pub := key.Public().(ed25519.PublicKey)
	return SignedSummary{Summary: body, Prev: prev, Key: base64.StdEncoding.EncodeToString(pub), Sig: base64.StdEncoding.EncodeToString(sig)}, nil
}

// Verify checks the signature with pub and returns the summary.
func (ss SignedSummary) Verify(pub ed25519.PublicKey) (SessionSummary, error) {
	sig, err := base64.StdEncoding.DecodeString(ss.Sig)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return SessionSummary{}, errors.New("rdesk: özet imzası geçersiz")
	}
	if ss.Key != base64.StdEncoding.EncodeToString(pub) || !ed25519.Verify(pub, summarySignedBytes(ss.Summary, ss.Prev), sig) {
		return SessionSummary{}, errors.New("rdesk: özet imzası doğrulanamadı")
	}
	var s SessionSummary
	dec := json.NewDecoder(bytes.NewReader(ss.Summary))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || s.Version != SummaryVersion {
		return SessionSummary{}, errors.New("rdesk: özet biçimi tanınmıyor")
	}
	return s, nil
}

const summaryKeyHeader = "openscale-rdesk-summary-key-v1"

// LoadOrCreateSummaryKey reads the device's summary signing key at path
// or creates it (owner only, never overwritten).
func LoadOrCreateSummaryKey(path string) (ed25519.PrivateKey, error) {
	data, err := securefile.ReadPrivate(path, 4096)
	if errors.Is(err, fs.ErrNotExist) {
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		body := summaryKeyHeader + "\n" + hex.EncodeToString(priv.Seed()) + "\n"
		werr := securefile.WriteNew(path, []byte(body))
		if werr == nil {
			return priv, nil
		}
		if !errors.Is(werr, fs.ErrExist) {
			return nil, fmt.Errorf("rdesk: özet anahtarı yazılamadı: %w", werr)
		}
		data, err = securefile.ReadPrivate(path, 4096)
	}
	if err != nil {
		return nil, fmt.Errorf("rdesk: özet anahtarı okunamadı: %w", err)
	}
	lines := strings.Fields(string(data))
	if len(lines) != 2 || lines[0] != summaryKeyHeader {
		return nil, errors.New("rdesk: özet anahtarı dosyası bozuk")
	}
	seed, err := hex.DecodeString(lines[1])
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("rdesk: özet anahtarı dosyası bozuk")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// maxSummaryLine bounds one log line.
const maxSummaryLine = 256 << 10

// SummaryLog appends signed summaries to a file, one JSON object per
// line, each naming the hash of the line before it.
type SummaryLog struct {
	mu   sync.Mutex
	path string
	key  ed25519.PrivateKey
}

// OpenSummaryLog opens (or prepares) the log at path.
func OpenSummaryLog(path string, key ed25519.PrivateKey) (*SummaryLog, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("rdesk: özet anahtarı geçersiz")
	}
	return &SummaryLog{path: path, key: key}, nil
}

// Append signs s and adds it to the log; it returns the signed line.
func (l *SummaryLog) Append(s SessionSummary) (SignedSummary, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev, err := lastLineHash(l.path)
	if err != nil {
		return SignedSummary{}, err
	}
	ss, err := SignSummary(l.key, s, prev)
	if err != nil {
		return SignedSummary{}, err
	}
	line, err := json.Marshal(ss)
	if err != nil {
		return SignedSummary{}, err
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return SignedSummary{}, fmt.Errorf("rdesk: özet günlüğü açılamadı: %w", err)
	}
	_, werr := f.Write(append(line, '\n'))
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return SignedSummary{}, fmt.Errorf("rdesk: özet günlüğüne yazılamadı: %w", err)
	}
	return ss, nil
}

func lineHash(line []byte) string {
	h := sha256.Sum256(line)
	return hex.EncodeToString(h[:])
}

func lastLineHash(path string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	last := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxSummaryLine)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			last = lineHash(sc.Bytes())
		}
	}
	return last, sc.Err()
}

// VerifySummaryLog checks every line of r: the signature with pub and the
// chain of hashes. It returns the summaries in order.
func VerifySummaryLog(r io.Reader, pub ed25519.PublicKey) ([]SessionSummary, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxSummaryLine)
	prev := ""
	var out []SessionSummary
	for n := 1; sc.Scan(); n++ {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ss SignedSummary
		if err := json.Unmarshal(line, &ss); err != nil {
			return out, fmt.Errorf("rdesk: özet günlüğü satır %d okunamadı", n)
		}
		if ss.Prev != prev {
			return out, fmt.Errorf("rdesk: özet günlüğü satır %d: zincir kopuk (silinmiş veya değiştirilmiş kayıt)", n)
		}
		s, err := ss.Verify(pub)
		if err != nil {
			return out, fmt.Errorf("rdesk: özet günlüğü satır %d: %w", n, err)
		}
		out = append(out, s)
		prev = lineHash(line)
	}
	return out, sc.Err()
}
