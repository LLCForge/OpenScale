package rdesk

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// Session recording (#128, ADR-0103). Recording is off unless the service
// sets Config.Recording. Recordings stay on the target device, encrypted
// with a key that never leaves it; the indicator and the consent prompt
// say that the session is recorded, and the viewer learns it from the
// welcome message. Only what the viewer saw is recorded: the screen
// messages (desktop, monitors, tiles, frame end). Keystrokes, typed text
// and clipboard contents are never recorded, because they can hold
// passwords.
//
// File format (.osrec):
//
//	magic "OSRDREC1" | salt (32 bytes)
//	chunks: flags u8 | length u32 | AES-256-GCM(chunk)
//
// The file key is HKDF-SHA256(device recording key, salt). The nonce is
// the chunk index; the additional data binds the header, the index and
// the flags, so chunks cannot be reordered, dropped from the middle or
// replayed from another file. The last chunk carries the final flag; a
// recording without it was cut short (crash or power loss) and the player
// reports ErrRecordingTruncated after the frames it could read. A chunk
// holds records: kind u8 | elapsed milliseconds u32 | length u32 | data.
// The first record is the JSON metadata.

const (
	recordingMagic     = "OSRDREC1"
	recordingSaltLen   = 32
	recordingHeaderLen = len(recordingMagic) + recordingSaltLen
	recordingKeyHeader = "openscale-rdesk-recording-key-v1"
	recordingExt       = ".osrec"

	recKindMeta    uint8 = 0
	recKindMessage uint8 = 1

	chunkFinal uint8 = 1

	recFlushBytes = 256 << 10
	recFlushEvery = 2 * time.Second
	// maxRecChunk bounds one decrypted chunk: one server message plus the
	// buffered records before it.
	maxRecChunk = maxServerMsg + recFlushBytes + 64<<10

	defaultMaxRecordingBytes = int64(4) << 30
)

var (
	// ErrRecordingTruncated means the recording ends without its final
	// chunk.
	ErrRecordingTruncated = errors.New("rdesk: kayıt yarıda kesilmiş")
	// ErrRecordingKey means the recording cannot be opened with this key or
	// was modified.
	ErrRecordingKey = errors.New("rdesk: kayıt bu anahtarla açılamıyor veya değiştirilmiş")
	// ErrRecordingLimit is returned when a recording reaches its size limit;
	// the session ends.
	ErrRecordingLimit = errors.New("rdesk: kayıt boyut sınırına ulaştı")
)

// RecordingKey is the device-local key of session recordings.
type RecordingKey struct {
	key [32]byte
}

// LoadOrCreateRecordingKey reads the key at path or creates it (owner
// only, never overwritten). Losing the file makes old recordings
// unreadable, which is the intended way to destroy them.
func LoadOrCreateRecordingKey(path string) (*RecordingKey, error) {
	data, err := securefile.ReadPrivate(path, 4096)
	if errors.Is(err, fs.ErrNotExist) {
		var k RecordingKey
		if _, err := rand.Read(k.key[:]); err != nil {
			return nil, err
		}
		body := recordingKeyHeader + "\n" + hex.EncodeToString(k.key[:]) + "\n"
		werr := securefile.WriteNew(path, []byte(body))
		if werr == nil {
			return &k, nil
		}
		if !errors.Is(werr, fs.ErrExist) {
			return nil, fmt.Errorf("rdesk: kayıt anahtarı yazılamadı: %w", werr)
		}
		data, err = securefile.ReadPrivate(path, 4096)
	}
	if err != nil {
		return nil, fmt.Errorf("rdesk: kayıt anahtarı okunamadı: %w", err)
	}
	return parseRecordingKey(data)
}

func parseRecordingKey(data []byte) (*RecordingKey, error) {
	lines := strings.Fields(string(data))
	if len(lines) != 2 || lines[0] != recordingKeyHeader {
		return nil, errors.New("rdesk: kayıt anahtarı dosyası bozuk")
	}
	raw, err := hex.DecodeString(lines[1])
	if err != nil || len(raw) != 32 {
		return nil, errors.New("rdesk: kayıt anahtarı dosyası bozuk")
	}
	var k RecordingKey
	copy(k.key[:], raw)
	return &k, nil
}

func (k *RecordingKey) fileAEAD(salt []byte) (cipher.AEAD, error) {
	fk, err := hkdf.Key(sha256.New, k.key[:], salt, "openscale rdesk recording v1", 32)
	if err != nil {
		return nil, err
	}
	return newGCM(fk)
}

// RecordingConfig turns session recording on (#128).
type RecordingConfig struct {
	// Dir receives the recordings; it is created owner-only.
	Dir string
	// Key encrypts them; see LoadOrCreateRecordingKey.
	Key *RecordingKey
	// MaxBytes ends a session whose recording grows beyond this (default
	// 4 GiB). Recording never silently stops while a session continues.
	MaxBytes int64
}

func (rc *RecordingConfig) validate() error {
	if rc == nil {
		return nil
	}
	if rc.Key == nil || rc.Dir == "" || !filepath.IsAbs(rc.Dir) {
		return errors.New("rdesk: kayıt için mutlak klasör ve anahtar gerekli")
	}
	if rc.MaxBytes <= 0 {
		rc.MaxBytes = defaultMaxRecordingBytes
	}
	if err := os.MkdirAll(rc.Dir, 0o700); err != nil {
		return fmt.Errorf("rdesk: kayıt klasörü oluşturulamadı: %w", err)
	}
	return nil
}

// RecordingMeta describes a recorded session.
type RecordingMeta struct {
	Version    int       `json:"v"`
	Peer       string    `json:"peer"`
	Mode       string    `json:"mode"`
	Unattended bool      `json:"unattended"`
	Start      time.Time `json:"start"`
	Code       string    `json:"code,omitempty"`
}

type recorder struct {
	f         *os.File
	path      string
	aead      cipher.AEAD
	header    []byte
	idx       uint64
	buf       []byte
	start     time.Time
	lastFlush time.Time
	written   int64
	max       int64
	failed    error
	closed    bool
}

// start creates the recording of sess.
func (rc *RecordingConfig) start(sess *session, at time.Time) (*recorder, error) {
	salt := make([]byte, recordingSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := rc.Key.fileAEAD(salt)
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("rdesk-%s-%d%s", at.UTC().Format("20060102T150405Z"), sess.id, recordingExt)
	path := filepath.Join(rc.Dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	header := append([]byte(recordingMagic), salt...)
	r := &recorder{f: f, path: path, aead: aead, header: header, start: at, lastFlush: at, max: rc.MaxBytes}
	if _, err := f.Write(header); err != nil {
		r.abort()
		return nil, err
	}
	r.written = int64(len(header))
	meta, _ := json.Marshal(RecordingMeta{Version: 1, Peer: sess.peer, Mode: sess.mode.String(), Unattended: !sess.consented, Start: at.UTC(), Code: sess.code})
	r.append(recKindMeta, 0, meta)
	if err := r.flush(0); err != nil {
		r.abort()
		return nil, err
	}
	return r, nil
}

func (r *recorder) abort() {
	_ = r.f.Close()
	_ = os.Remove(r.path)
	r.closed = true
}

func (r *recorder) append(kind uint8, elapsed uint32, data []byte) {
	r.buf = append(r.buf, kind)
	r.buf = binary.BigEndian.AppendUint32(r.buf, elapsed)
	r.buf = binary.BigEndian.AppendUint32(r.buf, uint32(len(data)))
	r.buf = append(r.buf, data...)
}

// record stores one outgoing message if it is part of the picture.
func (r *recorder) record(msg []byte) error {
	if r.failed != nil {
		return r.failed
	}
	if len(msg) < headerLen {
		return nil
	}
	t := msgType(msg[0])
	switch t {
	case msgDesktop, msgMonitors, msgTiles, msgFrameEnd:
	default:
		// Clipboard, status and keepalive messages are not recorded.
		return nil
	}
	now := time.Now()
	elapsed := now.Sub(r.start).Milliseconds()
	r.append(recKindMessage, uint32(min(max(elapsed, 0), int64(^uint32(0)))), msg)
	if len(r.buf) >= recFlushBytes || (t == msgFrameEnd && now.Sub(r.lastFlush) >= recFlushEvery) {
		if err := r.flush(0); err != nil {
			r.failed = err
			return err
		}
		r.lastFlush = now
	}
	return nil
}

func (r *recorder) aad(idx uint64, flags uint8) []byte {
	a := append([]byte(nil), r.header...)
	a = binary.BigEndian.AppendUint64(a, idx)
	return append(a, flags)
}

func (r *recorder) flush(flags uint8) error {
	if len(r.buf) == 0 && flags != chunkFinal {
		return nil
	}
	sealed := r.aead.Seal(nil, seqNonce(r.idx), r.buf, r.aad(r.idx, flags))
	if r.written+int64(5+len(sealed)) > r.max && flags != chunkFinal {
		return ErrRecordingLimit
	}
	out := append([]byte{flags}, binary.BigEndian.AppendUint32(nil, uint32(len(sealed)))...)
	out = append(out, sealed...)
	if _, err := r.f.Write(out); err != nil {
		return err
	}
	r.written += int64(len(out))
	r.idx++
	r.buf = r.buf[:0]
	return nil
}

// close writes the final chunk; a recording that failed keeps what was
// written and stays marked as cut short.
func (r *recorder) close() {
	if r == nil || r.closed {
		return
	}
	r.closed = true
	if r.failed == nil {
		_ = r.flush(chunkFinal)
	}
	_ = r.f.Sync()
	_ = r.f.Close()
}

// RecordedFrame is one complete picture of a recording.
type RecordedFrame struct {
	// At is the time since the session started.
	At    time.Duration
	Image *image.RGBA
}

// RecordingPlayer decrypts a recording frame by frame.
type RecordingPlayer struct {
	r      *bufio.Reader
	aead   cipher.AEAD
	header []byte
	idx    uint64
	buf    []byte
	final  bool
	meta   RecordingMeta
	canvas *image.RGBA
}

// OpenRecording checks the header and the metadata of a recording.
func OpenRecording(r io.Reader, key *RecordingKey) (*RecordingPlayer, error) {
	if key == nil {
		return nil, ErrRecordingKey
	}
	br := bufio.NewReaderSize(r, 256<<10)
	header := make([]byte, recordingHeaderLen)
	if _, err := io.ReadFull(br, header); err != nil || !bytes.HasPrefix(header, []byte(recordingMagic)) {
		return nil, errors.New("rdesk: kayıt dosyası değil")
	}
	aead, err := key.fileAEAD(header[len(recordingMagic):])
	if err != nil {
		return nil, err
	}
	p := &RecordingPlayer{r: br, aead: aead, header: header}
	kind, _, data, err := p.nextRecord()
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, ErrRecordingTruncated) {
			return nil, ErrRecordingTruncated
		}
		return nil, err
	}
	if kind != recKindMeta || json.Unmarshal(data, &p.meta) != nil || p.meta.Version != 1 {
		return nil, ErrRecordingKey
	}
	return p, nil
}

// Meta returns the recorded session's metadata.
func (p *RecordingPlayer) Meta() RecordingMeta { return p.meta }

func (p *RecordingPlayer) readChunk() error {
	var hdr [5]byte
	if _, err := io.ReadFull(p.r, hdr[:]); err != nil {
		return ErrRecordingTruncated
	}
	flags, n := hdr[0], binary.BigEndian.Uint32(hdr[1:])
	if flags&^chunkFinal != 0 || n < sealOverhead || n > maxRecChunk+sealOverhead {
		return ErrRecordingKey
	}
	sealed := make([]byte, n)
	if _, err := io.ReadFull(p.r, sealed); err != nil {
		return ErrRecordingTruncated
	}
	aad := binary.BigEndian.AppendUint64(append([]byte(nil), p.header...), p.idx)
	pt, err := p.aead.Open(sealed[:0], seqNonce(p.idx), sealed, append(aad, flags))
	if err != nil {
		return ErrRecordingKey
	}
	p.idx++
	p.buf = pt
	p.final = flags == chunkFinal
	return nil
}

func (p *RecordingPlayer) nextRecord() (uint8, uint32, []byte, error) {
	for len(p.buf) == 0 {
		if p.final {
			return 0, 0, nil, io.EOF
		}
		if err := p.readChunk(); err != nil {
			return 0, 0, nil, err
		}
	}
	d := dec{b: p.buf}
	kind, elapsed, n := d.u8(), d.u32(), d.u32()
	data := d.take(int(n))
	if d.bad || int64(n) > int64(maxServerMsg)+headerLen {
		return 0, 0, nil, ErrRecordingKey
	}
	p.buf = d.b
	return kind, elapsed, data, nil
}

// Next returns the next complete frame. It returns io.EOF at the end of a
// complete recording and ErrRecordingTruncated at the end of one that was
// cut short.
func (p *RecordingPlayer) Next() (RecordedFrame, error) {
	for {
		kind, elapsed, data, err := p.nextRecord()
		if err != nil {
			return RecordedFrame{}, err
		}
		if kind != recKindMessage || len(data) < headerLen {
			return RecordedFrame{}, ErrProtocol
		}
		t, payload := msgType(data[0]), data[headerLen:]
		if int64(binary.BigEndian.Uint32(data[1:headerLen])) != int64(len(payload)) {
			return RecordedFrame{}, ErrProtocol
		}
		switch t {
		case msgMonitors:
		case msgDesktop:
			dk, err := decodeDesktop(payload)
			if err != nil {
				return RecordedFrame{}, err
			}
			if p.canvas == nil || p.canvas.Rect.Dx() != dk.Width || p.canvas.Rect.Dy() != dk.Height {
				p.canvas = image.NewRGBA(image.Rect(0, 0, dk.Width, dk.Height))
			}
		case msgTiles:
			if p.canvas == nil {
				return RecordedFrame{}, ErrProtocol
			}
			if _, err := applyTiles(p.canvas, payload); err != nil {
				return RecordedFrame{}, err
			}
		case msgFrameEnd:
			if p.canvas == nil {
				return RecordedFrame{}, ErrProtocol
			}
			img := image.NewRGBA(p.canvas.Rect)
			copy(img.Pix, p.canvas.Pix)
			return RecordedFrame{At: time.Duration(elapsed) * time.Millisecond, Image: img}, nil
		default:
			return RecordedFrame{}, ErrProtocol
		}
	}
}

// PruneRecordings deletes recordings in dir last modified before
// now-keep and returns how many it removed.
func PruneRecordings(dir string, keep time.Duration, now time.Time) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	cutoff := now.Add(-keep)
	n := 0
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), recordingExt) {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			n++
		}
	}
	return n, nil
}
