package p2psend

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Wire format (version 1). Every connection starts with a preamble:
//
//	magic "OSP2" | kind (1) | version (1)
//
// kind 'F' is an end-to-end file stream to this device:
//
//	sender static key (32) | ephemeral key (32) | u16 length | sealed header
//	<- reply frame (accept with resume offset, or a refusal)
//	-> fixed size data records from the offset to the last chunk
//	<- reply frame (ok or integrity)
//
// kind 'R' is an onion layer for a relay (onion.go).
//
// Reply frames are u16 length | ChaCha20-Poly1305 ciphertext under the
// reply key with a counter nonce. Data records are exactly RecordSize
// bytes; the plaintext of every chunk is ChunkSize bytes, the last one
// zero padded, so nothing outside the two devices learns the file size
// more precisely than the number of chunks.
const (
	magic       = "OSP2"
	kindFile    = 'F'
	kindRelay   = 'R'
	wireVersion = 1

	// ChunkSize is the plaintext size of one data record.
	ChunkSize = 64 << 10
	// RecordSize is the size of one encrypted data record on the wire.
	RecordSize = ChunkSize + 16

	maxHeaderPlain = 4096
	headerPad      = 512
	maxReplyPlain  = 1024
	maxNameBytes   = 1024
)

// ErrProtocol is returned for malformed messages.
var ErrProtocol = errors.New("geçersiz uçtan uca aktarım mesajı")

// header is the sealed description of the file. Nothing in it is visible
// to relays.
type header struct {
	V      int    `json:"v"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Chunk  int    `json:"chunk"`
	// Stripped is true when the sender removed metadata (#658).
	Stripped bool `json:"stripped,omitempty"`
	// Pad hides the name length.
	Pad string `json:"pad,omitempty"`
}

// validate checks a received header strictly.
func (h *header) validate(maxSize int64) error {
	switch {
	case h.V != wireVersion:
		return fmt.Errorf("%w: sürüm %d", ErrProtocol, h.V)
	case !validHex(h.ID, 16):
		return fmt.Errorf("%w: aktarım kimliği", ErrProtocol)
	case h.Name == "" || len(h.Name) > maxNameBytes:
		return fmt.Errorf("%w: dosya adı", ErrProtocol)
	case h.Size < 0:
		return fmt.Errorf("%w: boyut", ErrProtocol)
	case maxSize > 0 && h.Size > maxSize:
		return ErrTooLarge
	case !validHex(h.SHA256, 32):
		return fmt.Errorf("%w: özet", ErrProtocol)
	case h.Chunk != ChunkSize:
		return fmt.Errorf("%w: parça boyutu", ErrProtocol)
	}
	for i := 0; i < len(h.Pad); i++ {
		if h.Pad[i] != ' ' {
			return fmt.Errorf("%w: dolgu", ErrProtocol)
		}
	}
	return nil
}

func validHex(s string, n int) bool {
	if len(s) != 2*n {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n && hex.EncodeToString(b) == s
}

// encodeHeader marshals and pads the header to a multiple of headerPad.
func encodeHeader(h header) ([]byte, error) {
	h.Pad = ""
	b, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	// The pad field adds `,"pad":""` (9 bytes) plus the spaces.
	want := (len(b) + 9 + headerPad - 1) / headerPad * headerPad
	if pad := want - len(b) - 9; pad > 0 {
		h.Pad = string(bytes.Repeat([]byte(" "), pad))
		if b, err = json.Marshal(h); err != nil {
			return nil, err
		}
	}
	if len(b) > maxHeaderPlain {
		return nil, fmt.Errorf("%w: başlık çok büyük", ErrProtocol)
	}
	return b, nil
}

func decodeHeader(b []byte) (header, error) {
	var h header
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return header{}, fmt.Errorf("%w: başlık", ErrProtocol)
	}
	if dec.More() {
		return header{}, fmt.Errorf("%w: başlık", ErrProtocol)
	}
	return h, nil
}

// numChunks is the number of data records for a file (at least one).
func numChunks(size int64) uint64 {
	if size <= 0 {
		return 1
	}
	return uint64((size + ChunkSize - 1) / ChunkSize)
}

// chunkLen is the number of real bytes in chunk i.
func chunkLen(size int64, i uint64) int {
	start := int64(i) * ChunkSize
	if start >= size {
		return 0
	}
	return int(min(int64(ChunkSize), size-start))
}

// chunkAD binds a record to its transfer and marks the last one.
func chunkAD(id []byte, final bool) []byte {
	ad := make([]byte, 0, len(id)+1)
	ad = append(ad, id...)
	if final {
		return append(ad, 1)
	}
	return append(ad, 0)
}

// transferID is deterministic so a retry of the same file to the same
// receiver resumes without state on the sender.
func transferID(receiver Key, digest []byte, size int64) []byte {
	h := sha256.New()
	h.Write([]byte("openscale/p2psend/v1/id"))
	h.Write(receiver[:])
	h.Write(digest)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(size))
	h.Write(n[:])
	return h.Sum(nil)[:16]
}

// Reply statuses.
const (
	statusAccept    = "accept"
	statusOK        = "ok"
	statusRejected  = "rejected"
	statusTooLarge  = "too_large"
	statusBusy      = "busy"
	statusBadName   = "bad_name"
	statusIntegrity = "integrity"
	statusError     = "error"
)

// Errors reported to the sender.
var (
	ErrRejected  = errors.New("alıcı dosyayı kabul etmedi")
	ErrTooLarge  = errors.New("dosya alıcının boyut sınırını aşıyor")
	ErrBusy      = errors.New("alıcı şu anda meşgul")
	ErrBadName   = errors.New("dosya adı alıcıda kullanılamıyor")
	ErrIntegrity = errors.New("bütünlük doğrulaması başarısız, alıcı dosyayı sildi")
	ErrRemote    = errors.New("alıcı tarafında hata oluştu")
)

func statusErr(s string) error {
	switch s {
	case statusRejected:
		return ErrRejected
	case statusTooLarge:
		return ErrTooLarge
	case statusBusy:
		return ErrBusy
	case statusBadName:
		return ErrBadName
	case statusIntegrity:
		return ErrIntegrity
	}
	return ErrRemote
}

type reply struct {
	Status string `json:"status"`
	Offset uint64 `json:"offset,omitempty"`
	Name   string `json:"name,omitempty"`
}

// replyChannel seals frames in one direction with a counter nonce.
type replyChannel struct {
	key     *[32]byte
	counter uint64
}

func (c *replyChannel) write(w io.Writer, r reply) error {
	p, err := json.Marshal(r)
	if err != nil {
		return err
	}
	ct, err := seal(c.key, domainReply, c.counter, p, []byte(magic))
	if err != nil {
		return err
	}
	c.counter++
	buf := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(ct)), uint16(len(ct)))
	_, err = w.Write(append(buf, ct...))
	return err
}

func (c *replyChannel) read(rd io.Reader) (reply, error) {
	var l [2]byte
	if _, err := io.ReadFull(rd, l[:]); err != nil {
		return reply{}, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n < 16 || n > maxReplyPlain+16 {
		return reply{}, ErrProtocol
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(rd, ct); err != nil {
		return reply{}, err
	}
	p, err := open(c.key, domainReply, c.counter, ct, []byte(magic))
	if err != nil {
		return reply{}, err
	}
	c.counter++
	var r reply
	dec := json.NewDecoder(bytes.NewReader(p))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil || r.Status == "" || len(r.Name) > maxNameBytes {
		return reply{}, ErrProtocol
	}
	return r, nil
}

// fileHello is the clear part of a 'F' stream after the preamble.
type fileHello struct {
	sender    Key
	ephemeral Key
	sealed    []byte
}

func writePreamble(w *bytes.Buffer, kind byte) {
	w.WriteString(magic)
	w.WriteByte(kind)
	w.WriteByte(wireVersion)
}

// readPreamble returns the kind byte.
func readPreamble(r io.Reader) (byte, error) {
	var p [6]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return 0, err
	}
	if string(p[:4]) != magic || p[5] != wireVersion || (p[4] != kindFile && p[4] != kindRelay) {
		return 0, ErrProtocol
	}
	return p[4], nil
}

func encodeFileHello(h fileHello) []byte {
	var b bytes.Buffer
	writePreamble(&b, kindFile)
	b.Write(h.sender[:])
	b.Write(h.ephemeral[:])
	_ = binary.Write(&b, binary.BigEndian, uint16(len(h.sealed)))
	b.Write(h.sealed)
	return b.Bytes()
}

// readFileHello reads the rest of an 'F' stream's hello after the preamble.
func readFileHello(r io.Reader) (fileHello, error) {
	var h fileHello
	if _, err := io.ReadFull(r, h.sender[:]); err != nil {
		return h, err
	}
	if _, err := io.ReadFull(r, h.ephemeral[:]); err != nil {
		return h, err
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return h, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n < 16 || n > maxHeaderPlain+16 {
		return h, ErrProtocol
	}
	h.sealed = make([]byte, n)
	if _, err := io.ReadFull(r, h.sealed); err != nil {
		return h, err
	}
	return h, nil
}

// ParseFileHello parses a complete 'F' hello including the preamble. It
// exists for fuzzing the receiver's first read; it does not decrypt.
func ParseFileHello(b []byte) error {
	r := bytes.NewReader(b)
	k, err := readPreamble(r)
	if err != nil {
		return err
	}
	if k != kindFile {
		return ErrProtocol
	}
	_, err = readFileHello(r)
	return err
}

// OpenHeader decrypts and validates a sealed header for receiver id. It
// is exported for fuzzing.
func OpenHeader(id Identity, b []byte, maxSize int64) error {
	r := bytes.NewReader(b)
	k, err := readPreamble(r)
	if err != nil {
		return err
	}
	if k != kindFile {
		return ErrProtocol
	}
	hello, err := readFileHello(r)
	if err != nil {
		return err
	}
	keys, err := receiverSession(id, hello.ephemeral, hello.sender)
	if err != nil {
		return err
	}
	defer keys.wipe()
	p, err := open(&keys.header, domainHeader, 0, hello.sealed, []byte(magic))
	if err != nil {
		return err
	}
	h, err := decodeHeader(p)
	if err != nil {
		return err
	}
	return h.validate(maxSize)
}
