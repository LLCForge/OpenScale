// Package logcrypt keeps debug logs encrypted on disk (#44, ADR-0060).
//
// Each log file starts with a header holding a random salt. The file key is
// derived with HKDF-SHA256 from the device's private signing seed and that
// salt, so only this device (or someone holding its key file) can read the
// log, and every file has its own key. Every Write becomes one record,
// sealed with ChaCha20-Poly1305 under a counter nonce; the header and the
// record number are additional data, so records cannot be reordered,
// dropped from the middle or moved between files unnoticed. Removing
// records from the end is not detected: a crash can legitimately leave a
// file at any record boundary.
//
//	file   = magic(8) || salt(16) || record*
//	record = length(4, big endian) || ciphertext(length)
package logcrypt

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	magic    = "OSLOGv1\x00"
	saltSize = 16
	// HeaderSize is the size of the file header.
	HeaderSize = len(magic) + saltSize
	// MaxRecord bounds one record's plaintext.
	MaxRecord = 1 << 20
	info      = "openscale/log-encryption/v1"
)

// ErrNotEncryptedLog is returned for a file without the log header.
var ErrNotEncryptedLog = errors.New("not an OpenScale encrypted log")

// ErrCorrupt is returned when a record fails authentication.
var ErrCorrupt = errors.New("encrypted log record is damaged, reordered or belongs to another key")

func fileKey(seed, salt []byte) ([]byte, error) {
	if len(seed) != 32 {
		return nil, errors.New("log key seed must be 32 bytes")
	}
	return hkdf.Key(sha256.New, seed, salt, info, chacha20poly1305.KeySize)
}

func nonce(counter uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func additionalData(header []byte, counter uint64) []byte {
	ad := make([]byte, 0, len(header)+8)
	ad = append(ad, header...)
	return binary.BigEndian.AppendUint64(ad, counter)
}

// Writer encrypts each Write as one record. It is safe for concurrent use.
type Writer struct {
	mu      sync.Mutex
	w       io.Writer
	aead    cipher.AEAD
	header  []byte
	counter uint64
}

// NewWriter writes a new header to w and returns a Writer whose key is
// derived from seed (the device signing seed) and a fresh salt.
func NewWriter(w io.Writer, seed []byte, random io.Reader) (*Writer, error) {
	header := make([]byte, HeaderSize)
	copy(header, magic)
	if _, err := io.ReadFull(random, header[len(magic):]); err != nil {
		return nil, fmt.Errorf("read log salt: %w", err)
	}
	key, err := fileKey(seed, header[len(magic):])
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	wipe(key)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(header); err != nil {
		return nil, fmt.Errorf("write log header: %w", err)
	}
	return &Writer{w: w, aead: aead, header: header}, nil
}

// Write encrypts p as one record. Longer input is split into records of at
// most MaxRecord bytes.
func (lw *Writer) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	written := 0
	for len(p) > 0 || written == 0 {
		chunk := p[:min(len(p), MaxRecord)]
		ct := lw.aead.Seal(nil, nonce(lw.counter), chunk, additionalData(lw.header, lw.counter))
		rec := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(ct)), uint32(len(ct))) //nolint:gosec // bounded by MaxRecord
		rec = append(rec, ct...)
		if _, err := lw.w.Write(rec); err != nil {
			return written, err
		}
		lw.counter++
		written += len(chunk)
		p = p[len(chunk):]
		if len(chunk) == 0 {
			break
		}
	}
	return written, nil
}

// Reader decrypts records in order.
type Reader struct {
	r       io.Reader
	aead    cipher.AEAD
	header  []byte
	counter uint64
}

// NewReader reads the header from r and prepares decryption with seed.
func NewReader(r io.Reader, seed []byte) (*Reader, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil || string(header[:len(magic)]) != magic {
		return nil, ErrNotEncryptedLog
	}
	key, err := fileKey(seed, header[len(magic):])
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	wipe(key)
	if err != nil {
		return nil, err
	}
	return &Reader{r: r, aead: aead, header: header}, nil
}

// Next returns the next record, or io.EOF after the last complete one.
func (lr *Reader) Next() ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(lr.r, lenBuf[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("%w: truncated record", ErrCorrupt)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < chacha20poly1305.Overhead || n > MaxRecord+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("%w: invalid record length", ErrCorrupt)
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(lr.r, ct); err != nil {
		return nil, fmt.Errorf("%w: truncated record", ErrCorrupt)
	}
	pt, err := lr.aead.Open(nil, nonce(lr.counter), ct, additionalData(lr.header, lr.counter))
	if err != nil {
		return nil, ErrCorrupt
	}
	lr.counter++
	return pt, nil
}

// Decrypt copies every record of r to w and returns the number of records.
func Decrypt(w io.Writer, r io.Reader, seed []byte) (int, error) {
	lr, err := NewReader(r, seed)
	if err != nil {
		return 0, err
	}
	n := 0
	for {
		rec, err := lr.Next()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if _, err := w.Write(rec); err != nil {
			return n, err
		}
		n++
	}
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
