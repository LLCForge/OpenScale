package trust

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Paper backup (#18, ADR-0063). A sealed root key copy (ADR-0011: the seed
// encrypted under a backup passphrase with Argon2id and XChaCha20-Poly1305)
// is packed into 130 bytes and printed twice: as a QR code and as 13 lines
// of base32 with a two-character check per line, so a typo is found on the
// line where it was made. Nothing on paper is usable without the backup
// passphrase; the public key, KDF parameters and salt stay bound to the
// ciphertext as additional data, so a changed field fails to decrypt.

const (
	paperMagic = "OSK1"
	// PaperBackupSize is the size of the packed sealed key.
	PaperBackupSize = len(paperMagic) + 1 + 4 + 1 + saltSize + chacha20poly1305.NonceSizeX + ed25519SeedSealedSize + KeySize
	// PaperQRPrefix starts the QR payload. Base32 and the prefix use only
	// QR alphanumeric characters, which keeps the code small.
	PaperQRPrefix = "OSPB1:"

	ed25519SeedSealedSize = 32 + chacha20poly1305.Overhead
	paperLineChars        = 16
	paperGroupChars       = 4
	paperCheckChars       = 2
	maxPaperText          = 4096
)

var paperEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrPaperChecksum is returned when a typed paper backup line is wrong.
var ErrPaperChecksum = errors.New("paper backup line check failed")

// EncodePaperBackup packs a sealed root key.
func EncodePaperBackup(s *SealedRootKey) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if s.KDF.Time > 255 {
		return nil, errors.New("argon2id time does not fit a paper backup")
	}
	out := make([]byte, 0, PaperBackupSize)
	out = append(out, paperMagic...)
	out = append(out, byte(s.KDF.Time))
	out = binary.BigEndian.AppendUint32(out, s.KDF.MemoryKiB)
	out = append(out, s.KDF.Threads)
	out = append(out, s.Salt...)
	out = append(out, s.Nonce...)
	out = append(out, s.Ciphertext...)
	out = append(out, s.PublicKey[:]...)
	return out, nil
}

// DecodePaperBackup unpacks and validates a packed sealed root key.
func DecodePaperBackup(b []byte) (*SealedRootKey, error) {
	if len(b) != PaperBackupSize || string(b[:len(paperMagic)]) != paperMagic {
		return nil, errors.New("not an OpenScale paper backup")
	}
	b = b[len(paperMagic):]
	s := &SealedRootKey{Format: rootKeyFormat}
	s.KDF.Time = uint32(b[0])
	s.KDF.MemoryKiB = binary.BigEndian.Uint32(b[1:5])
	s.KDF.Threads = b[5]
	b = b[6:]
	s.Salt = append([]byte(nil), b[:saltSize]...)
	b = b[saltSize:]
	s.Nonce = append([]byte(nil), b[:chacha20poly1305.NonceSizeX]...)
	b = b[chacha20poly1305.NonceSizeX:]
	s.Ciphertext = append([]byte(nil), b[:ed25519SeedSealedSize]...)
	b = b[ed25519SeedSealedSize:]
	copy(s.PublicKey[:], b)
	if err := s.validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// PaperQRText returns the QR payload of a packed backup.
func PaperQRText(packed []byte) string {
	return PaperQRPrefix + paperEncoding.EncodeToString(packed)
}

// PaperLines returns the printable lines: "01 ABCD EFGH IJKL MNOP  XY",
// where XY checks the line number and its sixteen characters.
func PaperLines(packed []byte) []string {
	text := paperEncoding.EncodeToString(packed)
	var lines []string
	for i := 0; i*paperLineChars < len(text); i++ {
		chunk := text[i*paperLineChars : min((i+1)*paperLineChars, len(text))]
		var groups []string
		for j := 0; j < len(chunk); j += paperGroupChars {
			groups = append(groups, chunk[j:min(j+paperGroupChars, len(chunk))])
		}
		lines = append(lines, fmt.Sprintf("%02d %s  %s", i+1, strings.Join(groups, " "), paperLineCheck(i+1, chunk)))
	}
	return lines
}

func paperLineCheck(n int, chunk string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("openscale/paper-line/v1|%d|%s", n, chunk)))
	return paperEncoding.EncodeToString(sum[:2])[:paperCheckChars]
}

// ParsePaperBackup reads either the QR payload or the typed lines and
// returns the packed backup. Lowercase letters and the look-alike digits
// 0, 1 and 8 (for O, I and B) are accepted.
func ParsePaperBackup(text string) ([]byte, error) {
	if len(text) > maxPaperText {
		return nil, errors.New("paper backup text is too long")
	}
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(strings.ToUpper(trimmed), PaperQRPrefix) {
		data, err := paperEncoding.DecodeString(normalizePaper(trimmed[len(PaperQRPrefix):]))
		if err != nil {
			return nil, errors.New("paper backup QR text is not valid base32")
		}
		return checkPacked(data)
	}
	var b strings.Builder
	n := 0
	for _, raw := range strings.Split(trimmed, "\n") {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		n++
		if len(fields) < 3 {
			return nil, fmt.Errorf("%w: line %d is incomplete", ErrPaperChecksum, n)
		}
		if num, err := strconv.Atoi(fields[0]); err != nil || num != n {
			return nil, fmt.Errorf("%w: line %d has the wrong number", ErrPaperChecksum, n)
		}
		chunk := normalizePaper(strings.Join(fields[1:len(fields)-1], ""))
		check := normalizePaper(fields[len(fields)-1])
		if len(chunk) > paperLineChars || check != paperLineCheck(n, chunk) {
			return nil, fmt.Errorf("%w: line %d", ErrPaperChecksum, n)
		}
		b.WriteString(chunk)
	}
	data, err := paperEncoding.DecodeString(b.String())
	if err != nil {
		return nil, errors.New("paper backup text is not valid base32")
	}
	return checkPacked(data)
}

func checkPacked(data []byte) ([]byte, error) {
	if _, err := DecodePaperBackup(data); err != nil {
		return nil, err
	}
	return data, nil
}

func normalizePaper(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '0':
			r = 'O'
		case '1':
			r = 'I'
		case '8':
			r = 'B'
		case '-', ' ', '\t', '\r':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
