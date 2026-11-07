package openscale

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/trust"
)

// Invite transfer over NFC (#470, P08, ADR in docs/adr). Android Beam is
// gone (API 29+), so the phone that holds the invite code emulates an NFC
// Forum Type 4 Tag (host card emulation) carrying one NDEF record, and the
// new phone reads it in reader mode. Only an invite code travels: it is
// classified with ClassifyScan and the owner compares the root fingerprint
// on screen exactly as after a QR scan, so NFC adds no new trust path.
//
// The tag is read-only, serves exactly one complete read and is armed by
// the app only while the share screen is open (the HCE service component
// is disabled otherwise). The APDU state machine and the NDEF parser are
// here so they are tested and fuzzed; the app only moves bytes.

// NFCInviteMIME is the NDEF media type of an invite record.
const NFCInviteMIME = "application/vnd.openscale.invite"

// Type 4 Tag constants (NFC Forum Type 4 Tag Technical Specification 2.0).
var nfcAID = []byte{0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01}

const (
	nfcCCFile   = 0xE103
	nfcNDEFFile = 0xE104
	nfcMLe      = 0x00FF // longest R-APDU data this tag sends
	nfcMaxAPDU  = 261    // short APDU: 4 header + 1 Lc + 255 data + 1 Le
	maxNFCText  = 2048   // the invite code limit of internal/trust
	maxNDEF     = 8 << 10
)

// Status words.
var (
	swOK            = []byte{0x90, 0x00}
	swWrongLength   = []byte{0x67, 0x00}
	swSecurity      = []byte{0x69, 0x82}
	swNotFound      = []byte{0x6A, 0x82}
	swWrongP1P2     = []byte{0x6B, 0x00}
	swINSNotSupport = []byte{0x6D, 0x00}
	swCLANotSupport = []byte{0x6E, 0x00}
)

// NfcTag is an emulated, read-only Type 4 Tag holding one invite code.
// Its methods are safe for concurrent use (Android calls processCommandApdu
// on the main thread, the share screen polls Delivered on another).
type NfcTag struct {
	mu        sync.Mutex
	cc        []byte
	ndef      []byte // NLEN + NDEF message
	appSel    bool
	file      int // selected file id, 0 for none
	readUntil int // highest NDEF file offset read
	delivered bool
	wiped     bool
}

// NewNfcTag prepares a tag for inviteCode, which must be a well-formed
// OpenScale invite code (it is decoded, not trusted, here).
func NewNfcTag(inviteCode string) (*NfcTag, error) {
	code := strings.TrimSpace(inviteCode)
	if _, err := trust.DecodeInviteCode(code); err != nil {
		return nil, err
	}
	msg := ndefMediaRecord(NFCInviteMIME, []byte(code))
	file := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(file, uint16(len(msg)))
	copy(file[2:], msg)
	cc := []byte{
		0x00, 0x0F, // CCLEN
		0x20,                            // mapping version 2.0
		byte(nfcMLe >> 8), byte(nfcMLe), // MLe
		0x00, 0x01, // MLc: this tag accepts no writes
		0x04, 0x06, // NDEF File Control TLV
		byte(nfcNDEFFile >> 8), byte(nfcNDEFFile & 0xFF),
		byte(len(file) >> 8), byte(len(file)), // maximum NDEF file size
		0x00, // read access granted
		0xFF, // no write access
	}
	return &NfcTag{cc: cc, ndef: file}, nil
}

// ndefMediaRecord encodes one NDEF message with a single media-type record.
func ndefMediaRecord(mime string, payload []byte) []byte {
	var b bytes.Buffer
	hdr := byte(0x80 | 0x40 | 0x02) // MB, ME, TNF media
	if len(payload) < 256 {
		hdr |= 0x10 // SR
	}
	b.WriteByte(hdr)
	b.WriteByte(byte(len(mime)))
	if len(payload) < 256 {
		b.WriteByte(byte(len(payload)))
	} else {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(payload)))
		b.Write(n[:])
	}
	b.WriteString(mime)
	b.Write(payload)
	return b.Bytes()
}

func respond(data []byte, sw []byte) []byte {
	out := make([]byte, 0, len(data)+2)
	return append(append(out, data...), sw...)
}

// Process answers one command APDU from the reader and returns the
// response APDU (data and status word). After the whole NDEF file was read
// once, or after Wipe, every command is answered with "file not found".
func (t *NfcTag) Process(apdu []byte) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(apdu) < 4 || len(apdu) > nfcMaxAPDU {
		return respond(nil, swWrongLength)
	}
	if t.wiped || t.delivered {
		return respond(nil, swNotFound)
	}
	cla, ins, p1, p2 := apdu[0], apdu[1], apdu[2], apdu[3]
	if cla != 0x00 {
		return respond(nil, swCLANotSupport)
	}
	body := apdu[4:]
	switch ins {
	case 0xA4: // SELECT
		if len(body) < 1 || int(body[0]) == 0 || len(body) < 1+int(body[0]) {
			return respond(nil, swWrongLength)
		}
		data := body[1 : 1+int(body[0])]
		if rest := len(body) - 1 - int(body[0]); rest > 1 {
			return respond(nil, swWrongLength)
		}
		switch {
		case p1 == 0x04 && p2 == 0x00: // by name
			if !bytes.Equal(data, nfcAID) {
				t.appSel, t.file = false, 0
				return respond(nil, swNotFound)
			}
			t.appSel, t.file = true, 0
			return respond(nil, swOK)
		case p1 == 0x00 && p2 == 0x0C: // by file identifier, no FCI
			if !t.appSel || len(data) != 2 {
				return respond(nil, swNotFound)
			}
			switch id := int(binary.BigEndian.Uint16(data)); id {
			case nfcCCFile, nfcNDEFFile:
				t.file = id
				return respond(nil, swOK)
			default:
				t.file = 0
				return respond(nil, swNotFound)
			}
		default:
			return respond(nil, swWrongP1P2)
		}
	case 0xB0: // READ BINARY
		if len(body) != 1 {
			return respond(nil, swWrongLength)
		}
		if p1&0x80 != 0 {
			return respond(nil, swWrongP1P2)
		}
		var file []byte
		switch t.file {
		case nfcCCFile:
			file = t.cc
		case nfcNDEFFile:
			file = t.ndef
		default:
			return respond(nil, swNotFound)
		}
		off := int(p1)<<8 | int(p2)
		le := int(body[0])
		if le == 0 {
			le = 256
		}
		le = min(le, nfcMLe)
		if off > len(file) {
			return respond(nil, swWrongP1P2)
		}
		end := min(off+le, len(file))
		out := respond(file[off:end], swOK)
		if t.file == nfcNDEFFile {
			t.readUntil = max(t.readUntil, end)
			// The message (not only NLEN) was read through to its end.
			if t.readUntil >= len(t.ndef) && end > 2 {
				t.delivered = true
			}
		}
		return out
	case 0xD6: // UPDATE BINARY: read-only tag
		return respond(nil, swSecurity)
	default:
		return respond(nil, swINSNotSupport)
	}
}

// Delivered reports whether the invite was read completely once; the app
// then disarms the tag.
func (t *NfcTag) Delivered() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.delivered
}

// Wipe clears the invite code from memory; the tag answers nothing after.
func (t *NfcTag) Wipe() {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.ndef)
	t.wiped = true
}

// NfcInviteFromNDEF returns the invite text of the first OpenScale invite
// record in an NDEF message (NdefMessage.toByteArray on Android). Chunked
// records and anything else malformed are refused; the text is only
// returned for ClassifyScan, never trusted here.
func NfcInviteFromNDEF(msg []byte) (string, error) {
	if len(msg) == 0 || len(msg) > maxNDEF {
		return "", errors.New("NFC iletisi boş veya fazla büyük")
	}
	first := true
	for len(msg) > 0 {
		hdr := msg[0]
		mb, me, cf, sr, il, tnf := hdr&0x80 != 0, hdr&0x40 != 0, hdr&0x20 != 0, hdr&0x10 != 0, hdr&0x08 != 0, hdr&0x07
		if mb != first {
			return "", errors.New("NFC iletisi bozuk: ileti başı işareti")
		}
		first = false
		if cf {
			return "", errors.New("parçalı NFC kayıtları desteklenmez")
		}
		p := 1
		if len(msg) < p+1 {
			return "", errors.New("NFC kaydı kısa")
		}
		typeLen := int(msg[p])
		p++
		var payloadLen int
		if sr {
			if len(msg) < p+1 {
				return "", errors.New("NFC kaydı kısa")
			}
			payloadLen = int(msg[p])
			p++
		} else {
			if len(msg) < p+4 {
				return "", errors.New("NFC kaydı kısa")
			}
			n := binary.BigEndian.Uint32(msg[p:])
			if n > maxNDEF {
				return "", errors.New("NFC kaydı fazla büyük")
			}
			payloadLen = int(n)
			p += 4
		}
		idLen := 0
		if il {
			if len(msg) < p+1 {
				return "", errors.New("NFC kaydı kısa")
			}
			idLen = int(msg[p])
			p++
		}
		if len(msg)-p < typeLen+idLen+payloadLen {
			return "", errors.New("NFC kaydı kısa")
		}
		typ := msg[p : p+typeLen]
		p += typeLen + idLen
		payload := msg[p : p+payloadLen]
		p += payloadLen
		if tnf == 0x02 && strings.EqualFold(string(typ), NFCInviteMIME) {
			if len(payload) == 0 || len(payload) > maxNFCText || !utf8.Valid(payload) {
				return "", errors.New("NFC davet kaydı geçersiz")
			}
			return strings.TrimSpace(string(payload)), nil
		}
		msg = msg[p:]
		if me {
			if len(msg) != 0 {
				return "", errors.New("NFC iletisi bozuk: ileti sonundan sonra veri")
			}
			break
		}
		if len(msg) == 0 {
			return "", errors.New("NFC iletisi bozuk: ileti sonu işareti yok")
		}
	}
	return "", errors.New("NFC iletisinde OpenScale daveti yok")
}
