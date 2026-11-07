// Package piv talks to a PIV smart card applet (YubiKey firmware 5.7+) at
// the APDU level to keep an Ed25519 key, such as the network root key, on
// the token (#3, ADR-0123). It also speaks the OpenPGP card application
// for YubiKeys older than 5.7 (ADR-0171). The transport is PC/SC:
// winscard.dll on Windows, loaded lazily; libpcsclite or PCSC.framework on
// Linux and macOS in cgo builds; ErrUnsupported elsewhere.
//
// Only short APDUs are used, with command chaining (ISO 7816-4 CLA bit
// 0x10) for long data and GET RESPONSE for long answers, which is what the
// YubiKey PIV applet expects.
package piv

import (
	"errors"
	"fmt"
)

// Command is one ISO 7816-4 command APDU.
type Command struct {
	CLA, INS, P1, P2 byte
	Data             []byte
	// Le requests response data; 0 means no Le byte is sent, 256 encodes
	// as 0x00.
	Le int
}

const (
	maxShortData = 255
	claChain     = 0x10
	insGetResp   = 0xC0
)

// encodeShort encodes c as one short APDU. Data must fit.
func (c Command) encodeShort(cla byte, data []byte) ([]byte, error) {
	if len(data) > maxShortData {
		return nil, errors.New("apdu data too long for a short apdu")
	}
	if c.Le < 0 || c.Le > 256 {
		return nil, errors.New("invalid le")
	}
	out := make([]byte, 0, 5+len(data)+1)
	out = append(out, cla, c.INS, c.P1, c.P2)
	if len(data) > 0 {
		out = append(out, byte(len(data)))
		out = append(out, data...)
	}
	if c.Le > 0 {
		out = append(out, byte(c.Le)) // 256 wraps to 0x00 as ISO 7816-4 defines
	}
	return out, nil
}

// Encode splits c into chained short APDUs: every part but the last has
// the chaining bit set in CLA.
func (c Command) Encode() ([][]byte, error) {
	if c.CLA&claChain != 0 {
		return nil, errors.New("chaining bit must not be set by the caller")
	}
	if len(c.Data) <= maxShortData {
		one, err := c.encodeShort(c.CLA, c.Data)
		if err != nil {
			return nil, err
		}
		return [][]byte{one}, nil
	}
	var parts [][]byte
	data := c.Data
	for len(data) > maxShortData {
		part := Command{INS: c.INS, P1: c.P1, P2: c.P2}
		enc, err := part.encodeShort(c.CLA|claChain, data[:maxShortData])
		if err != nil {
			return nil, err
		}
		parts = append(parts, enc)
		data = data[maxShortData:]
	}
	last, err := c.encodeShort(c.CLA, data)
	if err != nil {
		return nil, err
	}
	return append(parts, last), nil
}

// Response is a response APDU split into data and status word.
type Response struct {
	Data []byte
	SW   uint16
}

// ParseResponse splits a raw response APDU.
func ParseResponse(raw []byte) (Response, error) {
	if len(raw) < 2 {
		return Response{}, errors.New("response apdu shorter than its status word")
	}
	n := len(raw) - 2
	return Response{Data: append([]byte(nil), raw[:n]...), SW: uint16(raw[n])<<8 | uint16(raw[n+1])}, nil
}

// Status words used by the PIV applet.
const (
	swOK              = 0x9000
	swSecurityStatus  = 0x6982
	swAuthBlocked     = 0x6983
	swWrongData       = 0x6A80
	swFileNotFound    = 0x6A82
	swIncorrectParams = 0x6A86
	swInsNotSupported = 0x6D00
	swCondNotMet      = 0x6985
)

// StatusError is a non-success status word.
type StatusError struct{ SW uint16 }

func (e *StatusError) Error() string {
	switch e.SW {
	case swSecurityStatus:
		return "security status not satisfied (PIN or management key required)"
	case swAuthBlocked:
		return "PIN or management key is blocked"
	case swWrongData:
		return "card rejected the data"
	case swFileNotFound:
		return "slot or object not found"
	case swIncorrectParams:
		return "card rejected the parameters (algorithm or slot not supported)"
	case swInsNotSupported:
		return "instruction not supported by this card or firmware"
	case swCondNotMet:
		return "conditions of use not satisfied (touch required?)"
	}
	return fmt.Sprintf("card returned status %04X", e.SW)
}

// ErrWrongPIN is returned for a wrong PIN; Retries tells how many tries are
// left before the PIN blocks.
// Retries is -1 when the card did not tell. Admin marks the OpenPGP admin
// PIN (PW3).
type ErrWrongPIN struct {
	Retries int
	Admin   bool
}

func (e *ErrWrongPIN) Error() string {
	what := "PIN"
	if e.Admin {
		what = "admin PIN"
	}
	if e.Retries < 0 {
		return "wrong " + what
	}
	return fmt.Sprintf("wrong %s (%d tries left)", what, e.Retries)
}

// Transport sends one raw APDU and returns the raw response.
type Transport interface {
	Transmit(apdu []byte) ([]byte, error)
}

// maxResponse bounds a reassembled response; a PIV answer is at most a few
// kilobytes (certificates), a signature 64 bytes.
const maxResponse = 16 << 10

// maxGetResponseRounds bounds GET RESPONSE: maxResponse in full 256-byte
// pieces, plus slack for cards that answer in smaller pieces.
const maxGetResponseRounds = 2 * maxResponse / 256

// transmit sends c over t with command chaining and collects 61xx
// continuation data with GET RESPONSE. It returns the data of a 9000
// answer, or a *StatusError.
func transmit(t Transport, c Command) ([]byte, error) {
	parts, err := c.Encode()
	if err != nil {
		return nil, err
	}
	// The encoded parts may carry a PIN or key material; wipe them.
	defer func() {
		for _, p := range parts {
			clear(p)
		}
	}()
	var resp Response
	for i, p := range parts {
		raw, err := t.Transmit(p)
		if err != nil {
			return nil, fmt.Errorf("transmit: %w", err)
		}
		if resp, err = ParseResponse(raw); err != nil {
			return nil, err
		}
		if i < len(parts)-1 && resp.SW != swOK {
			return nil, &StatusError{SW: resp.SW}
		}
	}
	data := resp.Data
	for rounds := 0; resp.SW>>8 == 0x61; rounds++ {
		// A faulty or hostile card can answer 61xx with no data forever;
		// the length check below never fires then.
		if rounds >= maxGetResponseRounds {
			return nil, errors.New("response too long")
		}
		le := int(resp.SW & 0xFF)
		if le == 0 {
			le = 256
		}
		get, err := Command{INS: insGetResp, Le: le}.encodeShort(c.CLA, nil)
		if err != nil {
			return nil, err
		}
		raw, err := t.Transmit(get)
		if err != nil {
			return nil, fmt.Errorf("transmit: %w", err)
		}
		if resp, err = ParseResponse(raw); err != nil {
			return nil, err
		}
		data = append(data, resp.Data...)
		if len(data) > maxResponse {
			return nil, errors.New("response too long")
		}
	}
	if resp.SW != swOK {
		return nil, &StatusError{SW: resp.SW}
	}
	return data, nil
}
