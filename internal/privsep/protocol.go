package privsep

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Helper protocol (ADR-0233). The parent writes one request at a time to
// the helper's standard input and reads one reply from its standard output;
// nothing else crosses the boundary. Every frame is a 4-byte big-endian
// length followed by that many bytes:
//
//	request: kind (1) | data
//	reply:   status (1) | data
//
// The helper's first frame is a hello (statusHello) whose data starts with
// helperMagic and then describes the sandbox it entered. Lengths are
// checked before anything is allocated.

// HelperArg is the argument that starts the program as the parsing helper.
const HelperArg = "__privsep-helper"

// Kind is what a request asks the helper to parse.
type Kind byte

const (
	// KindEnvelope is a signed network document envelope received from the
	// network. The reply is its canonical encoding.
	KindEnvelope Kind = 1
	// KindRelease is a signed release manifest. The reply is empty: the
	// caller keeps verifying its own bytes (witnesses hash them).
	KindRelease Kind = 2
)

func (k Kind) String() string {
	switch k {
	case KindEnvelope:
		return "ağ belgesi"
	case KindRelease:
		return "sürüm manifestosu"
	}
	return fmt.Sprintf("tür %d", byte(k))
}

const (
	statusOK     byte = 0
	statusReject byte = 1
	statusHello  byte = 0x7f

	helperMagic = "openscale-privsep/1"
	// maxFrame bounds every frame in both directions: the largest envelope
	// (trust.MaxEnvelopeSize, 2 MiB) with room for its canonical form.
	maxFrame = 4 << 20
	// maxReason bounds a rejection reason.
	maxReason = 256
)

var errFrame = errors.New("ayrıştırma yardımcısı: bozuk çerçeve")

func writeFrame(w io.Writer, tag byte, data []byte) error {
	if len(data)+1 > maxFrame {
		return errFrame
	}
	buf := make([]byte, 5, 5+len(data))
	binary.BigEndian.PutUint32(buf, uint32(len(data)+1)) //nolint:gosec // bounded by maxFrame
	buf[4] = tag
	_, err := w.Write(append(buf, data...))
	return err
}

func readFrame(r *bufio.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrame {
		return 0, nil, errFrame
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	return body[0], body[1:], nil
}
