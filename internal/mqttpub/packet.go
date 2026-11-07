// Package mqttpub publishes OpenScale's state and events to the owner's
// own MQTT broker (#561, ADR-0167), for example Home Assistant's. It is
// a small MQTT 3.1.1 client written for this purpose (CONNECT, PUBLISH
// at QoS 0, PINGREQ, DISCONNECT) so no MQTT library is added (ADR-0002).
//
// Like the webhook (ADR-0108) it is off by default and only reaches
// loopback and private addresses, checked on the address actually dialed.
// Messages carry the event stream's fields and a short status: no keys,
// no endpoints, no addresses.
package mqttpub

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Packet types of MQTT 3.1.1 used here.
const (
	typeConnect    = 1
	typeConnack    = 2
	typePublish    = 3
	typePingreq    = 12
	typePingresp   = 13
	typeDisconnect = 14
)

// maxRemaining is the largest remaining length MQTT can encode.
const maxRemaining = 268435455

// maxIncoming bounds a packet read from the broker; only CONNACK and
// PINGRESP are expected.
const maxIncoming = 4 << 10

var errMalformed = errors.New("MQTT aracısından bozuk paket")

// appendString writes an MQTT UTF-8 string (length prefixed).
func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

// appendRemaining writes the variable length remaining length.
func appendRemaining(b []byte, n int) []byte {
	for {
		d := byte(n % 128)
		n /= 128
		if n > 0 {
			d |= 0x80
		}
		b = append(b, d)
		if n == 0 {
			return b
		}
	}
}

func packet(first byte, body []byte) ([]byte, error) {
	if len(body) > maxRemaining {
		return nil, errors.New("MQTT paketi çok büyük")
	}
	out := append([]byte{first}, appendRemaining(nil, len(body))...)
	return append(out, body...), nil
}

// connectOptions are the fields of a CONNECT packet.
type connectOptions struct {
	ClientID    string
	Username    string
	Password    string
	KeepAlive   uint16
	WillTopic   string
	WillMessage []byte
	WillRetain  bool
}

func encodeConnect(o connectOptions) ([]byte, error) {
	var flags byte = 0x02 // clean session
	if o.WillTopic != "" {
		flags |= 0x04
		if o.WillRetain {
			flags |= 0x20
		}
	}
	if o.Username != "" {
		flags |= 0x80
		if o.Password != "" {
			flags |= 0x40
		}
	}
	body := appendString(nil, "MQTT")
	body = append(body, 4, flags)
	body = binary.BigEndian.AppendUint16(body, o.KeepAlive)
	body = appendString(body, o.ClientID)
	if o.WillTopic != "" {
		body = appendString(body, o.WillTopic)
		body = binary.BigEndian.AppendUint16(body, uint16(len(o.WillMessage)))
		body = append(body, o.WillMessage...)
	}
	if o.Username != "" {
		body = appendString(body, o.Username)
		if o.Password != "" {
			body = appendString(body, o.Password)
		}
	}
	return packet(typeConnect<<4, body)
}

func encodePublish(topic string, payload []byte, retain bool) ([]byte, error) {
	first := byte(typePublish << 4)
	if retain {
		first |= 0x01
	}
	body := appendString(nil, topic)
	body = append(body, payload...)
	return packet(first, body)
}

// readPacket reads one packet: its type, flags and body.
func readPacket(r *bufio.Reader, limit int) (typ, flags byte, body []byte, err error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, 0, nil, err
	}
	n, mult := 0, 1
	for i := 0; ; i++ {
		if i == 4 {
			return 0, 0, nil, errMalformed
		}
		d, err := r.ReadByte()
		if err != nil {
			return 0, 0, nil, err
		}
		n += int(d&0x7f) * mult
		mult *= 128
		if d&0x80 == 0 {
			break
		}
	}
	if n > limit {
		return 0, 0, nil, errMalformed
	}
	body = make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, 0, nil, err
	}
	return first >> 4, first & 0x0f, body, nil
}

// connackError explains a refused connection.
func connackError(code byte) error {
	switch code {
	case 0:
		return nil
	case 1:
		return errors.New("MQTT aracısı bu protokol sürümünü (3.1.1) desteklemiyor")
	case 2:
		return errors.New("MQTT aracısı istemci kimliğini reddetti")
	case 3:
		return errors.New("MQTT aracısı şu an hizmet vermiyor")
	case 4:
		return errors.New("MQTT kullanıcı adı veya parolası yanlış")
	case 5:
		return errors.New("MQTT aracısı bu istemciye izin vermiyor")
	}
	return fmt.Errorf("MQTT aracısı bağlantıyı reddetti (kod %d)", code)
}
